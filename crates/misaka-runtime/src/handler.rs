//! Protocol message handler.
//!
//! The handler translates wire messages into service calls. Transport framing
//! stays in `network`; domain state remains owned by `SisterNode` and its
//! services.

use crate::authenticated_session::AuthenticatedPeer;
use crate::node::{now_secs, SisterNode};
use misaka_core::protocol::*;
use misaka_core::{MembershipKind, Permission, Principal};
use tokio::net::TcpStream;

fn require_side_effect_authorization(
    authorization: Option<&misaka_core::CommandAuthorization>,
    allow_unauthenticated_operations: bool,
) -> crate::Result<()> {
    if authorization.is_none() && !allow_unauthenticated_operations {
        return Err(crate::Error::Protocol(
            "side-effecting operation requires Human Authorization".to_string(),
        ));
    }
    Ok(())
}

/// True when `claimed` matches the peer authenticated on this stream. The
/// legacy TCP control plane has no per-stream authenticated peer, so it passes
/// `None` and keeps its historical (weaker) behavior; the Iroh control plane —
/// the normal path — must always match.
fn sender_matches_peer(peer: Option<&AuthenticatedPeer>, claimed: u64) -> bool {
    peer.is_none_or(|peer| peer.sister_id.as_u64() == claimed)
}

/// Build the envelope a Sister (`sender_id`) uses to forward an existing Job to
/// `executor`. The transport `from` is ALWAYS the forwarding Sister — the
/// immediate authenticated sender — never the logical creator (which stays in
/// `JobData.creator` inside the unchanged `data`). Forwarding must not
/// impersonate the creator at the transport layer, since only `sender_id`
/// authenticated this stream.
fn job_forward_envelope(
    network_id: misaka_core::NetworkId,
    sender_id: u64,
    executor: u64,
    data: Vec<u8>,
) -> Envelope {
    Envelope::new(network_id, MessageType::Job, sender_id, executor, data)
}

pub(crate) async fn dispatch(
    node: &SisterNode,
    env: Envelope,
    stream: &mut TcpStream,
) -> crate::Result<()> {
    // Legacy TCP control plane: no authenticated stream peer to bind to.
    if let Some(reply) = dispatch_envelope(node, env, None).await? {
        node.transport.reply(stream, &reply).await?;
    }
    Ok(())
}

/// Dispatch one control-plane envelope. The optional [`AuthenticatedPeer`] is the
/// identity established by the Iroh authenticated session for the stream this
/// message arrived on; when present, the message's sender and any identity-
/// bearing payload are pinned to it, so a valid Sister can never impersonate
/// another even within the same Network.
pub(crate) async fn dispatch_envelope(
    node: &SisterNode,
    env: Envelope,
    peer: Option<AuthenticatedPeer>,
) -> crate::Result<Option<Envelope>> {
    if env.network_id != node.config.network_id {
        return Err(crate::Error::Protocol(format!(
            "envelope belongs to network {} instead of {}",
            env.network_id, node.config.network_id
        )));
    }
    // §1: an authenticated stream's sender is cryptographically known; a
    // mismatched `Envelope::from` is spoofing and must be rejected outright.
    if !sender_matches_peer(peer.as_ref(), env.from) {
        return Err(crate::Error::Protocol(
            "envelope sender does not match the authenticated peer".to_string(),
        ));
    }
    match env.msg_type {
        MessageType::Ping => {
            // Ping/Pong is intentionally side-effect free: unlike Hello, it
            // never records the sender in the peer registry or PeerStore.
            let reply = Envelope::new(
                node.config.network_id,
                MessageType::Pong,
                node.identity.id.as_u64(),
                env.from,
                vec![],
            );
            return Ok(Some(reply));
        }

        MessageType::Hello => {
            let hello: HelloData = bincode::deserialize(&env.data)?;
            if hello.network_id != node.config.network_id {
                return Err(crate::Error::Protocol(format!(
                    "peer belongs to network {} instead of {}",
                    hello.network_id, node.config.network_id
                )));
            }
            // The Hello identity must match the authenticated stream peer.
            if !sender_matches_peer(peer.as_ref(), hello.identity.id.as_u64()) {
                return Err(crate::Error::Protocol(
                    "Hello identity does not match the authenticated peer".to_string(),
                ));
            }
            node.remember_peer(
                &hello.identity,
                hello.network_id,
                &hello.listen_addr,
                hello.stream_addr.as_deref(),
                hello.stream_certificate,
            )
            .await;
            // Return the Hello response before pushing the optional peer
            // record batch. Iroh bootstrap callers cannot start their own
            // accept loop until this response completes, so waiting here
            // would deadlock when the batch is sent back over Iroh.
            let peer_node = node.clone();
            let peer_id = env.from;
            tokio::spawn(async move {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    peer_node.send_peer_records(peer_id),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::debug!(peer_id, %error, "deferred peer record push failed");
                    }
                    Err(_) => {
                        tracing::debug!(
                            peer_id,
                            error = "peer record push timed out",
                            "deferred peer record push failed"
                        );
                    }
                }
            });
            let reply = Envelope::new(
                node.config.network_id,
                MessageType::Hello,
                node.identity.id.as_u64(),
                env.from,
                bincode::serialize(&HelloData {
                    network_id: node.config.network_id,
                    identity: node.identity.as_ref().clone(),
                    listen_addr: node.listen_addr.to_string(),
                    stream_addr: node.stream_endpoint(),
                    stream_certificate: node.stream_certificate(),
                })?,
            );
            return Ok(Some(reply));
        }

        MessageType::State => {
            let state: StateData = bincode::deserialize(&env.data)?;
            if state.network_id != node.config.network_id {
                tracing::debug!(
                    peer_id = env.from,
                    peer_network_id = %state.network_id,
                    network_id = %node.config.network_id,
                    "ignoring state from another network"
                );
                return Ok(None);
            }
            // A State payload must describe the same Sister the stream
            // authenticated as; otherwise a peer could overwrite another's row.
            if !sender_matches_peer(peer.as_ref(), state.identity.id.as_u64()) {
                return Err(crate::Error::Protocol(
                    "State identity does not match the authenticated peer".to_string(),
                ));
            }
            tracing::info!(
                event = "peer_state_updated",
                sister_id = node.identity.id.as_u64(),
                peer_id = env.from,
                peer_nickname = %state.identity.nickname.as_str(),
                cpu_usage = state.cpu_usage,
                memory_used = state.memory_used,
                memory_total = state.memory_total,
                running_jobs = state.running_jobs,
                queued_jobs = state.queued_jobs,
                "peer state updated"
            );
            node.peers
                .upsert(misaka_core::PeerState {
                    network_id: state.network_id,
                    id: state.identity.id.as_u64(),
                    nickname: state.identity.nickname.as_str().to_string(),
                    hostname: state.identity.hostname,
                    platform: state.identity.platform,
                    version: state.identity.version,
                    stream_endpoints: state.stream_addr.into_iter().collect(),
                    stream_certificate: state.stream_certificate,
                    addr: state.listen_addr,
                    cpu_usage: state.cpu_usage,
                    memory_total: state.memory_total,
                    memory_used: state.memory_used,
                    running_jobs: state.running_jobs,
                    queued_jobs: state.queued_jobs,
                    uptime_secs: state.uptime_secs,
                    capabilities: state.capabilities,
                })
                .await;
        }

        MessageType::Job => {
            let job: JobData = bincode::deserialize(&env.data)?;
            let local_id = node.identity.id.as_u64();
            // Where will this actually run? Forward only when a specific remote
            // executor is named AND we can reach it; otherwise we run it here.
            let will_forward = job.executor != 0
                && job.executor != local_id
                && node.peers.get(job.executor).await.is_some();
            // The Sister the authorization must name for this hop: the executor
            // when forwarding, or us when executing locally.
            let expected_target = if will_forward { job.executor } else { local_id };

            require_side_effect_authorization(
                job.authorization.as_ref(),
                node.config.allow_unauthenticated_operations,
            )?;
            if let Some(authorization) = job.authorization.as_ref() {
                let authority = crate::network_authority_store::NetworkAuthorityStore::load(
                    &node.config.data_dir,
                )
                .map_err(|error| crate::Error::Protocol(error.to_string()))?
                .ok_or_else(|| {
                    crate::Error::Protocol(
                        "human-authorized job requires a local Network authority descriptor"
                            .to_string(),
                    )
                })?;
                // §4/§6: a production JobSubmit authorization MUST be bound to a
                // concrete destination Sister. `target == None` is no longer a
                // Network-wide bearer capability, and `target == someOtherSister`
                // must not run here.
                let target_ok = authorization.target
                    == Some(Principal::Sister(misaka_core::SisterId(expected_target)));
                let command = job.full_command();
                let constraints_ok = authorization.constraints.iter().all(|constraint| {
                    constraint
                        .strip_prefix("command=")
                        .is_some_and(|expected| expected == command)
                });
                if authorization.permission != Permission::JobSubmit
                    || authorization.network_id != node.config.network_id
                    || !authorization.verify(&authority, now_secs())
                    || !target_ok
                    || !constraints_ok
                {
                    return Err(crate::Error::Protocol(
                        "human job authorization is invalid for this Sister".to_string(),
                    ));
                }
                if crate::revocation_store::RevocationStore::is_revoked(
                    &node.config.data_dir,
                    &authority,
                    authorization.network_id,
                    MembershipKind::Human,
                    authorization.membership.serial,
                )
                .map_err(|error| crate::Error::Protocol(error.to_string()))?
                {
                    return Err(crate::Error::Protocol(
                        "human job authorization membership has been revoked".to_string(),
                    ));
                }
                // §7: an intermediate forwarder verifies but does NOT consume the
                // destination's nonce — only the Sister that executes does.
                if !will_forward {
                    let _nonce_guard = node.authorization_nonce_lock.lock().await;
                    crate::authorization_nonce_store::AuthorizationNonceStore::record(
                        &node.config.data_dir,
                        authorization,
                        now_secs(),
                    )
                    .map_err(|error| crate::Error::Protocol(error.to_string()))?;
                }
            }
            if will_forward {
                // 转发到指定 executor(本机不执行)
                tracing::info!(
                    event = "job_forwarded",
                    sister_id = node.identity.id.as_u64(),
                    job_id = %job.id,
                    executor = job.executor,
                    "forwarding job"
                );
                node.send_fire_to_peer(
                    job.executor,
                    &job_forward_envelope(
                        node.config.network_id,
                        local_id,
                        job.executor,
                        env.data.clone(),
                    ),
                )
                .await?;
                return Ok(None);
            }
            // 本机执行
            let job_id = job.id.clone();
            let full_cmd = job.full_command();
            let mut local_job = crate::state::LocalJob::new(job_id.clone(), full_cmd.clone());
            local_job.creator = job.creator;
            local_job.creator_addr = Some(job.creator_addr.clone());
            local_job.authorization = job.authorization;
            node.jobs.enqueue(local_job).await;
            tracing::info!(
                event = "job_queued",
                sister_id = node.identity.id.as_u64(),
                job_id = %job_id,
                creator = job.creator,
                command = %full_cmd,
                "job queued"
            );
        }

        MessageType::JobResponse => {
            let result: JobResultData = bincode::deserialize(&env.data)?;
            // §6: only resolve a pending job that this Sister actually owns.
            // A pending is keyed by the (now unguessable, UUID) job id, but the
            // `creator` field guards against a peer delivering a result that
            // claims to be for someone else's submission. The authenticated
            // sender (§1) is who it claims; we intentionally do NOT require the
            // sender to equal the originally-directed executor, because a job may
            // legitimately be forwarded or work-stolen to a different Sister —
            // the result still names the true creator. Pinning the whole
            // executor chain needs a transfer-notification design (deferred with
            // the job-identity work), so id + creator + authenticated sender is
            // the practical, transfer-safe binding.
            if result.creator != node.identity.id.as_u64() {
                tracing::debug!(
                    event = "job_result_ignored",
                    sister_id = node.identity.id.as_u64(),
                    job_creator = result.creator,
                    job_id = %result.job_id,
                    "dropping a JobResponse for a job this Sister did not create"
                );
                return Ok(None);
            }
            tracing::info!(
                event = "job_result_received",
                sister_id = node.identity.id.as_u64(),
                job_id = %result.job_id,
                executor = result.executor,
                exit_code = result.exit_code,
                "job result received"
            );
            // 唤醒等结果的提交方
            if let Some(tx) = node.jobs.resolve_pending(&result.job_id) {
                let _ = tx.send(result);
            }
        }

        MessageType::JobRequest => {
            // Work stealing: offer only a job this requester is actually
            // authorized to run (§8/§9). A Human-authorized job bound to another
            // Sister is never taken here; an un-authorized job only in explicit
            // insecure-development mode.
            let requester = env.from;
            let peer_known = node.peers.get(requester).await.is_some();
            if let Some(job) = node
                .jobs
                .pop_transferable(requester, node.config.allow_unauthenticated_operations)
            {
                if peer_known {
                    let job_data = JobData {
                        id: job.id.clone(),
                        creator: job.creator,
                        executor: requester,
                        creator_addr: job
                            .creator_addr
                            .clone()
                            .unwrap_or_else(|| node.listen_addr.to_string()),
                        command: job.command.clone(),
                        arguments: vec![],
                        created_at: now_secs(),
                        authorization: job.authorization.clone(),
                    };
                    let envelope = Envelope::new(
                        node.config.network_id,
                        MessageType::Job,
                        node.identity.id.as_u64(),
                        requester,
                        bincode::serialize(&job_data)?,
                    );
                    if node.send_fire_to_peer(requester, &envelope).await.is_ok() {
                        tracing::info!(
                            event = "job_transferred",
                            sister_id = node.identity.id.as_u64(),
                            job_id = %job.id,
                            peer_id = requester,
                            "job transferred"
                        );
                        node.jobs.mark_transferred(&job.id).await;
                    } else {
                        // 保留任务，等待下一次请求重试。
                        node.jobs.push_back(job);
                    }
                } else {
                    node.jobs.push_back(job);
                }
            } else if peer_known {
                // 没有 → 回 Ack 表示无活
                let _ = node
                    .send_fire_to_peer(
                        requester,
                        &Envelope::new(
                            node.config.network_id,
                            MessageType::Ack,
                            node.identity.id.as_u64(),
                            requester,
                            vec![],
                        ),
                    )
                    .await;
            }
        }

        MessageType::PeerRecords => {
            let records: PeerRecordsData = bincode::deserialize(&env.data)?;
            if records.network_id != node.config.network_id {
                return Ok(None);
            }
            for record in records.records {
                node.remember_peer_record(record).await;
            }
        }

        _ => {}
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{dispatch_envelope, job_forward_envelope, require_side_effect_authorization};
    use crate::authenticated_session::AuthenticatedPeer;
    use crate::config::{DiscoveryMode, RuntimeConfig};
    use crate::node::SisterNode;
    use misaka_core::protocol::{HelloData, StateData};
    use misaka_core::{
        CommandAuthorization, Envelope, HumanId, HumanIdentity, HumanKeyPair,
        HumanMembershipCertificate, MessageType, NetworkId, Permission, Principal, Role, SisterId,
        SisterIdentity, SisterKeyPair,
    };

    #[test]
    fn missing_job_authorization_is_rejected_without_explicit_development_mode() {
        assert!(require_side_effect_authorization(None, false).is_err());
        assert!(require_side_effect_authorization(None, true).is_ok());
    }

    fn node() -> SisterNode {
        let dir = std::env::temp_dir().join(format!("misaka-handler-node-{}", std::process::id()));
        SisterNode::new(
            SisterIdentity::new(1, "node".into(), "h".into(), "p".into(), "v".into(), 31700),
            [0u8; 32],
            RuntimeConfig {
                network_id: NetworkId::default(),
                data_dir: dir,
                discovery: DiscoveryMode::Off,
                ..Default::default()
            },
        )
    }

    /// An authenticated stream peer that is Sister #2, distinct from the node.
    fn peer_two() -> (AuthenticatedPeer, SisterKeyPair) {
        let key = SisterKeyPair::generate();
        (
            AuthenticatedPeer {
                sister_id: SisterId(2),
                sister_public_key: key.public_key(),
                membership_serial: 5,
            },
            key,
        )
    }

    // S01: an authenticated Sister may not spoof Envelope.from as another Sister.
    #[tokio::test]
    async fn authenticated_peer_cannot_spoof_envelope_sender() {
        let (peer, _key) = peer_two();
        let spoofed = Envelope::new(NetworkId::default(), MessageType::Ping, 9, 0, vec![]);
        assert!(dispatch_envelope(&node(), spoofed, Some(peer.clone()))
            .await
            .is_err());
        let honest = Envelope::new(NetworkId::default(), MessageType::Ping, 2, 0, vec![]);
        assert!(dispatch_envelope(&node(), honest, Some(peer)).await.is_ok());
    }

    // S02: a Hello identity must match the authenticated peer.
    #[tokio::test]
    async fn authenticated_peer_cannot_send_hello_for_another_sister() {
        let (peer, _key) = peer_two();
        let hello = HelloData {
            network_id: NetworkId::default(),
            identity: SisterIdentity::new(9, "ghost".into(), "h".into(), "p".into(), "v".into(), 1),
            listen_addr: "127.0.0.1:1".into(),
            stream_addr: None,
            stream_certificate: None,
        };
        let env = Envelope::new(
            NetworkId::default(),
            MessageType::Hello,
            2,
            0,
            bincode::serialize(&hello).unwrap(),
        );
        assert!(dispatch_envelope(&node(), env, Some(peer)).await.is_err());
    }

    // S03: a State identity must match the authenticated peer.
    #[tokio::test]
    async fn authenticated_peer_cannot_send_state_for_another_sister() {
        let (peer, _key) = peer_two();
        let state = StateData {
            network_id: NetworkId::default(),
            identity: SisterIdentity::new(9, "ghost".into(), "h".into(), "p".into(), "v".into(), 1),
            listen_addr: "127.0.0.1:1".into(),
            stream_addr: None,
            stream_certificate: None,
            cpu_usage: 0.0,
            memory_total: 0,
            memory_used: 0,
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: 0,
            capabilities: vec![],
        };
        let env = Envelope::new(
            NetworkId::default(),
            MessageType::State,
            2,
            0,
            bincode::serialize(&state).unwrap(),
        );
        assert!(dispatch_envelope(&node(), env, Some(peer)).await.is_err());
    }

    // With no authenticated peer (legacy TCP), the historical behavior stands.
    #[tokio::test]
    async fn legacy_tcp_dispatch_has_no_peer_binding() {
        let env = Envelope::new(NetworkId::default(), MessageType::Ping, 9, 0, vec![]);
        assert!(dispatch_envelope(&node(), env, None).await.is_ok());
    }

    /// A node whose data dir holds a real authority descriptor, so a signed
    /// Human authorization can be validated (target is what we are testing).
    fn node_with_authority() -> (SisterNode, misaka_core::AuthorityKeyPair) {
        let dir =
            std::env::temp_dir().join(format!("misaka-handler-auth-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        let network_id = NetworkId::default();
        let (authority, authority_key) = misaka_core::NetworkAuthority::generate(network_id);
        crate::network_authority_store::NetworkAuthorityStore::install_descriptor(&dir, &authority)
            .unwrap();
        let node = SisterNode::new(
            SisterIdentity::new(1, "node".into(), "h".into(), "p".into(), "v".into(), 31700),
            [0u8; 32],
            RuntimeConfig {
                network_id,
                data_dir: dir,
                discovery: DiscoveryMode::Off,
                ..Default::default()
            },
        );
        (node, authority_key)
    }

    /// A JobSubmit authorization signed by a valid human + membership, targeted
    /// to `target` (None ⇒ an unbound, network-wide capability).
    fn job_authorization(
        authority_key: &misaka_core::AuthorityKeyPair,
        target: Option<u64>,
    ) -> misaka_core::CommandAuthorization {
        let network_id = NetworkId::default();
        let authority = misaka_core::NetworkAuthority {
            network_id,
            authority_public_key: authority_key.public_key(),
        };
        let hkey = HumanKeyPair::generate();
        let human = HumanIdentity::new(HumanId::generate(), "op".into(), hkey.public_key());
        let membership = HumanMembershipCertificate::issue(
            &authority,
            authority_key,
            human.clone(),
            Role::Operator,
            0,
            None,
            1,
        );
        CommandAuthorization::issue(
            network_id,
            human,
            membership,
            Role::Operator,
            Permission::JobSubmit,
            target.map(|id| Principal::Sister(SisterId(id))),
            vec!["command=printf hi".into()],
            0,
            u64::MAX,
            rand::random(),
            &hkey,
        )
    }

    // JH01: a production JobSubmit authorization with target=None is rejected.
    #[tokio::test]
    async fn job_submit_without_target_is_rejected() {
        let (node, authority_key) = node_with_authority();
        let (peer, _key) = peer_two(); // authenticated sender Sister #2
        let authorization = job_authorization(&authority_key, None);
        let job = misaka_core::JobData {
            id: "job-x".into(),
            creator: 2,
            executor: 1, // this node
            creator_addr: "127.0.0.1:1".into(),
            command: "printf hi".into(),
            arguments: vec![],
            created_at: 0,
            authorization: Some(authorization),
        };
        let env = Envelope::new(
            NetworkId::default(),
            MessageType::Job,
            2,
            1,
            bincode::serialize(&job).unwrap(),
        );
        assert!(dispatch_envelope(&node, env, Some(peer)).await.is_err());
    }

    // JH02 / JH03: a job authorized for Sister B must not execute on Sister C.
    #[tokio::test]
    async fn job_authorized_for_another_sister_is_rejected() {
        let (node, authority_key) = node_with_authority(); // node id = 1
        let (peer, _key) = peer_two(); // authenticated sender Sister #2
                                       // Authorization targets Sister #9; this node is #1 and cannot reach #9,
                                       // so it would execute locally — but the target is not it → reject.
        let authorization = job_authorization(&authority_key, Some(9));
        let job = misaka_core::JobData {
            id: "job-y".into(),
            creator: 2,
            executor: 1,
            creator_addr: "127.0.0.1:1".into(),
            command: "printf hi".into(),
            arguments: vec![],
            created_at: 0,
            authorization: Some(authorization),
        };
        let env = Envelope::new(
            NetworkId::default(),
            MessageType::Job,
            2,
            1,
            bincode::serialize(&job).unwrap(),
        );
        assert!(dispatch_envelope(&node, env, Some(peer)).await.is_err());
    }

    // JH04: forwarding a Job must send it with the forwarding Sister as the
    // transport sender, while the logical creator survives inside the payload.
    #[test]
    fn forwarding_uses_sender_identity_and_preserves_creator() {
        let creator = misaka_core::JobData {
            id: "job-j4".into(),
            creator: 7,  // logical creator C
            executor: 3, // intended executor B
            creator_addr: "127.0.0.1:1".into(),
            command: "printf hi".into(),
            arguments: vec![],
            created_at: 0,
            authorization: None,
        };
        let data = bincode::serialize(&creator).unwrap();
        // Sister A (id 1) forwards to B (id 3).
        let forwarded = job_forward_envelope(NetworkId::default(), 1, 3, data.clone());
        // Transport sender is A, not the creator C.
        assert_eq!(forwarded.from, 1);
        assert_eq!(forwarded.to, 3);
        // Creator survives unchanged inside the payload.
        let carried: misaka_core::JobData = bincode::deserialize(&forwarded.data).unwrap();
        assert_eq!(carried.creator, 7);
    }

    // JH06: a JobSubmit authorization targeted to THIS node executes (accepted).
    #[tokio::test]
    async fn job_authorized_for_this_sister_is_accepted() {
        let (node, authority_key) = node_with_authority();
        let (peer, _key) = peer_two();
        let authorization = job_authorization(&authority_key, Some(1)); // == node id
        let job = misaka_core::JobData {
            id: "job-ok".into(),
            creator: 2,
            executor: 1,
            creator_addr: "127.0.0.1:1".into(),
            command: "printf hi".into(),
            arguments: vec![],
            created_at: 0,
            authorization: Some(authorization),
        };
        let env = Envelope::new(
            NetworkId::default(),
            MessageType::Job,
            2,
            1,
            bincode::serialize(&job).unwrap(),
        );
        assert!(dispatch_envelope(&node, env, Some(peer)).await.is_ok());
    }

    // S06: a JobResponse for a job this Sister did not create must not resolve
    // its pending, even if the (unguessable) job id were somehow known.
    #[tokio::test]
    async fn job_response_for_another_creators_job_is_ignored() {
        let node = node(); // this node's identity id = 1
        let (sender_peer, _key) = peer_two(); // authenticated sender is Sister #2
        node.jobs.reserve_pending("job-live");

        let foreign = misaka_core::protocol::JobResultData {
            job_id: "job-live".into(),
            creator: 99, // someone else's job
            executor: 2,
            output: "x".into(),
            exit_code: 0,
            success: true,
            started_at: 0,
            finished_at: 1,
        };
        let env = Envelope::new(
            NetworkId::default(),
            MessageType::JobResponse,
            2,
            0,
            bincode::serialize(&foreign).unwrap(),
        );
        // Rejected-by-ownership: the pending must survive (not resolved).
        let _ = dispatch_envelope(&node, env, Some(sender_peer.clone()))
            .await
            .unwrap();
        assert!(
            node.jobs.resolve_pending("job-live").is_some(),
            "a foreign-creator JobResponse wrongly resolved our pending"
        );

        // The correct result (creator == us) resolves it.
        let ours = misaka_core::protocol::JobResultData {
            job_id: "job-live".into(),
            creator: 1,
            executor: 2,
            output: "ok".into(),
            exit_code: 0,
            success: true,
            started_at: 0,
            finished_at: 1,
        };
        let env = Envelope::new(
            NetworkId::default(),
            MessageType::JobResponse,
            2,
            0,
            bincode::serialize(&ours).unwrap(),
        );
        dispatch_envelope(&node, env, Some(sender_peer))
            .await
            .unwrap();
        // After the accepted result, the pending is gone.
        assert!(node.jobs.resolve_pending("job-live").is_none());
    }
}
