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
                let target_ok = match authorization.target.as_ref() {
                    None => true,
                    Some(Principal::Sister(id)) => {
                        id.as_u64()
                            == if job.executor == 0 {
                                node.identity.id.as_u64()
                            } else {
                                job.executor
                            }
                    }
                    Some(Principal::Human(_)) => false,
                };
                let command = job.full_command();
                let constraints_ok = authorization.constraints.iter().all(|constraint| {
                    constraint
                        .strip_prefix("command=")
                        .is_some_and(|expected| expected == command)
                });
                if authorization.permission != Permission::JobSubmit
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
                if job.executor == 0 || job.executor == node.identity.id.as_u64() {
                    let _nonce_guard = node.authorization_nonce_lock.lock().await;
                    crate::authorization_nonce_store::AuthorizationNonceStore::record(
                        &node.config.data_dir,
                        authorization,
                        now_secs(),
                    )
                    .map_err(|error| crate::Error::Protocol(error.to_string()))?;
                }
            }
            // 若指定了 executor 且不是本机 → 转发
            if job.executor != 0
                && job.executor != node.identity.id.as_u64()
                && node.peers.get(job.executor).await.is_some()
            {
                tracing::info!(
                    event = "job_forwarded",
                    sister_id = node.identity.id.as_u64(),
                    job_id = %job.id,
                    executor = job.executor,
                    "forwarding job"
                );
                node.send_fire_to_peer(
                    job.executor,
                    &Envelope::new(
                        node.config.network_id,
                        MessageType::Job,
                        env.from,
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
                creator = env.from,
                command = %full_cmd,
                "job queued"
            );
        }

        MessageType::JobResponse => {
            let result: JobResultData = bincode::deserialize(&env.data)?;
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
            // Work Stealing: 有人来要活。给一个本地排队中的任务。
            let requester = env.from;
            let peer_known = node.peers.get(requester).await.is_some();
            if let Some(job) = node.jobs.pop() {
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
    use super::{dispatch_envelope, require_side_effect_authorization};
    use crate::authenticated_session::AuthenticatedPeer;
    use crate::config::{DiscoveryMode, RuntimeConfig};
    use crate::node::SisterNode;
    use misaka_core::protocol::{HelloData, StateData};
    use misaka_core::{Envelope, MessageType, NetworkId, SisterId, SisterIdentity, SisterKeyPair};

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
}
