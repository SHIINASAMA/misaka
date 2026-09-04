//! Protocol message handler.
//!
//! The handler translates wire messages into service calls. Transport framing
//! stays in `network`; domain state remains owned by `SisterNode` and its
//! services.

use crate::node::{now_secs, SisterNode};
use misaka_core::protocol::*;
use tokio::net::TcpStream;

pub(crate) async fn dispatch(
    node: &SisterNode,
    env: Envelope,
    stream: &mut TcpStream,
) -> crate::Result<()> {
    match env.msg_type {
        MessageType::Ping => {
            // Ping/Pong is intentionally side-effect free: unlike Hello, it
            // never records the sender in the peer registry or PeerStore.
            let reply = Envelope::new(
                MessageType::Pong,
                node.identity.id.as_u64(),
                env.from,
                vec![],
            );
            node.transport.reply(stream, &reply).await?;
        }

        MessageType::Hello => {
            let hello: HelloData = bincode::deserialize(&env.data)?;
            if hello.network_id != node.config.network_id {
                return Err(crate::Error::Protocol(format!(
                    "peer belongs to network {} instead of {}",
                    hello.network_id, node.config.network_id
                )));
            }
            node.remember_peer(
                &hello.identity,
                hello.network_id,
                &hello.listen_addr,
                hello.stream_addr.as_deref(),
                hello.stream_certificate,
            )
            .await;
            let reply = Envelope::new(
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
            node.transport.reply(stream, &reply).await?;
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
                return Ok(());
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
            // 若指定了 executor 且不是本机 → 转发
            if job.executor != 0 && job.executor != node.identity.id.as_u64() {
                if let Some(addr) = node.peer_addr(job.executor).await {
                    tracing::info!(
                        event = "job_forwarded",
                        sister_id = node.identity.id.as_u64(),
                        job_id = %job.id,
                        executor = job.executor,
                        "forwarding job"
                    );
                    node.send_fire(
                        addr,
                        &Envelope::new(MessageType::Job, env.from, job.executor, env.data.clone()),
                    )
                    .await?;
                    return Ok(());
                }
            }
            // 本机执行
            let job_id = job.id.clone();
            let full_cmd = job.full_command();
            let mut local_job = crate::state::LocalJob::new(job_id.clone(), full_cmd.clone());
            local_job.creator = job.creator;
            local_job.creator_addr = Some(job.creator_addr.clone());
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
            let peer_addr = node.peers.addr_of(requester).await;
            if let Some(job) = node.jobs.pop() {
                if let Some(addr) = peer_addr {
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
                    };
                    let envelope = Envelope::new(
                        MessageType::Job,
                        node.identity.id.as_u64(),
                        requester,
                        bincode::serialize(&job_data)?,
                    );
                    if node.send_fire(addr, &envelope).await.is_ok() {
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
            } else if let Some(addr) = peer_addr {
                // 没有 → 回 Ack 表示无活
                let _ = node
                    .send_fire(
                        addr,
                        &Envelope::new(
                            MessageType::Ack,
                            node.identity.id.as_u64(),
                            requester,
                            vec![],
                        ),
                    )
                    .await;
            }
        }

        _ => {}
    }
    Ok(())
}
