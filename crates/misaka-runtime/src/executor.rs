//! Local job executor service.
//!
//! The executor owns queue consumption and command execution. Command
//! execution is moved to Tokio's blocking pool so network and introspection
//! tasks remain responsive while a shell command runs.

use crate::node::{now_secs, SisterNode};
use misaka_core::protocol::JobResultData;
use std::net::SocketAddr;

pub(crate) async fn execute_blocking(command: String) -> crate::commands::CommandResult {
    match tokio::task::spawn_blocking(move || crate::commands::CommandExecutor::execute(&command))
        .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => crate::commands::CommandResult {
            stdout: format!("Error: {}", e),
            stderr: String::new(),
            exit_code: -1,
        },
        Err(e) => crate::commands::CommandResult {
            stdout: format!("Error: command worker failed: {}", e),
            stderr: String::new(),
            exit_code: -1,
        },
    }
}

/// Consume local work until the runtime is shut down.
pub(crate) async fn run(node: &SisterNode) -> crate::Result<()> {
    loop {
        if node.shutdown.is_cancelled() {
            break;
        }
        if let Some(job) = node.jobs.pop() {
            let started = now_secs();
            node.jobs.mark_running(&job.id, started).await;

            tracing::info!(
                event = "job_started",
                sister_id = node.identity.id.as_u64(),
                job_id = %job.id,
                command = %job.command,
                "queued job execution started"
            );
            // Do not select away from a running blocking command: finish and
            // record it before the executor exits on cancellation.
            let result = execute_blocking(job.command.clone()).await;

            let finished = now_secs();
            let job_result = JobResultData {
                job_id: job.id.clone(),
                creator: job.creator,
                executor: node.identity.id.as_u64(),
                output: result.full_output(),
                exit_code: result.exit_code,
                success: result.success(),
                started_at: job.started_at.unwrap_or(started),
                finished_at: finished,
            };

            node.jobs.mark_finished(&job.id, &job_result).await;
            tracing::info!(
                event = if result.success() {
                    "job_completed"
                } else {
                    "job_failed"
                },
                sister_id = node.identity.id.as_u64(),
                job_id = %job.id,
                success = result.success(),
                exit_code = result.exit_code,
                output = %result.full_output(),
                "queued job execution finished"
            );

            // Return the result to the logical creator for a remotely-delegated
            // job. The transport used depends on the control plane in use.
            if job.creator != node.identity.id.as_u64() {
                let iroh = matches!(
                    &node.config.stream_backend,
                    crate::config::StreamBackend::Iroh(_)
                );
                let env = misaka_core::Envelope::new(
                    node.config.network_id,
                    misaka_core::MessageType::JobResponse,
                    // § transport identity: `from` is THIS Sister (the actual
                    // sender/executor); the logical creator stays in
                    // `job_result.creator`.
                    node.identity.id.as_u64(),
                    job.creator,
                    bincode::serialize(&job_result)?,
                );
                if iroh {
                    // Normal path: reach the creator over the authenticated Iroh
                    // control channel by SisterId. `creator_addr` is legacy
                    // DirectTcp callback metadata and is intentionally NOT used
                    // here — an Iroh delivery failure must NOT silently downgrade
                    // to a TCP callback to an unauthenticated address. The caller
                    // simply times out and must treat the command as "submitted,
                    // result unknown", never "not executed".
                    if let Err(error) = node.send_fire_to_peer(job.creator, &env).await {
                        tracing::warn!(
                            event = "job_result_route_unreachable",
                            job_id = %job.id,
                            creator = job.creator,
                            executor = node.identity.id.as_u64(),
                            %error,
                            "could not return job result over Iroh; the caller will time out (command may still have executed)"
                        );
                    }
                } else {
                    // DirectTcp compatibility: use the creator's callback address.
                    match job
                        .creator_addr
                        .as_ref()
                        .and_then(|addr| addr.parse::<SocketAddr>().ok())
                    {
                        Some(addr) => {
                            let _ = node.send_fire(addr, &env).await;
                        }
                        None => {
                            tracing::warn!(
                                event = "job_result_route_missing_addr",
                                job_id = %job.id,
                                "DirectTcp job has no usable creator callback address"
                            );
                        }
                    }
                }
            }
        } else {
            tokio::select! {
                _ = node.shutdown.cancelled() => break,
                _ = tokio::time::sleep(node.config.executor_poll_interval) => {}
            }
        }
    }
    Ok(())
}
