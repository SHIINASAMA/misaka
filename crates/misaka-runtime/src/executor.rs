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

            // 远端委派来的任务：回送结果给 creator
            if job.creator != node.identity.id.as_u64() {
                if let Some(creator_addr) = job.creator_addr {
                    if let Ok(addr) = creator_addr.parse::<SocketAddr>() {
                        let env = misaka_core::Envelope::new(
                            node.config.network_id,
                            misaka_core::MessageType::JobResponse,
                            node.identity.id.as_u64(),
                            job.creator,
                            bincode::serialize(&job_result)?,
                        );
                        let delivered = if matches!(
                            &node.config.stream_backend,
                            crate::config::StreamBackend::Iroh(_)
                        ) {
                            node.send_fire_to_peer(job.creator, &env).await
                        } else {
                            // The standalone `run --sister` command owns a
                            // temporary response listener. Direct TCP must
                            // preserve that callback address rather than
                            // sending the result to the long-running Sister.
                            node.send_fire(addr, &env).await
                        };
                        if delivered.is_err()
                            && matches!(
                                &node.config.stream_backend,
                                crate::config::StreamBackend::Iroh(_)
                            )
                        {
                            let _ = node.send_fire(addr, &env).await;
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
