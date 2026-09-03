//! Unified runtime shutdown and cancellation.
//!
//! A `Shutdown` owns the cancellation sender. Cloneable `ShutdownToken`s are
//! passed to long-lived runtime tasks. The implementation uses Tokio's
//! built-in watch channel so the runtime does not need another dependency.

use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct Shutdown {
    tx: watch::Sender<bool>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self { tx }
    }

    pub fn token(&self) -> ShutdownToken {
        ShutdownToken {
            rx: self.tx.subscribe(),
        }
    }

    /// Request shutdown. Returns false only if the sender has been closed.
    /// Repeated cancellation requests are harmless and return true.
    pub fn cancel(&self) -> bool {
        self.tx.send_replace(true);
        true
    }

    pub fn is_cancelled(&self) -> bool {
        *self.tx.borrow()
    }

    /// Install a process signal listener that requests graceful shutdown.
    /// The returned task may be aborted by the caller after `run` returns.
    pub fn install_signal_handler(&self) -> JoinHandle<()> {
        let shutdown = self.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = match signal(SignalKind::terminate()) {
                    Ok(signal) => signal,
                    Err(error) => {
                        tracing::warn!(event = "shutdown_signal_handler_failed", ?error);
                        return;
                    }
                };
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result {
                            tracing::warn!(event = "shutdown_signal_handler_failed", ?error);
                            return;
                        }
                    }
                    _ = sigterm.recv() => {}
                }
            }
            #[cfg(not(unix))]
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::warn!(event = "shutdown_signal_handler_failed", ?error);
                return;
            }

            tracing::info!(event = "shutdown_signal", "graceful shutdown requested");
            shutdown.cancel();
        })
    }
}

#[derive(Clone)]
pub struct ShutdownToken {
    rx: watch::Receiver<bool>,
}

impl ShutdownToken {
    /// A token that is never cancelled. Used by standalone, non-looping nodes.
    pub fn never() -> Self {
        let (tx, rx) = watch::channel(false);
        // Keep the sender alive for the lifetime of this token. This constructor
        // is used only by short-lived CLI client nodes, not runtime services.
        std::mem::forget(tx);
        Self { rx }
    }

    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves after cancellation. A closed channel also resolves so tasks do
    /// not remain stuck if their owner disappears unexpectedly.
    pub async fn cancelled(&self) {
        let mut rx = self.rx.clone();
        if *rx.borrow() {
            return;
        }
        let _ = rx.changed().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancellation_reaches_token() {
        let shutdown = Shutdown::new();
        let token = shutdown.token();
        let waiter = tokio::spawn(async move {
            token.cancelled().await;
            token.is_cancelled()
        });
        shutdown.cancel();
        assert!(waiter.await.unwrap());
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn cancellation_wait_does_not_resolve_before_cancel() {
        let shutdown = Shutdown::new();
        let token = shutdown.token();
        let result = tokio::time::timeout(Duration::from_millis(20), token.cancelled()).await;
        assert!(result.is_err());
        assert!(!shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn never_token_stays_pending() {
        let token = ShutdownToken::never();
        let result = tokio::time::timeout(Duration::from_millis(20), token.cancelled()).await;
        assert!(result.is_err());
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent() {
        let shutdown = Shutdown::new();
        assert!(shutdown.cancel());
        assert!(shutdown.cancel());
    }
}
