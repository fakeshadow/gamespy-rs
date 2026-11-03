//! Managed listener lifetime. Shutdown stops and joins the listener thread.
//!
//! [`Listener`] and [`StopSignal`] manage existing services; neither has its own
//! DNS endpoint. See the [crate endpoint table](crate) for service entry points.
use std::thread::{self, JoinHandle};

/// A clonable, one-way stop signal independent of any connection or runtime.
#[derive(Clone, Debug)]
pub struct StopSignal {
    state: tokio::sync::watch::Sender<bool>,
}
impl Default for StopSignal {
    fn default() -> Self {
        Self {
            state: tokio::sync::watch::channel(false).0,
        }
    }
}
impl StopSignal {
    pub fn stop(&self) {
        self.state.send_replace(true);
    }
    pub fn is_stopped(&self) -> bool {
        *self.state.borrow()
    }
    /// Resolves immediately if already stopped; wakes all concurrent waiters.
    pub async fn cancelled(&self) {
        let mut receiver = self.state.subscribe();
        let _ = receiver.wait_for(|stopped| *stopped).await;
    }
}

/// Lifecycle handle returned by service/transport spawn functions.
/// Retains no hostname configuration and does not create another endpoint.
#[must_use = "dropping the handle stops the listener"]
pub struct Listener {
    pub(crate) stop: StopSignal,
    pub(crate) thread: Option<JoinHandle<()>>,
}
impl Listener {
    /// Request shutdown and join the listener thread.
    pub fn shutdown(mut self) -> thread::Result<()> {
        self.stop.stop();
        self.thread.take().expect("listener thread").join()
    }
    /// Compatibility with process-lifetime applications; disables automatic shutdown.
    pub fn into_join_handle(mut self) -> JoinHandle<()> {
        self.thread.take().expect("listener thread")
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stop.stop();
            let _ = thread.join();
        }
    }
}
