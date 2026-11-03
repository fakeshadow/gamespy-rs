//! Async TCP handlers on a private runtime with per-task cancellation.
//!
//! Connections, spawn functions and shutdown settings are service-independent.
//! They have no default domain or port; see the [crate endpoint table](crate)
//! for the protocols layered on this transport.
use crate::listener::{Listener, StopSignal};
use std::{
    future::{Future, poll_fn},
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    pin::Pin,
    task::{Context, Poll},
    thread,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Best-effort shutdown policy for a TCP listener.
#[derive(Clone, Copy, Debug)]
pub struct ShutdownConfig {
    /// Time for active handlers to finish after accepting stops.
    pub grace_period: Duration,
    /// Time allowed for Tokio runtime shutdown after remaining handlers cancel.
    pub runtime_timeout: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            grace_period: Duration::from_secs(2),
            runtime_timeout: Duration::from_millis(100),
        }
    }
}

/// An owned connection with inherent async I/O; no I/O trait imports are needed.
/// Cancellation belongs to the listener, not to the socket.
/// Wraps an existing socket; it does not retain the client's resolved DNS name
/// or offer hostname resolution. Address accessors return numeric socket addresses.
#[derive(Debug)]
pub struct Connection {
    stream: tokio::net::TcpStream,
    read_timeout: Option<Duration>,
}

impl Connection {
    /// Import an accepted socket inside a runtime handler. Outside a runtime,
    /// returns an error. The socket is switched to nonblocking mode.
    pub fn from_stream(stream: TcpStream) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream: tokio::net::TcpStream::from_std(stream)?,
            read_timeout: None,
        })
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }
    pub fn set_nodelay(&self, value: bool) -> io::Result<()> {
        self.stream.set_nodelay(value)
    }
    /// Set the deadline for each `read` (and each read within `read_exact`).
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.read_timeout = timeout;
        Ok(())
    }
    /// Poll socket readiness directly, without applying the `read` timeout.
    pub fn poll_read(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut buffer = ReadBuf::new(bytes);
        match Pin::new(&mut self.stream).poll_read(cx, &mut buffer) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
    pub fn poll_write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    /// Cancellation-safe: dropping this future does not consume unread bytes.
    pub async fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let timeout = self.read_timeout;
        let read = poll_fn(|cx| self.poll_read(cx, bytes));
        match timeout {
            Some(timeout) => tokio::time::timeout(timeout, read)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
            None => read.await,
        }
    }
    /// May consume a partial buffer if cancelled or an error is returned.
    pub async fn read_exact(&mut self, mut bytes: &mut [u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            match self.read(bytes).await {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => bytes = &mut bytes[n..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    pub async fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        poll_fn(|cx| self.poll_write(cx, bytes)).await
    }
    /// May send a partial buffer if cancelled or an error is returned.
    pub async fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            match self.write(bytes).await {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => bytes = &bytes[n..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    pub async fn flush(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_flush(cx)).await
    }
    /// Finish the write side explicitly. Reads may continue until the peer closes.
    pub async fn shutdown(&mut self) -> io::Result<()> {
        poll_fn(|cx| Pin::new(&mut self.stream).poll_shutdown(cx)).await
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // One nonblocking attempt only; never run an executor or wait in Drop.
        // TcpStream is unbuffered. If shutdown fails or is pending, closing the
        // owned socket below is an acceptable best-effort fallback.
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let _ = Pin::new(&mut self.stream).poll_shutdown(&mut cx);
    }
}

/// Start async handlers on a private runtime. The handler is cloned for each
/// connection and produces an owned, Send future; callers need no Tokio setup.
/// Handlers must yield promptly so cancellation can be observed.
///
/// This generic transport has no service hostname or default port. The caller
/// supplies a bound listener; `name` is a diagnostic label, not a DNS name.
/// See the [crate DNS guide](crate) for the service-specific entry points.
pub fn spawn_with_listener<F>(
    listener: TcpListener,
    name: &'static str,
    handler: impl FnOnce(Connection) -> F + Clone + Send + 'static,
) -> io::Result<Listener>
where
    F: Future<Output = ()> + Send + 'static,
{
    spawn_with_listener_and_config(listener, name, ShutdownConfig::default(), handler)
}

/// Start a listener with an explicit best-effort shutdown policy.
/// DNS and port selection follow [`spawn_with_listener`]; `name` is only a label.
pub fn spawn_with_listener_and_config<F>(
    listener: TcpListener,
    name: &'static str,
    config: ShutdownConfig,
    handler: impl FnOnce(Connection) -> F + Clone + Send + 'static,
) -> io::Result<Listener>
where
    F: Future<Output = ()> + Send + 'static,
{
    listener.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let listener = {
        let _entered = runtime.enter();
        tokio::net::TcpListener::from_std(listener)?
    };
    let stop = StopSignal::default();
    let signal = stop.clone();
    let thread = thread::Builder::new().name(name.into()).spawn(move || {
        runtime.block_on(async {
            let mut workers: Vec<(StopSignal, tokio::task::JoinHandle<()>)> = Vec::new();
            loop {
                workers.retain(|(_, worker)| !worker.is_finished());
                tokio::select! {
                    biased;
                    _ = signal.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => {
                            let stop = StopSignal::default();
                            let future = handler.clone()(Connection { stream, read_timeout: None });
                            let worker = tokio::spawn(run_connection(future, stop.clone(), config.grace_period));
                            workers.push((stop, worker));
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            }
            drop(listener);
            for (stop, _) in &workers {
                stop.stop();
            }
            for (_, worker) in workers {
                let _ = worker.await;
            }
        });
        runtime.shutdown_timeout(config.runtime_timeout);
    })?;
    Ok(Listener {
        stop,
        thread: Some(thread),
    })
}

// Each task independently observes its token and allows its handler to finish
// within the grace period. Dropping a pending handler closes its connection.
async fn run_connection(future: impl Future<Output = ()>, stop: StopSignal, grace: Duration) {
    tokio::select! {
        _ = future => {},
        _ = async {
            stop.cancelled().await;
            tokio::time::sleep(grace).await;
        } => {},
    }
}

#[cfg(test)]
mod tests;
