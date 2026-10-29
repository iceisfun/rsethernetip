//! Generic connection lifecycle management for protocol clients.
//!
//! Port of Go `transport/` (only the pieces `ethernetip` imports): the
//! [`Transport`] trait, [`DirectTransport`] (connect once, fail on error) and
//! [`ReconnectingTransport`] (lazy connect with automatic reconnection).
//!
//! Implementation detail, not spec: connection management policy is a library
//! concern; nothing in this module is defined by ODVA/Rockwell documents.

use std::sync::{Arc, Mutex, RwLock};

use crate::conn::{Error, Result};
use crate::plc::Context;

// Implementation detail (not spec): Go `transport.Connector[C]`.
/// Creates new connections of type `C`.
pub trait Connector<C>: Send + Sync {
    /// Establishes a new connection.
    fn connect(&self, ctx: &Context) -> Result<C>;
}

// Implementation detail (not spec): Go `transport.Closer[C]`.
/// Tears down a connection of type `C`.
pub trait Closer<C>: Send + Sync {
    /// Closes `conn`.
    fn close(&self, conn: &C) -> Result<()>;
}

// Implementation detail (not spec): Go `transport.Transport[C]` (+ optional `Peeker`).
/// Manages the lifecycle of a protocol connection of type `C`.
pub trait Transport<C>: Send + Sync {
    /// Returns an active connection, creating one if necessary.
    fn conn(&self, ctx: &Context) -> Result<C>;

    /// Invalidates a stale connection. Only the holder of the failed
    /// connection triggers the invalidation (prevents thundering-herd resets).
    fn reset(&self, stale: &C) -> Result<()>;

    /// Permanently shuts down the transport.
    fn close(&self) -> Result<()>;

    /// Non-blocking connection check (Go `Peeker`). `None` when the transport
    /// does not support peeking; never creates a connection.
    fn peek(&self) -> Option<bool> {
        None
    }
}

// Implementation detail (not spec): lifecycle hook storage (Go `transport.Config`).
/// Callback fired when a connection is lost or closed.
pub type DisconnectHook = Arc<dyn Fn(Option<&Error>) + Send + Sync>;

/// Lifecycle hooks shared by all transport implementations.
#[derive(Clone, Default)]
pub struct Config {
    /// Callbacks fired after a new connection is established, in registration order.
    pub on_connect: Vec<Arc<dyn Fn() + Send + Sync>>,
    /// Callbacks fired when a connection is lost or closed; the argument is the
    /// result of the underlying close call.
    pub on_disconnect: Vec<DisconnectHook>,
}

impl Config {
    fn fire_on_connect(&self) {
        for f in &self.on_connect {
            f();
        }
    }

    fn fire_on_disconnect(&self, err: Option<&Error>) {
        for f in &self.on_disconnect {
            f(err);
        }
    }
}

// Implementation detail (not spec): Go functional `transport.Option`.
/// A transport lifecycle option.
#[derive(Clone)]
pub enum TransportOption {
    /// Registers a callback fired after a connection is established.
    OnConnect(Arc<dyn Fn() + Send + Sync>),
    /// Registers a callback fired when a connection is lost.
    OnDisconnect(DisconnectHook),
}

/// Registers a callback that fires after a connection is established.
pub fn with_on_connect(f: impl Fn() + Send + Sync + 'static) -> TransportOption {
    TransportOption::OnConnect(Arc::new(f))
}

/// Registers a callback that fires when a connection is lost.
pub fn with_on_disconnect(f: impl Fn(Option<&Error>) + Send + Sync + 'static) -> TransportOption {
    TransportOption::OnDisconnect(Arc::new(f))
}

fn apply_options(opts: &[TransportOption]) -> Config {
    let mut cfg = Config::default();
    for o in opts {
        match o {
            TransportOption::OnConnect(f) => cfg.on_connect.push(f.clone()),
            TransportOption::OnDisconnect(f) => cfg.on_disconnect.push(f.clone()),
        }
    }
    cfg
}

// Implementation detail: lock helper tolerating poisoning (a panicking callback must not wedge the client).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct DirectState<C> {
    conn: Option<C>,
    active: bool,
    closed: bool,
}

// Implementation detail (not spec): Go `transport.DirectTransport`.
/// Connects once via a [`Connector`] and does not reconnect on failure. After
/// close or reset, subsequent [`Transport::conn`] calls return an error.
pub struct DirectTransport<C> {
    closer: Arc<dyn Closer<C>>,
    cfg: Config,
    state: Mutex<DirectState<C>>,
}

impl<C: Clone + PartialEq + Send + Sync + 'static> DirectTransport<C> {
    /// Connects immediately; fails if the initial connection fails
    /// (`direct transport connect: ...`).
    pub fn new(
        ctx: &Context,
        connector: Arc<dyn Connector<C>>,
        closer: Arc<dyn Closer<C>>,
        opts: &[TransportOption],
    ) -> Result<DirectTransport<C>> {
        let cfg = apply_options(opts);
        let conn = connector
            .connect(ctx)
            .map_err(|e| Error::wrap("direct transport connect", e))?;
        cfg.fire_on_connect();
        Ok(DirectTransport {
            closer,
            cfg,
            state: Mutex::new(DirectState { conn: Some(conn), active: true, closed: false }),
        })
    }
}

impl<C: Clone + PartialEq + Send + Sync + 'static> Transport<C> for DirectTransport<C> {
    fn conn(&self, _ctx: &Context) -> Result<C> {
        let st = lock(&self.state);
        if st.closed {
            return Err(Error::msg("transport is closed"));
        }
        match (&st.conn, st.active) {
            (Some(c), true) => Ok(c.clone()),
            _ => Err(Error::msg("transport connection was reset")),
        }
    }

    fn peek(&self) -> Option<bool> {
        let st = lock(&self.state);
        Some(st.active && !st.closed)
    }

    fn reset(&self, stale: &C) -> Result<()> {
        let mut st = lock(&self.state);
        if !st.active || st.conn.as_ref() != Some(stale) {
            return Ok(());
        }
        let conn = st.conn.take();
        st.active = false;
        let err = match conn {
            Some(c) => self.closer.close(&c).err(),
            None => None,
        };
        self.cfg.fire_on_disconnect(err.as_ref());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let mut st = lock(&self.state);
        if st.closed {
            return Ok(());
        }
        st.closed = true;
        if !st.active {
            return Ok(());
        }
        let conn = st.conn.take();
        st.active = false;
        let res = match conn {
            Some(c) => self.closer.close(&c),
            None => Ok(()),
        };
        self.cfg.fire_on_disconnect(res.as_ref().err());
        res
    }
}

struct ReconnState<C> {
    conn: Option<C>,
    closed: bool,
}

// Implementation detail (not spec): Go `transport.ReconnectingTransport`.
/// Creates connections lazily and re-creates them after failures. Uses a
/// read-lock fast path with a double-checked write-lock slow path so only one
/// thread performs reconnection.
pub struct ReconnectingTransport<C> {
    connector: Arc<dyn Connector<C>>,
    closer: Arc<dyn Closer<C>>,
    cfg: Config,
    state: RwLock<ReconnState<C>>,
}

impl<C: Clone + PartialEq + Send + Sync + 'static> ReconnectingTransport<C> {
    /// Never connects and never fails.
    pub fn new(
        connector: Arc<dyn Connector<C>>,
        closer: Arc<dyn Closer<C>>,
        opts: &[TransportOption],
    ) -> ReconnectingTransport<C> {
        ReconnectingTransport {
            connector,
            closer,
            cfg: apply_options(opts),
            state: RwLock::new(ReconnState { conn: None, closed: false }),
        }
    }

    /// Creates the transport and immediately connects to verify reachability
    /// (`reconnecting transport dial: ...` on failure).
    pub fn dial(
        ctx: &Context,
        connector: Arc<dyn Connector<C>>,
        closer: Arc<dyn Closer<C>>,
        opts: &[TransportOption],
    ) -> Result<ReconnectingTransport<C>> {
        let rt = ReconnectingTransport::new(connector, closer, opts);
        rt.conn(ctx).map_err(|e| Error::wrap("reconnecting transport dial", e))?;
        Ok(rt)
    }
}

impl<C: Clone + PartialEq + Send + Sync + 'static> Transport<C> for ReconnectingTransport<C> {
    fn conn(&self, ctx: &Context) -> Result<C> {
        // Fast path: read lock.
        {
            let st = self.state.read().unwrap_or_else(|e| e.into_inner());
            if st.closed {
                return Err(Error::msg("transport is closed"));
            }
            if let Some(c) = &st.conn {
                return Ok(c.clone());
            }
        }
        // Slow path: write lock, double-check.
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        if st.closed {
            return Err(Error::msg("transport is closed"));
        }
        if let Some(c) = &st.conn {
            return Ok(c.clone());
        }
        let conn = self.connector.connect(ctx)?;
        st.conn = Some(conn.clone());
        self.cfg.fire_on_connect();
        Ok(conn)
    }

    fn peek(&self) -> Option<bool> {
        let st = self.state.read().unwrap_or_else(|e| e.into_inner());
        Some(!st.closed && st.conn.is_some())
    }

    fn reset(&self, stale: &C) -> Result<()> {
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        if st.conn.as_ref() != Some(stale) {
            return Ok(());
        }
        let conn = st.conn.take();
        let err = match conn {
            Some(c) => self.closer.close(&c).err(),
            None => None,
        };
        self.cfg.fire_on_disconnect(err.as_ref());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        if st.closed {
            return Ok(());
        }
        st.closed = true;
        let conn = match st.conn.take() {
            Some(c) => c,
            None => return Ok(()),
        };
        let res = self.closer.close(&conn);
        self.cfg.fire_on_disconnect(res.as_ref().err());
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Test connection: identity compared by id.
    #[derive(Clone, PartialEq, Debug)]
    struct Id(usize);

    struct Counter(AtomicUsize, AtomicUsize);
    impl Connector<Id> for Counter {
        fn connect(&self, _: &Context) -> Result<Id> {
            Ok(Id(self.0.fetch_add(1, Ordering::SeqCst) + 1))
        }
    }
    impl Closer<Id> for Counter {
        fn close(&self, _: &Id) -> Result<()> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct Failing;
    impl Connector<Id> for Failing {
        fn connect(&self, _: &Context) -> Result<Id> {
            Err(Error::msg("boom"))
        }
    }

    #[test]
    fn direct_connects_once_and_does_not_reconnect() {
        let c = Arc::new(Counter(AtomicUsize::new(0), AtomicUsize::new(0)));
        let t = DirectTransport::new(&Context::background(), c.clone(), c.clone(), &[]).unwrap();
        let a = t.conn(&Context::background()).unwrap();
        assert_eq!(a, Id(1));
        assert_eq!(t.peek(), Some(true));
        t.reset(&a).unwrap();
        assert_eq!(t.peek(), Some(false));
        assert_eq!(t.conn(&Context::background()).unwrap_err().to_string(), "transport connection was reset");
        t.close().unwrap();
        assert_eq!(t.conn(&Context::background()).unwrap_err().to_string(), "transport is closed");
        assert_eq!(c.1.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn direct_initial_failure_is_wrapped() {
        let c = Arc::new(Counter(AtomicUsize::new(0), AtomicUsize::new(0)));
        let e = DirectTransport::<Id>::new(&Context::background(), Arc::new(Failing), c, &[]).err().unwrap();
        assert_eq!(e.to_string(), "direct transport connect: boom");
    }

    #[test]
    fn reconnecting_is_lazy_and_reconnects_after_reset() {
        let c = Arc::new(Counter(AtomicUsize::new(0), AtomicUsize::new(0)));
        let connects = Arc::new(AtomicUsize::new(0));
        let disconnects = Arc::new(AtomicUsize::new(0));
        let (cc, dd) = (connects.clone(), disconnects.clone());
        let t = ReconnectingTransport::new(
            c.clone(),
            c.clone(),
            &[
                with_on_connect(move || {
                    cc.fetch_add(1, Ordering::SeqCst);
                }),
                with_on_disconnect(move |_| {
                    dd.fetch_add(1, Ordering::SeqCst);
                }),
            ],
        );
        assert_eq!(t.peek(), Some(false));
        let a = t.conn(&Context::background()).unwrap();
        assert_eq!(t.conn(&Context::background()).unwrap(), a);
        // Resetting a different connection is a no-op.
        t.reset(&Id(99)).unwrap();
        assert_eq!(t.peek(), Some(true));
        t.reset(&a).unwrap();
        let b = t.conn(&Context::background()).unwrap();
        assert_ne!(a, b);
        assert_eq!(connects.load(Ordering::SeqCst), 2);
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);
        t.close().unwrap();
        t.close().unwrap();
        assert_eq!(t.conn(&Context::background()).unwrap_err().to_string(), "transport is closed");
    }

    #[test]
    fn reconnecting_dial_failure_is_wrapped() {
        let c = Arc::new(Counter(AtomicUsize::new(0), AtomicUsize::new(0)));
        let e = ReconnectingTransport::<Id>::dial(&Context::background(), Arc::new(Failing), c, &[]).err().unwrap();
        assert_eq!(e.to_string(), "reconnecting transport dial: boom");
    }
}
