//! An async client for chronyd's command and monitoring protocol - what
//! `chronyc` speaks - over chronyd's Unix socket.
//!
//! ```no_run
//! # async fn example() -> Result<(), chrony_cmdmon::Error> {
//! let chronyd = chrony_cmdmon::Client::connect(chrony_cmdmon::DEFAULT_SOCKET).await?;
//! let tracking = chronyd.tracking().await?;
//! println!("synchronized: {}, offset {:+.6} s", tracking.synchronized(), tracking.current_correction);
//! for source in chronyd.sources().await? {
//!     println!("{} {} reach {:o}", source.state.symbol(), source.address, source.reachability);
//! }
//! chronyd.reload_sources().await?;
//! # Ok(())
//! # }
//! ```
//!
//! It speaks protocol version 6 (chrony 4.x) and covers `tracking`,
//! `sources`, `burst`, `online` / `offline`, `makestep` and
//! `reload sources`. [`protocol`] encodes the requests and decodes the
//! replies without I/O, for other transports.
//!
//! Privileged commands are only accepted over the Unix socket, which is
//! usually reachable by root and chronyd's own user only.

mod client;
pub mod protocol;

pub use client::Client;
pub use client::DEFAULT_SOCKET;
pub use protocol::Address;
pub use protocol::LeapStatus;
pub use protocol::SourceData;
pub use protocol::SourceMode;
pub use protocol::SourceState;
pub use protocol::Status;
pub use protocol::Tracking;

/// What can go wrong talking to chronyd.
#[derive(Debug)]
pub enum Error {
    /// The socket: chronyd not running, not reachable, ...
    Io(std::io::Error),
    /// No answer after every attempt.
    Timeout,
    /// chronyd answered, but did not carry the command out.
    Status(Status),
    /// chronyd speaks another protocol version.
    Version(u8),
    /// An answer that can't be decoded.
    Malformed(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "chronyd socket: {e}"),
            Error::Timeout => f.write_str("chronyd did not answer"),
            Error::Status(status) => write!(f, "chronyd: {status}"),
            Error::Version(version) => write!(
                f,
                "chronyd speaks protocol version {version}, not {}",
                protocol::PROTOCOL_VERSION
            ),
            Error::Malformed(what) => write!(f, "malformed answer from chronyd: {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
