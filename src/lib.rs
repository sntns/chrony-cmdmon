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
//! It speaks protocol version 6 (chrony 4.x), every command chronyd 4.x
//! accepts: [`Client`] has a method per `chronyc` command, and
//! [`Client::request`] sends any [`Request`]. [`protocol`] encodes the
//! requests and decodes the replies without I/O, for other transports.
//!
//! Privileged commands are only accepted over the Unix socket, which is
//! usually reachable by root and chronyd's own user only.

mod client;
pub mod protocol;

pub use client::Client;
pub use client::RawReply;
pub use client::DEFAULT_SOCKET;
pub use protocol::*;

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
    /// A request that can't be encoded (a source name too long, ...).
    InvalidRequest(&'static str),
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
            Error::InvalidRequest(what) => write!(f, "invalid request: {what}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_say_what_went_wrong() {
        let io = Error::from(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(io.to_string().starts_with("chronyd socket: "));
        assert!(std::error::Error::source(&io).is_some());
        for (error, text) in [
            (Error::Timeout, "chronyd did not answer"),
            (
                Error::Status(Status::NoSuchSource),
                "chronyd: No such source",
            ),
            (
                Error::Version(5),
                "chronyd speaks protocol version 5, not 6",
            ),
            (Error::Malformed("x"), "malformed answer from chronyd: x"),
            (Error::InvalidRequest("y"), "invalid request: y"),
        ] {
            assert_eq!(error.to_string(), text);
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}
