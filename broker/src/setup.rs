//! Everything the broker does before it serves, while nothing runs but the
//! main thread: the control channel from standard input, the install and
//! its one descriptor, the listening socket, the file of certificate
//! authorities and the TLS configuration. Any failure here ends the broker
//! without an answer; `server::run` answers `ready` once the sockets are
//! registered with the runtime too.
//!
//! The errors are plain text for the broker's standard error, which the
//! agent points at `/dev/null`: they name what failed, never a value (an
//! install's own reasons never contain one either).

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusthorse::broker_protocol::{self, Install, ToBroker};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use crate::config::Config;

/// Largest file of certificate authorities read, in bytes (the systems'
/// bundles are a few hundred KiB).
const MAX_CA_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// The only protocol offered to the destination.
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// What the broker serves once it has answered `ready`.
pub struct Prepared {
    /// The control channel, still blocking.
    pub control: UnixStream,
    /// The install, checked.
    pub install: Install,
    /// When it was received, on the boot-time clock: the grant's lifetime
    /// counts from then.
    pub received: Option<Duration>,
    /// The listening socket the agent bound, checked.
    pub listener: TcpListener,
    /// Its port: requests must carry `Host: 127.0.0.1:PORT`.
    pub port: u16,
    /// The TLS configuration for the destination.
    pub tls: Arc<ClientConfig>,
}

/// Read and check the install, within the ready deadline, and prepare
/// everything else the grant needs.
pub fn prepare(config: &Config) -> Result<Prepared, String> {
    let control = control_channel()?;
    let deadline = Instant::now() + config.limits.ready;
    let (message, fds) = broker_protocol::read_message::<ToBroker>(&control, Some(deadline))
        .map_err(|e| format!("no install arrived: {e}"))?;
    let received = crate::grant::boot_time();
    let ToBroker::Install(install) = message else {
        return Err("the first message is not an install".into());
    };
    install
        .validate()
        .map_err(|why| format!("the install has {why}"))?;
    let [listener] = <[OwnedFd; 1]>::try_from(fds)
        .map_err(|_| "the install does not carry exactly one descriptor".to_string())?;
    let (listener, port) = check_listener(listener)?;
    let ca = broker_protocol::open_ca_file()?;
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certificates(ca.file, &ca.path)?);
    if added == 0 {
        return Err(format!(
            "{} holds no usable certificate authority",
            ca.path.display()
        ));
    }
    if let Some(extra) = &config.extra_roots {
        add_roots(&mut roots, extra)?;
    }
    let tls = Arc::new(client_config(roots)?);
    Ok(Prepared {
        control,
        install,
        received,
        listener,
        port,
        tls,
    })
}

/// The control channel: standard input, a socket the agent shares with
/// standard output. A copy of the descriptor is used, without unsafe code.
fn control_channel() -> Result<UnixStream, String> {
    let fd = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| format!("no control channel: {e}"))?;
    Ok(UnixStream::from(fd))
}

/// Check the descriptor that came with the install: a listening TCP socket
/// (a stream socket of the IPv4 family) bound to `127.0.0.1` on a port.
pub fn check_listener(fd: OwnedFd) -> Result<(TcpListener, u16), String> {
    use nix::sys::socket::{SockType, getsockopt, sockopt};
    let kind = getsockopt(&fd, sockopt::SockType)
        .map_err(|e| format!("the descriptor is not a socket: {e}"))?;
    if kind != SockType::Stream {
        return Err("the descriptor is not a stream socket".into());
    }
    let listening = getsockopt(&fd, sockopt::AcceptConn)
        .map_err(|e| format!("cannot examine the socket: {e}"))?;
    if !listening {
        return Err("the socket is not listening".into());
    }
    let listener = TcpListener::from(fd);
    // Not an IP socket: its address does not parse.
    let address = listener
        .local_addr()
        .map_err(|_| "the socket is not an IP socket".to_string())?;
    match address {
        SocketAddr::V4(address) if *address.ip() == Ipv4Addr::LOCALHOST && address.port() != 0 => {
            Ok((listener, address.port()))
        }
        _ => Err("the socket is not bound to 127.0.0.1".into()),
    }
}

/// The certificates of a PEM file, read whole (at most
/// [`MAX_CA_FILE_BYTES`]). Sections of other kinds are skipped; a malformed
/// one fails the whole file.
fn certificates(file: impl Read, path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut pem = Vec::new();
    file.take(MAX_CA_FILE_BYTES + 1)
        .read_to_end(&mut pem)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if pem.len() as u64 > MAX_CA_FILE_BYTES {
        return Err(format!("{} is larger than 16 MiB", path.display()));
    }
    CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{} is not a valid PEM file: {e}", path.display()))
}

/// Add every certificate of the PEM file at `path` to `roots`; each must be
/// a usable authority.
fn add_roots(roots: &mut RootCertStore, path: &Path) -> Result<(), String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let certificates = certificates(file, path)?;
    if certificates.is_empty() {
        return Err(format!("{} holds no certificate", path.display()));
    }
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|e| format!("{} holds an unusable authority: {e}", path.display()))?;
    }
    Ok(())
}

/// The TLS configuration for destinations: the `ring` provider, TLS 1.3 and
/// 1.2, the authorities in `roots`, ALPN `http/1.1` only, no early data, no
/// key log, no client certificate, and no resumption (nothing is kept from
/// one connection to the next). The host is sent as SNI.
pub fn client_config(roots: RootCertStore) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("cannot configure TLS: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
    config.enable_early_data = false;
    config.enable_sni = true;
    config.key_log = Arc::new(rustls::NoKeyLog);
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::unix::net::UnixListener;

    fn fd_of(socket: impl Into<OwnedFd>) -> OwnedFd {
        socket.into()
    }

    #[test]
    fn only_a_listening_tcp_socket_on_127_0_0_1_is_served() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (_, got) = check_listener(fd_of(listener)).expect("a good listener");
        assert_eq!(got, port);

        // Another loopback address, every address, IPv6.
        for address in ["127.0.0.2:0", "0.0.0.0:0"] {
            let Ok(listener) = TcpListener::bind(address) else {
                continue;
            };
            assert!(check_listener(fd_of(listener)).is_err(), "{address}");
        }
        if let Ok(listener) = TcpListener::bind("[::1]:0") {
            assert!(check_listener(fd_of(listener)).is_err(), "::1");
        }
        // Not listening: a connected socket.
        let server = TcpListener::bind("127.0.0.1:0").expect("bind");
        let client =
            std::net::TcpStream::connect(server.local_addr().expect("addr")).expect("connect");
        assert_eq!(
            check_listener(fd_of(client)).map(|(_, port)| port),
            Err("the socket is not listening".into())
        );
        // Datagrams, a Unix socket, a pipe.
        let udp = UdpSocket::bind("127.0.0.1:0").expect("udp");
        assert_eq!(
            check_listener(fd_of(udp)).map(|(_, port)| port),
            Err("the descriptor is not a stream socket".into())
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let unix = UnixListener::bind(dir.path().join("s")).expect("unix");
        assert_eq!(
            check_listener(fd_of(unix)).map(|(_, port)| port),
            Err("the socket is not an IP socket".into())
        );
        let (read, _write) = nix::unistd::pipe().expect("pipe");
        assert!(check_listener(read).is_err());
    }

    #[test]
    fn the_tls_configuration_offers_only_what_phase_1_allows() {
        let config = client_config(RootCertStore::empty()).expect("config");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(!config.enable_early_data);
        assert!(config.enable_sni);
        assert!(!config.key_log.will_log("CLIENT_RANDOM"));
        assert!(!config.enable_secret_extraction);
        assert!(!config.client_auth_cert_resolver.has_certs());
        // Nothing kept from one connection to the next. (TLS 1.2 and 1.3 are
        // shown end to end, against destinations that speak only one.)
        let resumption = format!("{:?}", config.resumption);
        assert!(
            resumption.contains("NoClientSessionStorage"),
            "{resumption}"
        );
        assert!(resumption.contains("Disabled"), "{resumption}");
    }

    #[test]
    fn pem_files_are_read_strictly_and_with_a_bound() {
        let path = Path::new("test.pem");
        assert_eq!(certificates(&b""[..], path), Ok(Vec::new()));
        // Other kinds of section are skipped.
        let key = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert_eq!(certificates(&key[..], path), Ok(Vec::new()));
        // A malformed certificate section fails the file.
        let broken = b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        assert!(certificates(&broken[..], path).is_err());
        let unterminated = b"-----BEGIN CERTIFICATE-----\nAAAA\n";
        assert!(certificates(&unterminated[..], path).is_err());
        // Too large: refused without reading further.
        let huge = std::io::repeat(b'\n').take(MAX_CA_FILE_BYTES + 10);
        assert!(certificates(huge, path).is_err());
    }
}
