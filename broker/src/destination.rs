//! Reaching the destination: resolving the origin's host, keeping only
//! public addresses, and connecting to one of them — resolving and
//! connecting together within `CONNECT_TIMEOUT`, never resolving again.
//!
//! At most `MAX_CONCURRENT_RESOLUTIONS` names are resolved at a time, and a
//! resolution keeps its place until the system's resolver returns, even
//! after its request gave up waiting: a resolver that hangs cannot make the
//! broker start more of them.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rusthorse::broker_profile::BrokerProfile;
use rusthorse::broker_protocol::MAX_CONCURRENT_RESOLUTIONS;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::Config;

/// Why the destination could not be reached. Nothing was sent to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// The name did not resolve.
    Resolve,
    /// It resolved to no address the broker may connect to.
    NoPublicAddress,
    /// No checked address accepted the connection.
    Connect,
    /// Resolving and connecting took longer than allowed.
    TimedOut,
}

/// Whether `ip` is a public address: not loopback, private, link-local,
/// unique-local, shared (`100.64.0.0/10`), multicast, broadcast, unspecified,
/// reserved, a documentation or benchmarking range, nor any IPv6 form that
/// carries an IPv4 address (mapped, compatible, 6to4, Teredo). An address of
/// the well-known NAT64 prefix (`64:ff9b::/96`) is public when the IPv4
/// address it carries is.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let special = a == 0 // "this network", 0.0.0.0 included
        || a == 10 // private
        || (a == 100 && (64..=127).contains(&b)) // shared (carrier-grade NAT)
        || a == 127 // loopback
        || (a == 169 && b == 254) // link-local
        || (a == 172 && (16..=31).contains(&b)) // private
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2) // documentation (TEST-NET-1)
        || (a == 192 && b == 88 && c == 99) // 6to4 relays (deprecated)
        || (a == 192 && b == 168) // private
        || (a == 198 && (18..=19).contains(&b)) // benchmarking
        || (a == 198 && b == 51 && c == 100) // documentation (TEST-NET-2)
        || (a == 203 && b == 0 && c == 113) // documentation (TEST-NET-3)
        || a >= 224; // multicast, reserved, broadcast
    !special
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // The well-known NAT64 prefix carries an IPv4 address: judge that one.
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [a, b] = s[6].to_be_bytes();
        let [c, d] = s[7].to_be_bytes();
        return is_public_v4(Ipv4Addr::new(a, b, c, d));
    }
    // Only global unicast (2000::/3): this leaves out the unspecified and
    // loopback addresses, the IPv4-mapped and IPv4-compatible forms,
    // unique-local, link-local, site-local and multicast addresses, and
    // everything not assigned.
    let global = s[0] & 0xe000 == 0x2000;
    let special = (s[0] == 0x2001 && s[1] < 0x0200) // IETF assignments: Teredo, benchmarking, ORCHID
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || s[0] == 0x2002 // 6to4
        || (s[0] == 0x3fff && s[1] < 0x1000); // documentation (3fff::/20)
    global && !special
}

/// Whether the broker may connect to `ip`: a public address, or, for tests
/// only (`allow_loopback`), `127.0.0.0/8` or `::1` — never another private
/// address, nor an IPv6 form of a loopback one.
pub fn is_allowed(ip: IpAddr, allow_loopback: bool) -> bool {
    let test_loopback = match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip == Ipv6Addr::LOCALHOST,
    };
    is_public(ip) || (allow_loopback && test_loopback)
}

/// Lookups that block, at most a fixed number at a time, each holding its
/// place until it returns.
pub struct Resolver {
    places: Arc<Semaphore>,
}

impl Resolver {
    /// At most `places` lookups at a time.
    pub fn new(places: usize) -> Resolver {
        Resolver {
            places: Arc::new(Semaphore::new(places)),
        }
    }

    /// Run `lookup` on a thread of its own once a place is free; `None` if
    /// it could not run. Whoever awaits this may stop waiting: the lookup
    /// keeps its place until it returns.
    pub async fn run<T: Send + 'static>(
        &self,
        lookup: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let place = Arc::clone(&self.places).acquire_owned().await.ok()?;
        tokio::task::spawn_blocking(move || {
            let _place = place;
            lookup()
        })
        .await
        .ok()
    }
}

/// The destination of a grant.
pub struct Destination {
    host: String,
    port: u16,
    resolver: Resolver,
    allow_loopback: bool,
    addresses: Option<Vec<IpAddr>>,
    resolve_delay: Duration,
    deadline: Duration,
}

impl Destination {
    /// The destination of `profile`, as `config` says to reach it.
    pub fn new(profile: &BrokerProfile, config: &Config) -> Destination {
        Destination {
            host: profile.host().to_string(),
            port: profile.port(),
            resolver: Resolver::new(MAX_CONCURRENT_RESOLUTIONS),
            allow_loopback: config.allow_loopback,
            addresses: config.addresses.clone(),
            resolve_delay: config.resolve_delay,
            deadline: config.limits.connect,
        }
    }

    /// Resolve the host and connect to the first checked address that
    /// accepts, within the deadline.
    pub async fn connect(&self) -> Result<TcpStream, Unreachable> {
        tokio::time::timeout(self.deadline, self.resolve_and_connect())
            .await
            .unwrap_or(Err(Unreachable::TimedOut))
    }

    async fn resolve_and_connect(&self) -> Result<TcpStream, Unreachable> {
        let checked: Vec<SocketAddr> = self
            .resolve()
            .await?
            .into_iter()
            .filter(|address| is_allowed(address.ip(), self.allow_loopback))
            .collect();
        if checked.is_empty() {
            return Err(Unreachable::NoPublicAddress);
        }
        for address in checked {
            // An address, not a name: nothing is resolved again.
            if let Ok(stream) = TcpStream::connect(address).await {
                return Ok(stream);
            }
        }
        Err(Unreachable::Connect)
    }

    async fn resolve(&self) -> Result<Vec<SocketAddr>, Unreachable> {
        let host = self.host.clone();
        let port = self.port;
        let fixed = self.addresses.clone();
        let delay = self.resolve_delay;
        let lookup = move || -> io::Result<Vec<SocketAddr>> {
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            match fixed {
                Some(fixed) => Ok(fixed
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect()),
                None => (host.as_str(), port)
                    .to_socket_addrs()
                    .map(Iterator::collect),
            }
        };
        match self.resolver.run(lookup).await {
            Some(Ok(addresses)) => Ok(addresses),
            _ => Err(Unreachable::Resolve),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    #[test]
    fn only_public_addresses_are_allowed() {
        let public = [
            "1.1.1.1",
            "8.8.8.8",
            "160.79.104.10",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.1",
            "192.88.98.1",
            "192.169.0.1",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "2607:6bc0::10",
            "2a00:1450:4001:80b::200e",
            "2001:4860:4860::8888",
            "2001:200::1",
            "2620:4f:8000::1",
            "3ffe::1",
            "3fff:1000::1",
            "64:ff9b::808:808",
        ];
        let refused = [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "10.255.255.255",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:8.8.8.8",
            "::127.0.0.1",
            "::10.0.0.1",
            "::8.8.8.8",
            "::ffff:0:10.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::808:808",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "ff05::2",
            "100::1",
            "2001::1",
            "2001:0:4136:e378::1",
            "2001:2::1",
            "2001:10::1",
            "2001:1ff::1",
            "2001:db8::1",
            "2002:a00:1::1",
            "2002:808:808::1",
            "3fff::1",
            "3fff:fff::1",
            "4000::1",
            "5f00::1",
        ];
        for ip in public {
            let ip: IpAddr = ip.parse().expect(ip);
            assert!(is_public(ip), "{ip} is public");
            assert!(is_allowed(ip, false), "{ip}");
        }
        for ip in refused {
            let ip: IpAddr = ip.parse().expect(ip);
            assert!(!is_public(ip), "{ip} is not public");
            assert!(!is_allowed(ip, false), "{ip}");
        }
    }

    #[test]
    fn tests_may_reach_loopback_and_nothing_else_private() {
        for ip in ["127.0.0.1", "127.1.2.3", "::1"] {
            let ip: IpAddr = ip.parse().expect(ip);
            assert!(is_allowed(ip, true), "{ip}");
            assert!(!is_allowed(ip, false), "{ip}");
        }
        for ip in [
            "10.0.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "::",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "fe80::1",
            "fd00::1",
        ] {
            let ip: IpAddr = ip.parse().expect(ip);
            assert!(!is_allowed(ip, true), "{ip}");
        }
    }

    /// Through a destination built as the broker builds it, on a runtime
    /// whose pool of blocking threads is far larger than the limit: only the
    /// resolver's places hold the lookups back.
    #[tokio::test(flavor = "current_thread")]
    async fn a_destination_runs_at_most_the_allowed_lookups_at_once_even_abandoned_ones() {
        use rusthorse::broker_profile::{Preset, ProfileRequest};
        let profile = ProfileRequest::new(Preset::Anthropic)
            .resolve()
            .expect("profile");
        let destination = Arc::new(Destination::new(&profile, &Config::release()));
        let running = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let (release, released) = mpsc::channel::<()>();
        let released = Arc::new(std::sync::Mutex::new(released));
        let lookup = || {
            let (running, most, released) = (running.clone(), most.clone(), released.clone());
            move || {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                let _ = released.lock().expect("lock").recv();
                running.fetch_sub(1, Ordering::SeqCst);
            }
        };
        // Lookups whose callers give up keep their places.
        for _ in 0..MAX_CONCURRENT_RESOLUTIONS + 2 {
            let destination = destination.clone();
            let lookup = lookup();
            let abandoned = tokio::time::timeout(Duration::from_millis(50), async move {
                destination.resolver.run(lookup).await
            })
            .await;
            assert!(abandoned.is_err(), "the lookup blocks");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(running.load(Ordering::SeqCst), MAX_CONCURRENT_RESOLUTIONS);
        // Another one waits for a place.
        let waiting = tokio::spawn({
            let destination = destination.clone();
            let lookup = lookup();
            async move { destination.resolver.run(lookup).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiting.is_finished());
        for _ in 0..MAX_CONCURRENT_RESOLUTIONS + 3 {
            release.send(()).expect("release");
        }
        assert_eq!(waiting.await.expect("join"), Some(()));
        assert_eq!(most.load(Ordering::SeqCst), MAX_CONCURRENT_RESOLUTIONS);
    }
}
