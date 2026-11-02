//! Broker profiles: what a grant of the credential broker allows
//! ([ADR 0013](../docs/adr/0013-credential-broker.md)).
//!
//! A profile belongs to an entry. It names a built-in [`Preset`] and the
//! revision of it that the human approved, the destination's origin and base
//! path, and the grant policy: whether the automatic locks end the entry's
//! grants, their maximum lifetime, and an optional request limit. It is
//! stored in the entry's custom field `Rusthorse.Broker`
//! ([`crate::vault::FIELD_BROKER`]), unprotected, as one line of JSON with
//! every field written out ([`BrokerProfile::to_stored`]), so that a later
//! default never changes it; it is read strictly ([`BrokerProfile::parse`]):
//! anything unexpected makes it unusable, and nothing guesses. A profile holds
//! no secret.
//!
//! The rules a grant enforces are pure functions here, shared by the agent
//! and `rusthorse-broker` so that both decide alike: the presets' routes and
//! header rules ([`PresetSpec`]), route matching ([`is_origin_form`],
//! [`match_route`]), the check of the token a client presents
//! ([`check_inbound_token`]) and of the credential a broker presents
//! ([`is_valid_credential`]).

use std::fmt;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};

use crate::broker_protocol::{MAX_IN_FLIGHT, is_well_formed_token};
use crate::protocol::SecretString;
use crate::util;

/// The profile format this build reads and writes.
pub const PROFILE_VERSION: u32 = 1;

/// Longest stored profile, in characters; a longer one is unusable.
pub const MAX_PROFILE_CHARS: usize = 1000;

/// The maximum lifetimes a profile may give its grants, in minutes: up to a
/// day.
pub const MAX_LIFETIME_MINUTES_RANGE: RangeInclusive<u32> = 1..=1440;

/// The request limits a profile may set.
pub const MAX_REQUESTS_RANGE: RangeInclusive<u64> = 1..=1_000_000;

/// Shortest credential, in characters, that a broker presents to a
/// destination ([`is_valid_credential`]). It is above the length under which
/// the redactor ignores a secret ([`crate::redact::MIN_REDACT_LEN`]): the
/// redactor replaces literal copies of any credential the broker accepts.
pub const MIN_CREDENTIAL_CHARS: usize = 8;

/// Longest credential, in characters, that a broker presents to a
/// destination ([`is_valid_credential`]): it travels in a header.
pub const MAX_CREDENTIAL_CHARS: usize = 4096;

// A credential the broker accepts is never too short for the redactor.
const _: () = assert!(MIN_CREDENTIAL_CHARS >= crate::redact::MIN_REDACT_LEN);

/// Longest host name of an origin, as DNS allows.
const MAX_HOST_CHARS: usize = 253;
/// Longest label of a host name, as DNS allows.
const MAX_LABEL_CHARS: usize = 63;
/// Longest `{id}` segment of a route, and longest query value.
const MAX_ID_CHARS: usize = 128;

/// A preset built into the program: the routes a grant allows, how the
/// client presents the token and how the credential is presented to the
/// destination. Each has revisions ([`PresetSpec`]); a stored profile names
/// the one the human approved, and a newer Rusthorse keeps old revisions as
/// they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    /// The Anthropic API (`https://api.anthropic.com` by default).
    Anthropic,
    /// The OpenAI API (`https://api.openai.com/v1` by default).
    Openai,
    /// An API that follows OpenAI's, at an origin the profile names (there
    /// is no default), with fewer routes than [`Preset::Openai`].
    OpenaiCompatible,
}

impl Preset {
    /// Every preset.
    pub const ALL: [Preset; 3] = [Self::Anthropic, Self::Openai, Self::OpenaiCompatible];

    /// The stored and serialized form: `anthropic`, `openai`,
    /// `openai-compatible`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Openai => "openai",
            Self::OpenaiCompatible => "openai-compatible",
        }
    }

    /// A name for people: `Anthropic`, `OpenAI`, `OpenAI-compatible`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::Openai => "OpenAI",
            Self::OpenaiCompatible => "OpenAI-compatible",
        }
    }
}

impl fmt::Display for Preset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Preset {
    type Err = ProfileError;

    /// The preset written exactly as [`Preset::as_str`] writes it.
    fn from_str(text: &str) -> Result<Self, ProfileError> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str() == text)
            .ok_or(ProfileError::UnknownPreset)
    }
}

/// Whether the automatic locks — the screen locking, the computer
/// suspending, the idle timeout — end an entry's grants (ADR 0013, decision
/// 8). The explicit `rusthorse lock` ends every grant whatever this says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticLocks {
    /// They end the entry's grants.
    End,
    /// They do not: the grants keep working while the screen is locked,
    /// even though the vault itself locks.
    Continue,
}

impl AutomaticLocks {
    /// Both policies.
    pub const ALL: [AutomaticLocks; 2] = [Self::End, Self::Continue];

    /// The stored and serialized form: `end` or `continue`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::End => "end",
            Self::Continue => "continue",
        }
    }
}

impl fmt::Display for AutomaticLocks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AutomaticLocks {
    type Err = ProfileError;

    /// The policy written exactly as [`AutomaticLocks::as_str`] writes it.
    fn from_str(text: &str) -> Result<Self, ProfileError> {
        Self::ALL
            .into_iter()
            .find(|l| l.as_str() == text)
            .ok_or(ProfileError::UnknownLocks)
    }
}

/// Why a profile is unusable, or cannot be made.
///
/// The messages never repeat what they refuse at length: a stored profile
/// is metadata, but it may have been written by another program.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The stored text has a line break.
    #[error("the profile must be one line of JSON")]
    NotOneLine,
    /// The stored text is longer than [`MAX_PROFILE_CHARS`].
    #[error("the profile is {0} characters long; at most {MAX_PROFILE_CHARS} are read")]
    TooLong(usize),
    /// Not JSON of the expected shape: a syntax error, an unknown, missing
    /// or repeated field, a value of the wrong type, an unknown preset or
    /// policy. The text is escaped and shortened.
    #[error("the profile is not valid: {0}")]
    Json(String),
    /// A format version this build does not read.
    #[error("profile version {0} is unknown (this Rusthorse reads version {PROFILE_VERSION})")]
    Version(u64),
    /// A preset name that is none of [`Preset::ALL`].
    #[error("unknown preset; the presets are anthropic, openai and openai-compatible")]
    UnknownPreset,
    /// A policy for the automatic locks other than `end` and `continue`.
    #[error("unknown policy for the automatic locks; use end or continue")]
    UnknownLocks,
    /// A revision of the preset this build does not know.
    #[error("revision {revision} of the {preset} preset is unknown to this Rusthorse")]
    Revision {
        /// The preset.
        preset: Preset,
        /// The unknown revision.
        revision: u32,
    },
    /// The origin is not `https://` and a host name, with an optional port.
    #[error("the origin is not valid: {0}")]
    Origin(&'static str),
    /// The preset has no default origin, and none was given.
    #[error("the {0} preset has no default origin; name one")]
    OriginRequired(Preset),
    /// The base path is not empty or `/` and segments.
    #[error("the base path is not valid: {0}")]
    BasePath(&'static str),
    /// The maximum lifetime is outside [`MAX_LIFETIME_MINUTES_RANGE`].
    #[error("the maximum lifetime must be 1 to 1440 minutes, not {0}")]
    Lifetime(u32),
    /// The request limit is outside [`MAX_REQUESTS_RANGE`].
    #[error("the request limit must be 1 to 1000000, not {0}")]
    Requests(u64),
}

/// A broker profile: an entry's destination and grant policy, as stored in
/// its `Rusthorse.Broker` field.
///
/// The fields are public so that tests and the protocol can build and read
/// profiles; a profile from [`BrokerProfile::parse`] or
/// [`ProfileRequest::resolve`] has passed [`BrokerProfile::validate`], and
/// one from anywhere else must be validated before it is used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerProfile {
    /// The format: [`PROFILE_VERSION`].
    pub version: u32,
    /// The preset.
    pub preset: Preset,
    /// The revision of the preset the human approved.
    pub revision: u32,
    /// `https://` and a host name, with an optional port: no IP address,
    /// user information, path, query or fragment. In lowercase.
    pub origin: String,
    /// What the client's base URL adds after the origin: empty, or `/` and
    /// segments of letters, digits, `.`, `_`, `~` and `-`.
    pub base_path: String,
    /// Whether the automatic locks end the entry's grants.
    pub automatic_locks: AutomaticLocks,
    /// The longest a grant lasts, in minutes ([`MAX_LIFETIME_MINUTES_RANGE`]).
    pub max_lifetime_minutes: u32,
    /// The most requests one grant admits ([`MAX_REQUESTS_RANGE`]); `None`
    /// for no limit. Left out of the stored form when there is none; an
    /// explicit `null` is refused.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_u64"
    )]
    pub max_requests: Option<u64>,
}

/// A field that, when present, must hold a number: `null` is refused.
fn present_u64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    u64::deserialize(deserializer).map(Some)
}

/// What [`BrokerProfile::parse`] reads first when a profile does not parse,
/// to tell a profile of another version from a broken one.
#[derive(Deserialize)]
struct VersionOnly {
    version: u64,
}

fn json_error(e: serde_json::Error) -> ProfileError {
    ProfileError::Json(util::truncate(&util::visible(&e.to_string()), 200))
}

impl BrokerProfile {
    /// Read a stored profile, strictly: one line of at most
    /// [`MAX_PROFILE_CHARS`] characters, JSON with every field of this
    /// format and no other (only `max_requests` may be left out), a known
    /// version, preset and revision, and every value valid
    /// ([`BrokerProfile::validate`]). The fields may come in any order, with
    /// spaces between them.
    pub fn parse(stored: &str) -> Result<BrokerProfile, ProfileError> {
        let chars = stored.chars().count();
        if chars > MAX_PROFILE_CHARS {
            return Err(ProfileError::TooLong(chars));
        }
        if stored.contains(['\n', '\r']) {
            return Err(ProfileError::NotOneLine);
        }
        let profile: BrokerProfile = match serde_json::from_str(stored) {
            Ok(profile) => profile,
            Err(e) => {
                // A profile of another version may well have other fields:
                // say that it is of another version.
                if let Ok(VersionOnly { version }) = serde_json::from_str(stored)
                    && version != u64::from(PROFILE_VERSION)
                {
                    return Err(ProfileError::Version(version));
                }
                return Err(json_error(e));
            }
        };
        profile.validate()?;
        Ok(profile)
    }

    /// The stored form: one line of JSON with every field written out, in a
    /// fixed order (`max_requests`, last, only when there is a limit).
    pub fn to_stored(&self) -> String {
        serde_json::to_string(self).expect("a profile always serializes")
    }

    /// Check every rule of the format: the version, a known preset and
    /// revision, the origin, the base path, the lifetime, the request limit,
    /// and that the stored form is at most [`MAX_PROFILE_CHARS`] characters.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.version != PROFILE_VERSION {
            return Err(ProfileError::Version(u64::from(self.version)));
        }
        if spec_for(self.preset, self.revision).is_none() {
            return Err(ProfileError::Revision {
                preset: self.preset,
                revision: self.revision,
            });
        }
        check_origin(&self.origin)?;
        check_base_path(&self.base_path)?;
        if !MAX_LIFETIME_MINUTES_RANGE.contains(&self.max_lifetime_minutes) {
            return Err(ProfileError::Lifetime(self.max_lifetime_minutes));
        }
        if let Some(limit) = self.max_requests
            && !MAX_REQUESTS_RANGE.contains(&limit)
        {
            return Err(ProfileError::Requests(limit));
        }
        let chars = self.to_stored().chars().count();
        if chars > MAX_PROFILE_CHARS {
            return Err(ProfileError::TooLong(chars));
        }
        Ok(())
    }

    /// The revision of the preset the profile names.
    ///
    /// # Panics
    ///
    /// When this build does not know that revision, which a profile from
    /// [`BrokerProfile::parse`] or [`ProfileRequest::resolve`], or one that
    /// passed [`BrokerProfile::validate`], never names.
    pub fn spec(&self) -> &'static PresetSpec {
        spec_for(self.preset, self.revision).expect("a validated profile names a known revision")
    }

    /// The origin without its scheme: the host, and the port if the origin
    /// names one. It is the `Host` header the broker sends.
    pub fn authority(&self) -> &str {
        self.origin.strip_prefix("https://").unwrap_or(&self.origin)
    }

    /// The origin's host name.
    pub fn host(&self) -> &str {
        let authority = self.authority();
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
    }

    /// The origin's port: the one it names, or 443. (Only a valid profile's
    /// port means anything: one that does not parse also gives 443.)
    pub fn port(&self) -> u16 {
        self.authority()
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or(443)
    }

    /// The destination: the origin and the base path
    /// (`https://api.openai.com/v1`).
    pub fn destination(&self) -> String {
        format!("{}{}", self.origin, self.base_path)
    }

    /// The base URL a command gets for a broker listening on `port`:
    /// `http://127.0.0.1:PORT` and the base path — never `localhost`, which
    /// can resolve to an IPv6 address another program listens on.
    pub fn local_url(&self, port: u16) -> String {
        format!("http://127.0.0.1:{port}{}", self.base_path)
    }

    /// The profile as approval dialogs show it, as label and value pairs:
    /// `Destination`, `Allows` (every route), `Ends` (how and when a grant
    /// ends) and `Requests` (the limits).
    pub fn describe(&self) -> Vec<(String, String)> {
        let allows = match spec_for(self.preset, self.revision) {
            Some(spec) => spec
                .routes
                .iter()
                .map(Route::template)
                .collect::<Vec<_>>()
                .join(", "),
            None => format!(
                "nothing: revision {} of the {} preset is unknown to this Rusthorse",
                self.revision, self.preset
            ),
        };
        let lifetime = util::format_duration(Duration::from_secs(
            u64::from(self.max_lifetime_minutes) * 60,
        ));
        let automatic =
            "the screen locks, the computer suspends or the vault locks after idle time";
        let ends = format!(
            "when the command ends, on rusthorse lock, when revoked or the entry changes, or \
             after {lifetime}; {}",
            match self.automatic_locks {
                AutomaticLocks::Continue => format!("not when {automatic}"),
                AutomaticLocks::End => format!("also when {automatic}"),
            }
        );
        let requests = match self.max_requests {
            Some(limit) => format!("at most {limit}; at most {MAX_IN_FLIGHT} at a time"),
            None => format!("no limit; at most {MAX_IN_FLIGHT} at a time"),
        };
        vec![
            ("Destination".into(), self.destination()),
            ("Allows".into(), allows),
            ("Ends".into(), ends),
            ("Requests".into(), requests),
        ]
    }
}

/// `origin`: `https://` and a lowercase host name (not an IP address in any
/// form a resolver accepts), with an optional port.
fn check_origin(origin: &str) -> Result<(), ProfileError> {
    let Some(rest) = origin.strip_prefix("https://") else {
        return Err(ProfileError::Origin("it must start with https://"));
    };
    if rest.contains('@') {
        return Err(ProfileError::Origin("it must not contain user information"));
    }
    if rest.contains('/') {
        return Err(ProfileError::Origin(
            "it must not contain a path (not even a trailing /); a path goes in the base path",
        ));
    }
    if rest.contains(['?', '#']) {
        return Err(ProfileError::Origin(
            "it must not contain a query or a fragment",
        ));
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    check_host(host)?;
    if let Some(port) = port {
        let valid = !port.is_empty()
            && port.len() <= 5
            && port.bytes().all(|b| b.is_ascii_digit())
            && !port.starts_with('0')
            && port.parse::<u16>().is_ok();
        if !valid {
            return Err(ProfileError::Origin(
                "the port must be a number from 1 to 65535",
            ));
        }
    }
    Ok(())
}

fn check_host(host: &str) -> Result<(), ProfileError> {
    if host.is_empty() {
        return Err(ProfileError::Origin("it must name a host"));
    }
    if host.starts_with('[') {
        return Err(ProfileError::Origin(
            "it must name a host, not an IP address",
        ));
    }
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(ProfileError::Origin("the host name must be in lowercase"));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(ProfileError::Origin(
            "the host name may only contain letters, digits, - and . (an international name in \
             its xn-- form)",
        ));
    }
    if host.len() > MAX_HOST_CHARS {
        return Err(ProfileError::Origin("the host name is too long"));
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(ProfileError::Origin(
                "the host name must not have an empty label (two dots, or a dot at an end)",
            ));
        }
        if label.len() > MAX_LABEL_CHARS {
            return Err(ProfileError::Origin(
                "a label of the host name is longer than 63 characters",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ProfileError::Origin(
                "a label of the host name must not start or end with -",
            ));
        }
    }
    // Top-level domains start with a letter. A last label that starts with
    // a digit is an IP address in some form a resolver accepts (`1.2.3.4`,
    // `2130706433`, `0x7f.1`).
    let last = host.rsplit('.').next().unwrap_or(host);
    if !last.starts_with(|c: char| c.is_ascii_lowercase()) {
        return Err(ProfileError::Origin(
            "it must name a host, not an IP address",
        ));
    }
    Ok(())
}

/// `base_path`: empty, or `/` and non-empty segments of letters, digits,
/// `.`, `_`, `~` and `-`, none made only of dots.
fn check_base_path(path: &str) -> Result<(), ProfileError> {
    if path.is_empty() {
        return Ok(());
    }
    let Some(rest) = path.strip_prefix('/') else {
        return Err(ProfileError::BasePath("it must be empty or start with /"));
    };
    for segment in rest.split('/') {
        if segment.is_empty() {
            return Err(ProfileError::BasePath(
                "it must not end with / or contain //",
            ));
        }
        if segment.bytes().all(|b| b == b'.') {
            return Err(ProfileError::BasePath(
                "it must not contain . or .. segments",
            ));
        }
        if !segment.bytes().all(is_unreserved) {
            return Err(ProfileError::BasePath(
                "it may only contain letters, digits, ., _, ~, - and /",
            ));
        }
    }
    Ok(())
}

/// Letters, digits, `.`, `_`, `~` and `-`: the characters of a base path's
/// segments and of query values.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-')
}

/// What a client sends to set an entry's profile (`edit.broker`): a preset,
/// and whatever should differ from the defaults of its latest revision.
/// Unknown fields are refused: an edit that sets a profile must be
/// understood whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRequest {
    /// The preset.
    pub preset: Preset,
    /// The origin; required for presets without a default one
    /// ([`Preset::OpenaiCompatible`]). Its scheme and host are lowercased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The base path; `Some("")` for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_path: Option<String>,
    /// Whether the automatic locks end the grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automatic_locks: Option<AutomaticLocks>,
    /// The maximum lifetime of a grant, in minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lifetime_minutes: Option<u32>,
    /// The request limit of a grant; `None` for no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u64>,
}

impl ProfileRequest {
    /// A request for `preset` with every default.
    pub fn new(preset: Preset) -> Self {
        Self {
            preset,
            origin: None,
            base_path: None,
            automatic_locks: None,
            max_lifetime_minutes: None,
            max_requests: None,
        }
    }

    /// The profile this request makes: the latest revision of its preset,
    /// with that revision's defaults for whatever the request leaves out,
    /// validated. Deterministic, so that the profile an approval dialog
    /// shows is the one stored.
    pub fn resolve(&self) -> Result<BrokerProfile, ProfileError> {
        let spec = latest(self.preset);
        let origin = match (&self.origin, spec.default_origin) {
            (Some(origin), _) => origin.to_ascii_lowercase(),
            (None, Some(default)) => default.to_string(),
            (None, None) => return Err(ProfileError::OriginRequired(self.preset)),
        };
        let profile = BrokerProfile {
            version: PROFILE_VERSION,
            preset: self.preset,
            revision: spec.revision,
            origin,
            base_path: self
                .base_path
                .clone()
                .unwrap_or_else(|| spec.default_base_path.to_string()),
            automatic_locks: self.automatic_locks.unwrap_or(spec.default_automatic_locks),
            max_lifetime_minutes: self
                .max_lifetime_minutes
                .unwrap_or(spec.default_max_lifetime_minutes),
            max_requests: self.max_requests,
        };
        profile.validate()?;
        Ok(profile)
    }
}

/// How a token or a credential travels in a request's headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthHeader {
    /// `x-api-key: VALUE`.
    XApiKey,
    /// `Authorization: Bearer VALUE`.
    Bearer,
}

impl AuthHeader {
    /// The header's name, in lowercase: `x-api-key` or `authorization`.
    pub fn name(self) -> &'static str {
        match self {
            Self::XApiKey => "x-api-key",
            Self::Bearer => "authorization",
        }
    }

    /// The header's value for `secret`: the secret itself, or `Bearer `
    /// and the secret, in a buffer that is wiped on drop.
    pub fn value(self, secret: &str) -> SecretString {
        let prefix = match self {
            Self::XApiKey => "",
            Self::Bearer => "Bearer ",
        };
        let mut value = SecretString::new(String::with_capacity(prefix.len() + secret.len()));
        value.push_str(prefix);
        value.push_str(secret);
        value
    }
}

/// One route of a preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The method, as HTTP writes it (`POST`); methods are case-sensitive.
    pub method: &'static str,
    /// The path after the base path, exactly; `{id}` stands for one segment
    /// of 1 to 128 letters, digits, `.`, `_`, `:`, `~` and `-`.
    pub path: &'static str,
    /// The query parameters it allows (`beta` only with the value `true`).
    pub query: &'static [&'static str],
}

impl Route {
    /// How audit records and dialogs write it: the method, a space and the
    /// path (`POST /v1/messages`, `GET /v1/models/{id}`).
    pub fn template(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

/// Which headers pass: those named, and those that start with one of the
/// prefixes, compared ignoring ASCII case. All others are dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderRule {
    /// Whole names, in lowercase.
    pub names: &'static [&'static str],
    /// Prefixes, in lowercase.
    pub prefixes: &'static [&'static str],
}

impl HeaderRule {
    /// Whether the header `name` passes.
    pub fn allows(&self, name: &str) -> bool {
        self.names.iter().any(|n| n.eq_ignore_ascii_case(name))
            || self.prefixes.iter().any(|prefix| {
                name.as_bytes()
                    .get(..prefix.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(prefix.as_bytes()))
            })
    }
}

/// A revision of a preset, as ADR 0013 lists it. Revisions are never
/// changed once released: a change is a new revision.
#[derive(Debug, PartialEq, Eq)]
pub struct PresetSpec {
    /// The preset.
    pub preset: Preset,
    /// This revision's number.
    pub revision: u32,
    /// The origin a profile gets when it names none; `None` when it must.
    pub default_origin: Option<&'static str>,
    /// The base path a profile gets when it names none.
    pub default_base_path: &'static str,
    /// The policy for the automatic locks a profile gets by default.
    pub default_automatic_locks: AutomaticLocks,
    /// The maximum lifetime a profile gets by default, in minutes.
    pub default_max_lifetime_minutes: u32,
    /// The headers in which a client may present the token
    /// ([`check_inbound_token`]).
    pub token_headers: &'static [AuthHeader],
    /// The header in which the broker presents the credential to the
    /// destination.
    pub credential_header: AuthHeader,
    /// The routes, relative to the base path.
    pub routes: &'static [Route],
    /// The request headers forwarded to the destination.
    pub request_headers: HeaderRule,
    /// The response headers relayed to the client.
    pub response_headers: HeaderRule,
}

impl PresetSpec {
    /// The route written as `template` ([`Route::template`]), if this
    /// revision has it.
    pub fn route(&self, template: &str) -> Option<&'static Route> {
        self.routes.iter().find(|r| r.template() == template)
    }
}

/// The response headers every phase 1 preset relays.
const RESPONSE_HEADERS: HeaderRule = HeaderRule {
    names: &[
        "content-type",
        "date",
        "cache-control",
        "retry-after",
        "x-should-retry",
        "request-id",
        "x-request-id",
        "openai-processing-ms",
        "openai-version",
    ],
    prefixes: &["anthropic-ratelimit-", "x-ratelimit-"],
};

/// The request headers the OpenAI presets forward. `OpenAI-Organization`
/// and `OpenAI-Project` are not among them: the key decides the account.
const OPENAI_REQUEST_HEADERS: HeaderRule = HeaderRule {
    names: &["content-type", "accept", "user-agent", "openai-beta"],
    prefixes: &["x-stainless-"],
};

/// Every revision of every preset.
static PRESETS: [PresetSpec; 3] = [
    PresetSpec {
        preset: Preset::Anthropic,
        revision: 1,
        default_origin: Some("https://api.anthropic.com"),
        default_base_path: "",
        default_automatic_locks: AutomaticLocks::Continue,
        default_max_lifetime_minutes: 720,
        token_headers: &[AuthHeader::XApiKey, AuthHeader::Bearer],
        credential_header: AuthHeader::XApiKey,
        routes: &[
            Route {
                method: "POST",
                path: "/v1/messages",
                query: &["beta"],
            },
            Route {
                method: "POST",
                path: "/v1/messages/count_tokens",
                query: &["beta"],
            },
            Route {
                method: "GET",
                path: "/v1/models",
                query: &["beta", "limit", "before_id", "after_id"],
            },
            Route {
                method: "GET",
                path: "/v1/models/{id}",
                query: &["beta"],
            },
        ],
        request_headers: HeaderRule {
            names: &["content-type", "accept", "user-agent"],
            prefixes: &["anthropic-", "x-stainless-", "x-claude-code-"],
        },
        response_headers: RESPONSE_HEADERS,
    },
    PresetSpec {
        preset: Preset::Openai,
        revision: 1,
        default_origin: Some("https://api.openai.com"),
        default_base_path: "/v1",
        default_automatic_locks: AutomaticLocks::Continue,
        default_max_lifetime_minutes: 720,
        token_headers: &[AuthHeader::Bearer],
        credential_header: AuthHeader::Bearer,
        routes: &[
            Route {
                method: "POST",
                path: "/chat/completions",
                query: &[],
            },
            Route {
                method: "POST",
                path: "/responses",
                query: &[],
            },
            Route {
                method: "POST",
                path: "/responses/input_tokens",
                query: &[],
            },
            Route {
                method: "POST",
                path: "/embeddings",
                query: &[],
            },
            Route {
                method: "GET",
                path: "/models",
                query: &[],
            },
            Route {
                method: "GET",
                path: "/models/{id}",
                query: &[],
            },
        ],
        request_headers: OPENAI_REQUEST_HEADERS,
        response_headers: RESPONSE_HEADERS,
    },
    PresetSpec {
        preset: Preset::OpenaiCompatible,
        revision: 1,
        default_origin: None,
        default_base_path: "/v1",
        default_automatic_locks: AutomaticLocks::Continue,
        default_max_lifetime_minutes: 720,
        token_headers: &[AuthHeader::Bearer],
        credential_header: AuthHeader::Bearer,
        routes: &[
            Route {
                method: "POST",
                path: "/chat/completions",
                query: &[],
            },
            Route {
                method: "POST",
                path: "/embeddings",
                query: &[],
            },
            Route {
                method: "GET",
                path: "/models",
                query: &[],
            },
            Route {
                method: "GET",
                path: "/models/{id}",
                query: &[],
            },
        ],
        request_headers: OPENAI_REQUEST_HEADERS,
        response_headers: RESPONSE_HEADERS,
    },
];

/// Revision `revision` of `preset`, if this build knows it.
pub fn spec_for(preset: Preset, revision: u32) -> Option<&'static PresetSpec> {
    PRESETS
        .iter()
        .find(|spec| spec.preset == preset && spec.revision == revision)
}

/// The latest revision of `preset`: the one new profiles get.
pub fn latest(preset: Preset) -> &'static PresetSpec {
    PRESETS
        .iter()
        .filter(|spec| spec.preset == preset)
        .max_by_key(|spec| spec.revision)
        .expect("every preset has a revision")
}

/// Why [`match_route`] refused a request target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRefusal {
    /// Not a request target in origin form ([`is_origin_form`]): a local
    /// `400`, like the other framing errors (ADR 0013, step 1).
    Malformed,
    /// In origin form, but not exactly a route of the preset after the base
    /// path: an escape, `\`, `;` or `#`, an empty or dot segment, a
    /// malformed query or a parameter given twice, another path or method,
    /// or a query the route does not allow. A local `404` (step 3).
    NotAllowed,
}

impl RouteRefusal {
    /// The status of the local answer: `400` or `404`.
    pub fn status(self) -> u16 {
        match self {
            Self::Malformed => 400,
            Self::NotAllowed => 404,
        }
    }
}

/// A request target that [`match_route`] accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRoute {
    /// The route it matched, as [`Route::template`] writes it, relative to
    /// the base path (`POST /v1/messages`, `GET /v1/models/{id}`): what
    /// audit records say, never the raw path.
    pub template: String,
    /// The target exactly as it was checked, byte for byte: what the broker
    /// sends to the destination.
    pub path_and_query: String,
}

/// Whether `target` is a request target in origin form: it starts with `/`
/// (it is not `https://…`, `host:port` or `*`), and every byte is visible
/// ASCII (`0x21`–`0x7e`), as in any request target; the HTTP library
/// refuses most other bytes before this. The broker answers any other
/// target `400` while it checks the framing, before the token (ADR 0013,
/// step 1); [`match_route`] refuses it too.
pub fn is_origin_form(target: &str) -> bool {
    target.starts_with('/') && target.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Match a request against a preset's routes.
///
/// `target` is the raw request target, path and optional query, exactly as
/// it arrived; `method` the method, compared exactly (`post` is not
/// `POST`). A target that is not in origin form ([`is_origin_form`]) is
/// [`RouteRefusal::Malformed`]. Any other is [`RouteRefusal::NotAllowed`]
/// unless it is in the exact form routes are written in — no `%` (no
/// escapes at all), `\`, `;` or `#`, no empty segment (`//`, a trailing
/// `/`), no segment made only of dots (`.`, `..`), and a query, if any, of
/// non-empty `name=value` pairs joined by `&`, no name twice — its path is
/// the base path, as whole segments, followed by a route of the preset for
/// that method, and every query parameter is one the route allows, `beta`
/// with the value `true` and the others with 1 to 128 letters, digits, `.`,
/// `_`, `~` and `-`.
///
/// The path the broker checks is the path it sends:
/// [`MatchedRoute::path_and_query`] is `target` itself.
pub fn match_route(
    spec: &PresetSpec,
    base_path: &str,
    method: &str,
    target: &str,
) -> Result<MatchedRoute, RouteRefusal> {
    let (path, query) = split_target(target)?;
    let pairs = parse_query(query)?;
    let relative = strip_base_path(path, base_path).ok_or(RouteRefusal::NotAllowed)?;
    let route = spec
        .routes
        .iter()
        .find(|route| route.method == method && path_matches(route.path, relative))
        .ok_or(RouteRefusal::NotAllowed)?;
    for (name, value) in pairs {
        if !route.query.contains(&name) {
            return Err(RouteRefusal::NotAllowed);
        }
        let allowed = if name == "beta" {
            value == "true"
        } else {
            is_query_value(value)
        };
        if !allowed {
            return Err(RouteRefusal::NotAllowed);
        }
    }
    Ok(MatchedRoute {
        template: route.template(),
        path_and_query: target.to_string(),
    })
}

/// The path and query of a target in origin form, if it is in the exact
/// form routes are written in.
fn split_target(target: &str) -> Result<(&str, Option<&str>), RouteRefusal> {
    if !is_origin_form(target) {
        return Err(RouteRefusal::Malformed);
    }
    // No escapes at all, and nothing that servers may read differently.
    if target
        .bytes()
        .any(|b| matches!(b, b'%' | b'\\' | b';' | b'#'))
    {
        return Err(RouteRefusal::NotAllowed);
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    for segment in path[1..].split('/') {
        if segment.is_empty() || segment.bytes().all(|b| b == b'.') {
            return Err(RouteRefusal::NotAllowed);
        }
    }
    Ok((path, query))
}

/// The `name=value` pairs of a query; an empty query, an empty pair, a pair
/// without `=` or with an empty name, and a name given twice are refused.
fn parse_query(query: Option<&str>) -> Result<Vec<(&str, &str)>, RouteRefusal> {
    let Some(query) = query else {
        return Ok(Vec::new());
    };
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').ok_or(RouteRefusal::NotAllowed)?;
        if name.is_empty() || pairs.iter().any(|(seen, _)| *seen == name) {
            return Err(RouteRefusal::NotAllowed);
        }
        pairs.push((name, value));
    }
    Ok(pairs)
}

/// `path` without the base path, which must match as whole segments.
fn strip_base_path<'a>(path: &'a str, base_path: &str) -> Option<&'a str> {
    if base_path.is_empty() {
        return Some(path);
    }
    let rest = path.strip_prefix(base_path)?;
    rest.starts_with('/').then_some(rest)
}

/// Whether `path` is the route path `template`, `{id}` matching one segment.
fn path_matches(template: &str, path: &str) -> bool {
    let mut expected = template.split('/');
    let mut actual = path.split('/');
    loop {
        match (expected.next(), actual.next()) {
            (None, None) => return true,
            (Some("{id}"), Some(segment)) if is_id(segment) => {}
            (Some(want), Some(segment)) if want != "{id}" && want == segment => {}
            _ => return false,
        }
    }
}

/// An `{id}` segment: 1 to 128 letters, digits, `.`, `_`, `:`, `~` and `-`.
fn is_id(segment: &str) -> bool {
    (1..=MAX_ID_CHARS).contains(&segment.len())
        && segment.bytes().all(|b| is_unreserved(b) || b == b':')
}

/// A query value other than `beta`'s: 1 to 128 letters, digits, `.`, `_`,
/// `~` and `-`.
fn is_query_value(value: &str) -> bool {
    (1..=MAX_ID_CHARS).contains(&value.len()) && value.bytes().all(is_unreserved)
}

/// Whether the broker forwards the request header `name` to the destination
/// (ASCII case-insensitive). Every other header is dropped, the client's
/// token headers and hop-by-hop headers among them; the broker writes the
/// request line, `Host`, `Content-Length`, `Accept-Encoding` and the
/// credential header itself.
pub fn forwards_request_header(spec: &PresetSpec, name: &str) -> bool {
    spec.request_headers.allows(name)
}

/// Whether the broker relays the response header `name` to the client
/// (ASCII case-insensitive). Every other header is dropped.
pub fn relays_response_header(spec: &PresetSpec, name: &str) -> bool {
    spec.response_headers.allows(name)
}

/// Why [`check_inbound_token`] refused a request: a local `401` either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRefusal {
    /// No header of the preset presents a token.
    Missing,
    /// A token header is not of the exact form: another scheme, other
    /// spacing, or a value that is not a token ([`is_well_formed_token`]).
    Malformed,
    /// A token of the right form, but not this grant's.
    Wrong,
}

/// Check the token a request presents.
///
/// Every header of the request whose name (ignoring ASCII case) is one of
/// the preset's token headers ([`PresetSpec::token_headers`]) must present
/// exactly `token`, and at least one must be there: when a client sends
/// both of the Anthropic preset's headers, or one twice, every one counts.
/// `x-api-key` carries the token alone; `Authorization` carries `Bearer`
/// (in any case), exactly one space, and the token. A presented value that
/// is not of the token's form is refused before any comparison; the
/// comparison takes the same time wherever the first difference is
/// ([`tokens_equal`]). Headers that are not token headers of the preset —
/// `x-api-key` for the OpenAI presets — are ignored here; the header rule
/// drops them.
pub fn check_inbound_token<'a>(
    spec: &PresetSpec,
    headers: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    token: &str,
) -> Result<(), TokenRefusal> {
    let mut presented = false;
    let mut refusal = None;
    for (name, value) in headers {
        let Some(kind) = spec
            .token_headers
            .iter()
            .find(|header| header.name().eq_ignore_ascii_case(name))
        else {
            continue;
        };
        presented = true;
        let candidate = match kind {
            AuthHeader::XApiKey => Some(value),
            AuthHeader::Bearer => bearer_credentials(value),
        };
        let verdict = match candidate {
            Some(candidate) if std::str::from_utf8(candidate).is_ok_and(is_well_formed_token) => {
                if tokens_equal(candidate, token.as_bytes()) {
                    None
                } else {
                    Some(TokenRefusal::Wrong)
                }
            }
            _ => Some(TokenRefusal::Malformed),
        };
        refusal = refusal.or(verdict);
    }
    match (presented, refusal) {
        (false, _) => Err(TokenRefusal::Missing),
        (true, Some(refusal)) => Err(refusal),
        (true, None) => Ok(()),
    }
}

/// What follows `Bearer` and exactly one space in an `Authorization` value.
fn bearer_credentials(value: &[u8]) -> Option<&[u8]> {
    const SCHEME: &[u8] = b"bearer ";
    let (scheme, rest) = value.split_at_checked(SCHEME.len())?;
    scheme.eq_ignore_ascii_case(SCHEME).then_some(rest)
}

/// Whether `a` and `b` are the same bytes, in a time that depends on their
/// lengths only: every byte is compared, whatever the first difference.
pub fn tokens_equal(a: &[u8], b: &[u8]) -> bool {
    let mut difference = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        difference |= usize::from(x ^ y);
    }
    std::hint::black_box(difference) == 0
}

/// Whether an entry's value can be used with the broker (ADR 0013):
/// [`MIN_CREDENTIAL_CHARS`] to [`MAX_CREDENTIAL_CHARS`] characters, all
/// visible ASCII (`!` to `~`): no spaces, line breaks or other control
/// characters, which could end or split the header it travels in. The
/// agent checks it before the approval dialog; a broker checks it again
/// ([`Install::validate`](crate::broker_protocol::Install::validate)).
pub fn is_valid_credential(value: &str) -> bool {
    // Visible ASCII only, so its length in bytes is its length in
    // characters.
    (MIN_CREDENTIAL_CHARS..=MAX_CREDENTIAL_CHARS).contains(&value.len())
        && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The profile ADR 0013 shows, as stored.
    const EXAMPLE: &str = r#"{"version":1,"preset":"anthropic","revision":1,"origin":"https://api.anthropic.com","base_path":"","automatic_locks":"continue","max_lifetime_minutes":720}"#;

    fn anthropic() -> BrokerProfile {
        BrokerProfile::parse(EXAMPLE).expect("the ADR's example")
    }

    fn token(fill: char) -> String {
        format!("rh_{}", fill.to_string().repeat(64))
    }

    #[test]
    fn the_example_of_the_adr_round_trips_byte_for_byte() {
        let profile = anthropic();
        assert_eq!(profile.preset, Preset::Anthropic);
        assert_eq!(profile.revision, 1);
        assert_eq!(profile.max_requests, None);
        assert_eq!(profile.to_stored(), EXAMPLE);
        assert_eq!(
            ProfileRequest::new(Preset::Anthropic).resolve(),
            Ok(profile)
        );
    }

    #[test]
    fn stored_profiles_are_canonical_and_round_trip() {
        let requests = [
            ProfileRequest::new(Preset::Anthropic),
            ProfileRequest::new(Preset::Openai),
            ProfileRequest {
                origin: Some("https://api.deepseek.com".into()),
                ..ProfileRequest::new(Preset::OpenaiCompatible)
            },
            ProfileRequest {
                origin: Some("https://gateway.example.com:8443".into()),
                base_path: Some("/anthropic/a.b_c~d-e".into()),
                automatic_locks: Some(AutomaticLocks::End),
                max_lifetime_minutes: Some(15),
                max_requests: Some(200),
                ..ProfileRequest::new(Preset::Anthropic)
            },
        ];
        for request in requests {
            let profile = request.resolve().expect("resolve");
            let stored = profile.to_stored();
            assert!(!stored.contains(['\n', ' ']), "{stored}");
            assert_eq!(
                BrokerProfile::parse(&stored),
                Ok(profile.clone()),
                "{stored}"
            );
            assert_eq!(
                BrokerProfile::parse(&stored).expect("parse").to_stored(),
                stored
            );
        }
        // A limit is written last; none is left out, never `null`.
        let limited = ProfileRequest {
            max_requests: Some(200),
            ..ProfileRequest::new(Preset::Anthropic)
        }
        .resolve()
        .expect("resolve");
        assert!(
            limited
                .to_stored()
                .ends_with(r#""max_lifetime_minutes":720,"max_requests":200}"#),
            "{}",
            limited.to_stored()
        );
        assert!(!anthropic().to_stored().contains("max_requests"));
    }

    #[test]
    fn a_valid_profile_written_differently_is_read_and_stored_canonically() {
        let spaced = r#" { "max_lifetime_minutes": 720, "automatic_locks": "continue", "base_path": "", "origin": "https://api.anthropic.com", "revision": 1, "preset": "anthropic", "version": 1 } "#;
        let profile = BrokerProfile::parse(spaced).expect("spaces and order are not errors");
        assert_eq!(profile, anthropic());
        assert_eq!(profile.to_stored(), EXAMPLE);
    }

    fn replaced(from: &str, to: &str) -> String {
        assert!(EXAMPLE.contains(from), "{from}");
        EXAMPLE.replacen(from, to, 1)
    }

    #[test]
    fn every_invalid_profile_is_unusable() {
        let long_path = format!("/{}", "a".repeat(MAX_PROFILE_CHARS));
        let cases: Vec<(String, &str)> = vec![
            (String::new(), "empty"),
            ("not json".into(), "not JSON"),
            ("null".into(), "null"),
            ("[]".into(), "an array"),
            ("{}".into(), "no fields"),
            (format!("{EXAMPLE}\n"), "a line break"),
            (EXAMPLE.replace(',', ",\n"), "several lines"),
            (EXAMPLE.replace(',', ",\r"), "a carriage return"),
            (
                replaced(
                    r#""base_path":"""#,
                    &format!(r#""base_path":"{long_path}""#),
                ),
                "too long",
            ),
            (replaced(r#""version":1"#, r#""version":2"#), "version 2"),
            (replaced(r#""version":1"#, r#""version":0"#), "version 0"),
            (
                replaced(r#""version":1"#, r#""version":"1""#),
                "version as text",
            ),
            (
                replaced(r#""version":1"#, r#""version":1.0"#),
                "version as a float",
            ),
            (
                replaced(r#""preset":"anthropic""#, r#""preset":"gemini""#),
                "unknown preset",
            ),
            (
                replaced(r#""preset":"anthropic""#, r#""preset":"Anthropic""#),
                "preset in capitals",
            ),
            (
                replaced(r#""revision":1"#, r#""revision":2"#),
                "unknown revision",
            ),
            (replaced(r#""revision":1"#, r#""revision":0"#), "revision 0"),
            (replaced("720}", r#"720,"extra":true}"#), "unknown field"),
            (replaced("720}", r#"720,"version":1}"#), "a field twice"),
            (replaced(r#""base_path":"","#, ""), "a missing field"),
            (
                replaced("720}", r#"720,"max_requests":null}"#),
                "an explicit null",
            ),
            (replaced("720}", r#"720,"max_requests":0}"#), "no requests"),
            (
                replaced("720}", r#"720,"max_requests":1000001}"#),
                "too many requests",
            ),
            (
                replaced("720}", r#"720,"max_requests":-1}"#),
                "negative requests",
            ),
            (replaced(":720", ":0"), "no lifetime"),
            (replaced(":720", ":1441"), "more than a day"),
            (replaced(":720", ":720.0"), "lifetime as a float"),
            (
                replaced(r#""continue""#, r#""Continue""#),
                "policy in capitals",
            ),
            (replaced(r#""continue""#, r#""always""#), "unknown policy"),
            (
                replaced(r#""base_path":"""#, r#""base_path":"v1""#),
                "base path without /",
            ),
        ];
        for (stored, why) in cases {
            assert!(BrokerProfile::parse(&stored).is_err(), "{why}: {stored}");
        }
        // The version is named when it is the problem, even with other
        // fields of that version.
        let future = r#"{"version":2,"preset":"anthropic","routes":["POST /x"]}"#;
        assert_eq!(BrokerProfile::parse(future), Err(ProfileError::Version(2)));
        let long = replaced(
            r#""base_path":"""#,
            &format!(r#""base_path":"{long_path}""#),
        );
        assert!(matches!(
            BrokerProfile::parse(&long),
            Err(ProfileError::TooLong(_))
        ));
        assert_eq!(
            BrokerProfile::parse(&replaced(r#""revision":1"#, r#""revision":2"#)),
            Err(ProfileError::Revision {
                preset: Preset::Anthropic,
                revision: 2
            })
        );
    }

    #[test]
    fn errors_do_not_repeat_what_they_refuse_raw() {
        let hostile = replaced("720}", "720,\"\\u001b[31mevil\":1}");
        let err = BrokerProfile::parse(&hostile).expect_err("unknown field");
        let text = err.to_string();
        assert!(!text.contains('\u{1b}'), "{text:?}");
        let flood = replaced("720}", &format!(r#"720,"{}":1}}"#, "x".repeat(700)));
        let err = BrokerProfile::parse(&flood).expect_err("unknown field");
        assert!(matches!(err, ProfileError::Json(_)), "{err:?}");
        let text = err.to_string();
        assert!(text.chars().count() < 300, "{text}");
    }

    fn with_origin(origin: &str) -> BrokerProfile {
        BrokerProfile {
            origin: origin.into(),
            ..anthropic()
        }
    }

    #[test]
    fn origins_are_https_and_a_host_name() {
        for valid in [
            "https://api.anthropic.com",
            "https://api.deepseek.com",
            "https://gateway.example.com:8443",
            "https://example.com:1",
            "https://example.com:65535",
            "https://example.com:443",
            "https://xn--bcher-kva.example",
            "https://a-b.c-d.example",
            "https://localhost",
            "https://a1.b2.example",
        ] {
            assert_eq!(with_origin(valid).validate(), Ok(()), "{valid}");
        }
        let long_label = format!("https://{}.example.com", "a".repeat(64));
        let long_host = format!("https://{}.example", vec!["a".repeat(60); 5].join("."));
        for invalid in [
            "http://api.anthropic.com",
            "api.anthropic.com",
            "HTTPS://api.anthropic.com",
            "https://API.anthropic.com",
            "https://",
            "https://:443",
            "https://api.anthropic.com/",
            "https://api.anthropic.com/v1",
            "https://api.anthropic.com?x=1",
            "https://api.anthropic.com#x",
            "https://user@api.anthropic.com",
            "https://user:pass@api.anthropic.com",
            "https://127.0.0.1",
            "https://1.2.3.4:443",
            "https://2130706433",
            "https://0x7f000001",
            "https://0x7f.0.0.1",
            "https://api.example.123",
            "https://[::1]",
            "https://[::1]:443",
            "https://example.com:0",
            "https://example.com:65536",
            "https://example.com:0443",
            "https://example.com:",
            "https://example.com:abc",
            "https://example.com:1:2",
            "https://-api.example.com",
            "https://api-.example.com",
            "https://api..example.com",
            "https://api.example.com.",
            "https://.example.com",
            "https://api_x.example.com",
            "https://bücher.example",
            "https://api.example .com",
            "https://api.example.com\\x",
            "https://api.example.com%2f",
            " https://api.example.com",
            long_label.as_str(),
            long_host.as_str(),
        ] {
            assert!(
                matches!(
                    with_origin(invalid).validate(),
                    Err(ProfileError::Origin(_))
                ),
                "{invalid:?}: {:?}",
                with_origin(invalid).validate()
            );
        }
    }

    #[test]
    fn base_paths_are_empty_or_whole_segments() {
        let with = |path: &str| BrokerProfile {
            base_path: path.into(),
            ..anthropic()
        };
        for valid in ["", "/v1", "/api/v1", "/a.b_c~d-e", "/V1", "/v1/x.y"] {
            assert_eq!(with(valid).validate(), Ok(()), "{valid:?}");
        }
        for invalid in [
            "v1", "/", "/v1/", "//v1", "/v1//x", "/.", "/..", "/./v1", "/../v1", "/v1/..", "/...",
            "/v 1", "/v1?x=1", "/v1#x", "/v%31", "/v1;x", "/v1\\x", "/ü", "/v1:x", "/v1@x",
        ] {
            assert!(
                matches!(with(invalid).validate(), Err(ProfileError::BasePath(_))),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn lifetimes_and_request_limits_have_bounds() {
        let with = |minutes: u32, requests: Option<u64>| BrokerProfile {
            max_lifetime_minutes: minutes,
            max_requests: requests,
            ..anthropic()
        };
        assert_eq!(with(1, Some(1)).validate(), Ok(()));
        assert_eq!(with(1440, Some(1_000_000)).validate(), Ok(()));
        assert_eq!(with(0, None).validate(), Err(ProfileError::Lifetime(0)));
        assert_eq!(
            with(1441, None).validate(),
            Err(ProfileError::Lifetime(1441))
        );
        assert_eq!(with(60, Some(0)).validate(), Err(ProfileError::Requests(0)));
        assert_eq!(
            with(60, Some(1_000_001)).validate(),
            Err(ProfileError::Requests(1_000_001))
        );
        let version = BrokerProfile {
            version: 2,
            ..anthropic()
        };
        assert_eq!(version.validate(), Err(ProfileError::Version(2)));
    }

    #[test]
    fn requests_take_the_defaults_of_the_latest_revision() {
        let openai = ProfileRequest::new(Preset::Openai)
            .resolve()
            .expect("openai");
        assert_eq!(openai.origin, "https://api.openai.com");
        assert_eq!(openai.base_path, "/v1");
        assert_eq!(openai.automatic_locks, AutomaticLocks::Continue);
        assert_eq!(openai.max_lifetime_minutes, 720);
        assert_eq!(openai.max_requests, None);
        assert_eq!(openai.revision, latest(Preset::Openai).revision);
        assert_eq!(openai.destination(), "https://api.openai.com/v1");

        // The compatible preset has no origin of its own.
        assert_eq!(
            ProfileRequest::new(Preset::OpenaiCompatible).resolve(),
            Err(ProfileError::OriginRequired(Preset::OpenaiCompatible))
        );
        let deepseek = ProfileRequest {
            origin: Some("HTTPS://API.DeepSeek.com".into()),
            ..ProfileRequest::new(Preset::OpenaiCompatible)
        }
        .resolve()
        .expect("deepseek");
        assert_eq!(deepseek.origin, "https://api.deepseek.com", "lowercased");
        assert_eq!(deepseek.base_path, "/v1");

        // Everything can be set; what is set is validated.
        let custom = ProfileRequest {
            origin: Some("https://gateway.example.com".into()),
            base_path: Some(String::new()),
            automatic_locks: Some(AutomaticLocks::End),
            max_lifetime_minutes: Some(15),
            max_requests: Some(200),
            ..ProfileRequest::new(Preset::Openai)
        }
        .resolve()
        .expect("custom");
        assert_eq!(custom.base_path, "");
        assert_eq!(custom.automatic_locks, AutomaticLocks::End);
        assert_eq!(custom.max_lifetime_minutes, 15);
        assert_eq!(custom.max_requests, Some(200));
        for bad in [
            ProfileRequest {
                origin: Some("https://api.deepseek.com/".into()),
                ..ProfileRequest::new(Preset::OpenaiCompatible)
            },
            ProfileRequest {
                base_path: Some("/v1/".into()),
                ..ProfileRequest::new(Preset::Openai)
            },
            ProfileRequest {
                max_lifetime_minutes: Some(0),
                ..ProfileRequest::new(Preset::Anthropic)
            },
            ProfileRequest {
                max_requests: Some(0),
                ..ProfileRequest::new(Preset::Anthropic)
            },
            ProfileRequest {
                base_path: Some(format!("/{}", "a".repeat(MAX_PROFILE_CHARS))),
                ..ProfileRequest::new(Preset::Anthropic)
            },
        ] {
            assert!(bad.resolve().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn profile_requests_have_a_strict_json_shape() {
        let minimal: ProfileRequest =
            serde_json::from_str(r#"{"preset":"openai"}"#).expect("minimal");
        assert_eq!(minimal, ProfileRequest::new(Preset::Openai));
        assert_eq!(
            serde_json::to_value(&minimal).expect("json"),
            serde_json::json!({"preset": "openai"})
        );
        let full: ProfileRequest = serde_json::from_value(serde_json::json!({
            "preset": "openai-compatible",
            "origin": "https://api.deepseek.com",
            "base_path": "/v1",
            "automatic_locks": "end",
            "max_lifetime_minutes": 60,
            "max_requests": 10,
        }))
        .expect("full");
        assert_eq!(full.automatic_locks, Some(AutomaticLocks::End));
        assert!(serde_json::from_str::<ProfileRequest>(r#"{"preset":"openai","x":1}"#).is_err());
        assert!(serde_json::from_str::<ProfileRequest>(r#"{"origin":"https://x.com"}"#).is_err());
    }

    #[test]
    fn presets_and_policies_have_one_spelling() {
        for preset in Preset::ALL {
            assert_eq!(preset.as_str().parse::<Preset>(), Ok(preset));
            assert_eq!(
                serde_json::to_value(preset).expect("json"),
                serde_json::json!(preset.as_str())
            );
            assert_eq!(preset.to_string(), preset.as_str());
            assert!(!preset.label().is_empty());
        }
        for policy in AutomaticLocks::ALL {
            assert_eq!(policy.as_str().parse::<AutomaticLocks>(), Ok(policy));
            assert_eq!(
                serde_json::to_value(policy).expect("json"),
                serde_json::json!(policy.as_str())
            );
        }
        for wrong in ["Anthropic", "open-ai", "openai_compatible", "", " openai"] {
            assert_eq!(wrong.parse::<Preset>(), Err(ProfileError::UnknownPreset));
        }
        assert_eq!(
            "End".parse::<AutomaticLocks>(),
            Err(ProfileError::UnknownLocks)
        );
    }

    #[test]
    fn revisions_are_found_and_the_latest_is_used() {
        for preset in Preset::ALL {
            let spec = latest(preset);
            assert_eq!(spec.preset, preset);
            assert_eq!(spec.revision, 1);
            assert_eq!(spec_for(preset, 1), Some(spec));
            assert_eq!(spec_for(preset, 0), None);
            assert_eq!(spec_for(preset, 2), None);
            assert_eq!(spec.default_max_lifetime_minutes, 720);
            assert_eq!(spec.default_automatic_locks, AutomaticLocks::Continue);
            // Every route can be found by its template.
            for route in spec.routes {
                assert_eq!(spec.route(&route.template()), Some(route));
            }
        }
        assert_eq!(
            latest(Preset::Anthropic).route("POST /v1/messages/batches"),
            None
        );
        assert_eq!(anthropic().spec(), latest(Preset::Anthropic));
    }

    #[test]
    fn the_origin_gives_the_host_port_and_urls() {
        let profile = anthropic();
        assert_eq!(profile.authority(), "api.anthropic.com");
        assert_eq!(profile.host(), "api.anthropic.com");
        assert_eq!(profile.port(), 443);
        assert_eq!(profile.destination(), "https://api.anthropic.com");
        assert_eq!(profile.local_url(43210), "http://127.0.0.1:43210");
        let gateway = ProfileRequest {
            origin: Some("https://gateway.example.com:8443".into()),
            base_path: Some("/openai/v1".into()),
            ..ProfileRequest::new(Preset::Openai)
        }
        .resolve()
        .expect("gateway");
        assert_eq!(gateway.authority(), "gateway.example.com:8443");
        assert_eq!(gateway.host(), "gateway.example.com");
        assert_eq!(gateway.port(), 8443);
        assert_eq!(
            gateway.destination(),
            "https://gateway.example.com:8443/openai/v1"
        );
        assert_eq!(gateway.local_url(1), "http://127.0.0.1:1/openai/v1");
    }

    #[test]
    fn dialogs_describe_the_whole_profile() {
        let lines = anthropic().describe();
        let expected: Vec<(String, String)> = [
            ("Destination", "https://api.anthropic.com"),
            (
                "Allows",
                "POST /v1/messages, POST /v1/messages/count_tokens, GET /v1/models, \
                 GET /v1/models/{id}",
            ),
            (
                "Ends",
                "when the command ends, on rusthorse lock, when revoked or the entry changes, or \
                 after 12h; not when the screen locks, the computer suspends or the vault locks \
                 after idle time",
            ),
            ("Requests", "no limit; at most 16 at a time"),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        assert_eq!(lines, expected);

        let strict = ProfileRequest {
            automatic_locks: Some(AutomaticLocks::End),
            max_lifetime_minutes: Some(90),
            max_requests: Some(200),
            ..ProfileRequest::new(Preset::Openai)
        }
        .resolve()
        .expect("openai");
        let lines = strict.describe();
        assert_eq!(lines[0].1, "https://api.openai.com/v1");
        assert_eq!(
            lines[1].1,
            "POST /chat/completions, POST /responses, POST /responses/input_tokens, \
             POST /embeddings, GET /models, GET /models/{id}"
        );
        assert_eq!(
            lines[2].1,
            "when the command ends, on rusthorse lock, when revoked or the entry changes, or \
             after 1h30m; also when the screen locks, the computer suspends or the vault locks \
             after idle time"
        );
        assert_eq!(lines[3].1, "at most 200; at most 16 at a time");
        // Every line is drawn as it is.
        for (label, value) in lines {
            assert_eq!(crate::ui::dialog_text(&label), label);
            assert_eq!(crate::ui::dialog_text(&value), value);
        }
        // A revision this build does not know allows nothing, and says so.
        let unknown = BrokerProfile {
            revision: 9,
            ..anthropic()
        };
        assert!(unknown.describe()[1].1.starts_with("nothing:"));
    }

    /// The attack table, one case per line: the preset, the base path (`-`
    /// for none), the method, the target, and what [`match_route`] says —
    /// the route audit records name, or the status of the refusal (`400`
    /// for a target not in origin form, `404` for any other that is not
    /// exactly a route). Targets with spaces, control characters or computed
    /// lengths are checked in the test itself.
    const ROUTE_CASES: &str = r"
        // Routes, and what audit records call them.
        anthropic          -        POST     /v1/messages                                 POST /v1/messages
        anthropic          -        POST     /v1/messages?beta=true                       POST /v1/messages
        anthropic          -        POST     /v1/messages/count_tokens                    POST /v1/messages/count_tokens
        anthropic          -        GET      /v1/models                                   GET /v1/models
        anthropic          -        GET      /v1/models?limit=20&after_id=claude-x_1.2~3  GET /v1/models
        anthropic          -        GET      /v1/models?beta=true&before_id=m             GET /v1/models
        anthropic          -        GET      /v1/models/claude-sonnet-4-5                 GET /v1/models/{id}
        anthropic          -        GET      /v1/models/ft:gpt-4o:org::x~y_z.1            GET /v1/models/{id}
        anthropic          /gw      POST     /gw/v1/messages                              POST /v1/messages
        openai             /v1      POST     /v1/chat/completions                         POST /chat/completions
        openai             /v1      POST     /v1/responses                                POST /responses
        openai             /v1      POST     /v1/responses/input_tokens                   POST /responses/input_tokens
        openai             /v1      POST     /v1/embeddings                               POST /embeddings
        openai             /v1      GET      /v1/models                                   GET /models
        openai             /v1      GET      /v1/models/gpt-4o                            GET /models/{id}
        openai-compatible  /v1      POST     /v1/chat/completions                         POST /chat/completions
        openai-compatible  /v1      POST     /v1/embeddings                               POST /embeddings
        openai-compatible  /api/v1  GET      /api/v1/models                               GET /models

        // Escapes, and characters that servers may read differently: in
        // origin form, but not in the exact form routes are written in.
        anthropic          -        POST     /v1/messages/%2e%2e/batches                  404
        anthropic          -        POST     /v1/%2e%2e/v1/messages                       404
        anthropic          -        POST     /v1%2fmessages                               404
        anthropic          -        POST     /v1/%6dessages                               404
        anthropic          -        GET      /v1/models/a%20b                             404
        anthropic          -        POST     /v1/messages?beta=%74rue                     404
        anthropic          -        POST     //v1/messages                                404
        anthropic          -        POST     /v1//messages                                404
        anthropic          -        POST     /v1/messages;x=1                             404
        anthropic          -        POST     /v1;/messages                                404
        anthropic          -        POST     /v1\messages                                 404
        anthropic          -        POST     /v1/messages\                                404
        anthropic          -        POST     /v1/messages/                                404
        anthropic          -        POST     /v1/./messages                               404
        anthropic          -        POST     /v1/../v1/messages                           404
        anthropic          -        POST     /v1/messages/..                              404
        anthropic          -        GET      /v1/models/...                               404
        anthropic          -        POST     /v1/messages#x                               404
        anthropic          -        POST     /v1/messages?beta=true#x                     404
        anthropic          -        POST     /                                            404
        openai             /v1      POST     /v1/chat/completions/                        404
        openai             /v1      POST     /v1/chat//completions                        404

        // Not in origin form.
        anthropic          -        POST     https://api.anthropic.com/v1/messages        400
        anthropic          -        POST     http://127.0.0.1:1/v1/messages               400
        anthropic          -        CONNECT  api.anthropic.com:443                        400
        anthropic          -        OPTIONS  *                                            400
        anthropic          -        POST     v1/messages                                  400
        anthropic          -        POST     /v1/méssages                                 400

        // Malformed queries, and a parameter given twice.
        anthropic          -        POST     /v1/messages?                                404
        anthropic          -        POST     /v1/messages?beta=true&beta=true             404
        anthropic          -        GET      /v1/models?limit=1&limit=2                   404
        anthropic          -        POST     /v1/messages?beta                            404
        anthropic          -        POST     /v1/messages?=true                           404
        anthropic          -        POST     /v1/messages?beta=true&                      404
        anthropic          -        POST     /v1/messages?&beta=true                      404
        anthropic          -        POST     /v1/messages?beta=true&&x=1                  404

        // Well formed, but not a route.
        anthropic          -        POST     /v1/messages/batches                         404
        anthropic          -        GET      /v1/messages/batches/msgbatch_1/results      404
        anthropic          -        POST     /v1/files                                    404
        anthropic          -        POST     /v1/organizations/api_keys                   404
        anthropic          -        POST     /V1/messages                                 404
        anthropic          -        POST     /v1/Messages                                 404
        anthropic          -        POST     /v1/messages.json                            404
        anthropic          -        POST     /v2/messages                                 404
        anthropic          -        POST     /v1                                          404
        anthropic          -        GET      /v1/models/{id}                              404
        anthropic          -        GET      /v1/models/a/b                               404
        anthropic          -        GET      /v1/models/a@b                               404
        anthropic          -        GET      /v1/models/a+b                               404
        openai             /v1      POST     /v1/fine_tuning/jobs                         404
        openai             /v1      POST     /v1/uploads                                  404
        openai             /v1      POST     /v1/files                                    404
        openai             /v1      POST     /chat/completions                            404
        openai             /v1      POST     /v1/v1/chat/completions                      404
        openai-compatible  /v1      POST     /v1/responses                                404

        // The base path matches whole segments only.
        openai             /v1      POST     /v1x/chat/completions                        404
        openai             /v1      POST     /v10/chat/completions                        404
        openai             /v1      GET      /v1                                          404
        anthropic          /gw      POST     /v1/messages                                 404
        anthropic          /gw      POST     /gwx/v1/messages                             404

        // Methods are exact.
        anthropic          -        HEAD     /v1/messages                                 404
        anthropic          -        post     /v1/messages                                 404
        anthropic          -        Post     /v1/messages                                 404
        anthropic          -        GET      /v1/messages                                 404
        anthropic          -        PUT      /v1/messages                                 404
        anthropic          -        DELETE   /v1/models/claude                            404
        anthropic          -        POST     /v1/models                                   404
        anthropic          -        TRACE    /v1/messages                                 404
        anthropic          -        OPTIONS  /v1/messages                                 404
        openai             /v1      GET      /v1/chat/completions                         404

        // Queries the route does not allow.
        anthropic          -        POST     /v1/messages?beta=false                      404
        anthropic          -        POST     /v1/messages?beta=TRUE                       404
        anthropic          -        POST     /v1/messages?beta=                           404
        anthropic          -        POST     /v1/messages?x=1                             404
        anthropic          -        POST     /v1/messages?BETA=true                       404
        anthropic          -        POST     /v1/messages?limit=10                        404
        anthropic          -        POST     /v1/messages?beta=true&x=1                   404
        anthropic          -        GET      /v1/models/claude?limit=1                    404
        anthropic          -        GET      /v1/models?limit=                            404
        anthropic          -        GET      /v1/models?limit=a+b                         404
        anthropic          -        GET      /v1/models?limit=1=2                         404
        anthropic          -        GET      /v1/models?after_id=a/b                      404
        anthropic          -        GET      /v1/models?after_id=a?b                      404
        anthropic          -        GET      /v1/models?after_id=a:b                      404
        openai             /v1      GET      /v1/models?limit=10                          404
        openai             /v1      POST     /v1/chat/completions?beta=true               404
        openai-compatible  /v1      GET      /v1/models?x=1                               404
    ";

    /// Check one case of the attack table: `expected` is the route audit
    /// records name, `400` or `404`.
    fn check_route(spec: &PresetSpec, base: &str, method: &str, target: &str, expected: &str) {
        let got = match_route(spec, base, method, target);
        let case = format!("{} {base:?} {method} {target:?}", spec.preset);
        // `400` exactly when the broker refuses the target as it checks the
        // framing, before the token.
        assert_eq!(
            got == Err(RouteRefusal::Malformed),
            !is_origin_form(target),
            "{case}"
        );
        match expected {
            "400" => assert_eq!(got, Err(RouteRefusal::Malformed), "{case}"),
            "404" => assert_eq!(got, Err(RouteRefusal::NotAllowed), "{case}"),
            template => {
                let matched = got.unwrap_or_else(|e| panic!("{case}: {e:?}"));
                assert_eq!(matched.template, template, "{case}");
                assert_eq!(matched.path_and_query, target, "{case}: sent as checked");
            }
        }
    }

    /// What reaches the destination is exactly a route.
    #[test]
    fn route_matching_refuses_everything_but_exact_routes() {
        let mut cases = 0;
        for line in ROUTE_CASES.lines().map(str::trim) {
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [preset, base, method, target, expected @ ..] = fields.as_slice() else {
                panic!("a malformed case: {line}")
            };
            let spec = latest(preset.parse().expect("a preset"));
            let base = if *base == "-" { "" } else { *base };
            check_route(spec, base, method, target, &expected.join(" "));
            cases += 1;
        }
        assert!(cases > 100, "only {cases} cases were read");

        // What the table cannot write.
        let anthropic = latest(Preset::Anthropic);
        let id = |n: usize| format!("/v1/models/{}", "a".repeat(n));
        let limit = |n: usize| format!("/v1/models?limit={}", "1".repeat(n));
        check_route(anthropic, "", "GET", &id(128), "GET /v1/models/{id}");
        check_route(anthropic, "", "GET", &id(129), "404");
        check_route(anthropic, "", "GET", &limit(128), "GET /v1/models");
        check_route(anthropic, "", "GET", &limit(129), "404");
        for target in [
            "",
            "/v1/messages ",
            " /v1/messages",
            "/v1/mess ages",
            "/v1/messages\t",
            "/v1/messages\r\n",
            "/v1/messages\u{0}",
            "/v1/messages\u{7f}",
            "/v1/messages?beta=true\u{0}",
            "/v1/models/a\u{a0}b",
        ] {
            check_route(anthropic, "", "POST", target, "400");
        }
        assert_eq!(RouteRefusal::Malformed.status(), 400);
        assert_eq!(RouteRefusal::NotAllowed.status(), 404);

        // Origin form: a path, then anything visible.
        for target in ["/", "/v1/messages", "/v1/%2e%2e", "/v1\\x", "/a#b", "/?"] {
            assert!(is_origin_form(target), "{target:?}");
        }
        for target in [
            "",
            "*",
            "v1/messages",
            "https://api.anthropic.com/v1/messages",
            "api.anthropic.com:443",
            "/v1 messages",
            "/v1/m\u{e9}ssages",
            "/v1/messages\r\n",
        ] {
            assert!(!is_origin_form(target), "{target:?}");
        }
    }

    /// Redundant with route matching today (every route starts with `/`),
    /// and kept so that it stays true whatever a later route looks like.
    #[test]
    fn the_base_path_is_stripped_as_whole_segments() {
        assert_eq!(
            strip_base_path("/v1/chat/completions", "/v1"),
            Some("/chat/completions")
        );
        assert_eq!(
            strip_base_path("/api/v1/models", "/api/v1"),
            Some("/models")
        );
        assert_eq!(strip_base_path("/v1/models", ""), Some("/v1/models"));
        assert_eq!(strip_base_path("/v1x/chat/completions", "/v1"), None);
        assert_eq!(strip_base_path("/api/v10/models", "/api/v1"), None);
        assert_eq!(strip_base_path("/v1", "/v1"), None);
        assert_eq!(strip_base_path("/v2/models", "/v1"), None);
    }

    #[test]
    fn only_the_listed_request_headers_are_forwarded() {
        let anthropic = latest(Preset::Anthropic);
        let openai = latest(Preset::Openai);
        let compatible = latest(Preset::OpenaiCompatible);
        for name in [
            "content-type",
            "Content-Type",
            "accept",
            "user-agent",
            "anthropic-version",
            "Anthropic-Beta",
            "x-stainless-retry-count",
            "X-Stainless-Lang",
            "x-claude-code-session-id",
        ] {
            assert!(forwards_request_header(anthropic, name), "{name}");
        }
        for name in [
            "x-api-key",
            "authorization",
            "proxy-authorization",
            "cookie",
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
            "accept-encoding",
            "origin",
            "x-forwarded-for",
            "forwarded",
            "openai-beta",
            "openai-organization",
            "anthropic",
            "x-stainless",
            "",
        ] {
            assert!(!forwards_request_header(anthropic, name), "{name}");
        }
        for spec in [openai, compatible] {
            for name in [
                "content-type",
                "accept",
                "user-agent",
                "openai-beta",
                "OpenAI-Beta",
                "x-stainless-os",
            ] {
                assert!(forwards_request_header(spec, name), "{name}");
            }
            for name in [
                "OpenAI-Organization",
                "openai-project",
                "x-api-key",
                "authorization",
                "anthropic-version",
                "x-claude-code-session-id",
                "cookie",
                "connection",
                "accept-encoding",
            ] {
                assert!(!forwards_request_header(spec, name), "{name}");
            }
        }
    }

    #[test]
    fn only_the_listed_response_headers_are_relayed() {
        for spec in Preset::ALL.map(latest) {
            for name in [
                "content-type",
                "date",
                "cache-control",
                "retry-after",
                "x-should-retry",
                "request-id",
                "x-request-id",
                "openai-processing-ms",
                "openai-version",
                "anthropic-ratelimit-requests-remaining",
                "Anthropic-RateLimit-Tokens-Reset",
                "x-ratelimit-remaining-tokens",
            ] {
                assert!(relays_response_header(spec, name), "{name}");
            }
            for name in [
                "set-cookie",
                "location",
                "content-length",
                "content-encoding",
                "transfer-encoding",
                "connection",
                "trailer",
                "upgrade",
                "www-authenticate",
                "proxy-authenticate",
                "server",
                "alt-svc",
                "strict-transport-security",
                "openai-organization",
                "anthropic-organization-id",
                "x-ratelimit",
            ] {
                assert!(!relays_response_header(spec, name), "{name}");
            }
        }
    }

    #[test]
    fn credentials_are_presented_as_each_preset_says() {
        assert_eq!(
            latest(Preset::Anthropic).credential_header,
            AuthHeader::XApiKey
        );
        assert_eq!(latest(Preset::Openai).credential_header, AuthHeader::Bearer);
        assert_eq!(
            latest(Preset::OpenaiCompatible).credential_header,
            AuthHeader::Bearer
        );
        assert_eq!(AuthHeader::XApiKey.name(), "x-api-key");
        assert_eq!(AuthHeader::Bearer.name(), "authorization");
        assert_eq!(AuthHeader::XApiKey.value("sk-1").as_str(), "sk-1");
        assert_eq!(AuthHeader::Bearer.value("sk-1").as_str(), "Bearer sk-1");
    }

    #[test]
    fn tokens_are_checked_in_every_header_that_may_carry_one() {
        use TokenRefusal::{Malformed, Missing, Wrong};
        let ours = token('a');
        let other = token('b');
        let (a, o) = (latest(Preset::Anthropic), latest(Preset::Openai));
        let key = |value: &str| ("x-api-key", value.to_string());
        let auth = |value: &str| ("authorization", value.to_string());
        let named = |name: &'static str, value: &str| (name, value.to_string());
        let json = || ("content-type", "application/json".to_string());
        let bearer = format!("Bearer {ours}");
        let bearer_other = format!("Bearer {other}");
        let cases = [
            (a, vec![key(&ours)], Ok(())),
            (a, vec![named("X-Api-Key", &ours)], Ok(())),
            (a, vec![auth(&bearer)], Ok(())),
            (a, vec![auth(&format!("bearer {ours}"))], Ok(())),
            (
                a,
                vec![named("AUTHORIZATION", &format!("BEARER {ours}"))],
                Ok(()),
            ),
            (a, vec![key(&ours), auth(&bearer)], Ok(())),
            (a, vec![json(), key(&ours)], Ok(())),
            (a, vec![], Err(Missing)),
            (a, vec![json()], Err(Missing)),
            (a, vec![named("x-api-keys", &ours)], Err(Missing)),
            (a, vec![key(&other)], Err(Wrong)),
            (a, vec![auth(&bearer_other)], Err(Wrong)),
            // Both headers: both must carry the token.
            (a, vec![key(&ours), auth(&bearer_other)], Err(Wrong)),
            (a, vec![key(&other), auth(&bearer)], Err(Wrong)),
            (
                a,
                vec![key(&ours), auth("Basic dXNlcjpwYXNz")],
                Err(Malformed),
            ),
            // The same header twice: every one counts.
            (a, vec![key(&ours), key(&other)], Err(Wrong)),
            (a, vec![key(&ours), key(&ours)], Ok(())),
            // The exact form, or nothing.
            (a, vec![auth(&format!("Bearer  {ours}"))], Err(Malformed)),
            (a, vec![auth(&format!("Bearer\t{ours}"))], Err(Malformed)),
            (a, vec![auth(&format!("Bearer{ours}"))], Err(Malformed)),
            (a, vec![auth(&format!("{bearer} "))], Err(Malformed)),
            (a, vec![auth(&format!(" {bearer}"))], Err(Malformed)),
            (a, vec![auth(&format!("Token {ours}"))], Err(Malformed)),
            (a, vec![auth(&ours)], Err(Malformed)),
            (a, vec![auth("Bearer")], Err(Malformed)),
            (a, vec![auth("Bearer ")], Err(Malformed)),
            (a, vec![key(&bearer)], Err(Malformed)),
            (a, vec![key(&format!("{ours} "))], Err(Malformed)),
            (a, vec![key(&ours.to_uppercase())], Err(Malformed)),
            (a, vec![key(&ours[..66])], Err(Malformed)),
            (a, vec![key(&format!("{ours}0"))], Err(Malformed)),
            (a, vec![key(&format!("sk_{}", &ours[3..]))], Err(Malformed)),
            (a, vec![key("")], Err(Malformed)),
            // The OpenAI presets take the token in Authorization only;
            // x-api-key is ignored here (the header rule drops it).
            (o, vec![auth(&bearer)], Ok(())),
            (o, vec![key(&ours)], Err(Missing)),
            (o, vec![key("garbage"), auth(&bearer)], Ok(())),
            (o, vec![auth(&bearer_other)], Err(Wrong)),
            (o, vec![auth(&bearer), auth(&bearer_other)], Err(Wrong)),
        ];
        for (spec, headers, expected) in cases {
            let pairs = headers
                .iter()
                .map(|(name, value)| (*name, value.as_bytes()));
            let got = check_inbound_token(spec, pairs, &ours);
            assert_eq!(got, expected, "{} {headers:?}", spec.preset);
        }
        // Bytes that are not text are not a token.
        let raw: [(&str, &[u8]); 1] = [("x-api-key", b"rh_\xff")];
        assert_eq!(check_inbound_token(a, raw, &ours), Err(Malformed));
        // An expected token that is not well formed matches nothing.
        let headers = [("x-api-key", b"not-a-token".as_slice())];
        assert_eq!(
            check_inbound_token(a, headers, "not-a-token"),
            Err(Malformed)
        );
    }

    #[test]
    fn token_comparison_compares_every_byte() {
        let a = token('a');
        assert!(tokens_equal(a.as_bytes(), a.as_bytes()));
        assert!(tokens_equal(b"", b""));
        let mut first = a.clone().into_bytes();
        first[0] = b'x';
        let mut last = a.clone().into_bytes();
        *last.last_mut().expect("byte") = b'b';
        assert!(!tokens_equal(a.as_bytes(), &first));
        assert!(!tokens_equal(a.as_bytes(), &last));
        assert!(!tokens_equal(a.as_bytes(), &a.as_bytes()[..66]));
        assert!(!tokens_equal(&a.as_bytes()[..66], a.as_bytes()));
        assert!(!tokens_equal(b"", b"\0"));
    }

    #[test]
    fn credentials_fit_in_a_header_and_are_long_enough_to_redact() {
        assert_eq!((MIN_CREDENTIAL_CHARS, MAX_CREDENTIAL_CHARS), (8, 4096));
        assert!(is_valid_credential("sk-ant-api03-abc_DEF-123"));
        assert!(is_valid_credential(&"k".repeat(8)));
        assert!(is_valid_credential(&"k".repeat(4096)));
        // Every visible ASCII character.
        let visible: String = (0x21u8..=0x7e).map(char::from).collect();
        assert!(is_valid_credential(&visible));
        for bad in [
            String::new(),
            "x".into(),
            "abc".into(),
            "k9".into(),
            "k".repeat(7),
            "k".repeat(4097),
            "sk-1\r\nX-Injected: 1".into(),
            "sk-12345\n".into(),
            "sk 12345".into(),
            "sk-12345\t".into(),
            "sk-12345\u{7f}".into(),
            // Eight characters, nine bytes: not ASCII.
            "sk-1234\u{e9}".into(),
            "\0".repeat(8),
        ] {
            assert!(!is_valid_credential(&bad), "{bad:?}");
        }
        // The shortest credential accepted is replaced by the redactor; the
        // redactor ignores shorter secrets, and would let them through.
        for shortest in ["k".repeat(8), "a1b2c3d4".into()] {
            let mut redactor = crate::redact::Redactor::new([("credential", shortest.as_bytes())]);
            let mut out = redactor.push(format!(r#"{{"echo":"{shortest}"}}"#).as_bytes());
            out.extend(redactor.finish());
            assert_eq!(out, br#"{"echo":"[REDACTED:credential]"}"#);
        }
        let mut redactor = crate::redact::Redactor::new([("credential", b"abc".as_slice())]);
        let mut out = redactor.push(br#"{"echo":"abc"}"#);
        out.extend(redactor.finish());
        assert_eq!(out, br#"{"echo":"abc"}"#, "too short to redact");
    }
}
