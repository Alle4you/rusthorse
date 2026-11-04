//! End-to-end tests of `rusthorse-broker`, the program alone: the real
//! binary, played by a fake agent over its control channel, in front of a
//! fake HTTPS destination in the test process (ADR 0013, "Tests before real
//! credentials", the broker's rows). Every key is fake; nothing leaves the
//! loopback interface.
//!
//! Tests that need the broker to reach the fake destination need its
//! `test-upstream` feature (`cargo test -p rusthorse-broker
//! --all-features`) and an environment that names the test's authority
//! (`RUSTHORSE_BROKER_TEST_ROOTS`, which `Options` sets); the others run in
//! both builds. Some show that a build without the feature, and any build
//! started with an empty environment as the agent starts it, refuse a
//! loopback destination.

mod support;

use std::time::{Duration, Instant};

use rusthorse::broker_grant::MethodLabel;
use rusthorse::broker_protocol::{AdmissionRefusal, EndReason, FromBroker, RequestOutcome};
use support::*;

/// The message of a local answer, without the broker's prefix.
fn message(response: &Response) -> String {
    let message = response.json()["error"]["message"]
        .as_str()
        .expect("a message")
        .to_string();
    message
        .strip_prefix("rusthorse-broker: ")
        .unwrap_or_else(|| panic!("no prefix: {message}"))
        .to_string()
}

/// Headers, as `raw_request` takes them.
type Headers = Vec<(String, String)>;

/// The headers `pairs` as owned pairs, for `raw_request`.
fn owned(pairs: &[(&str, &str)]) -> Headers {
    pairs
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

/// A token of the right form that is no grant's.
fn foreign_token() -> String {
    format!("rh_{}", "0".repeat(64))
}

/// What the broker answers when the token is missing, misplaced or another,
/// or the key itself is in the request, or the head too large with the key
/// in it.
const MISSING: &str = "the request does not present this grant's token in a header value";
const MISPLACED: &str = "a token may only be in the value of a header the broker forwards";
const FOREIGN: &str = "the request holds a token that is not this grant's, byte for byte";
const KEY: &str = "the request holds the key itself; present the grant's token instead";
#[cfg(feature = "test-upstream")]
const TOO_LARGE: &str = "the request's headers are larger than 32 KiB with the key in them";

#[cfg(feature = "test-upstream")]
#[test]
fn a_request_reaches_the_destination_as_the_broker_builds_it() {
    let ca = TestCa::new();
    let body = br#"{"model":"claude-test","max_tokens":1}"#;
    let destination = Destination::new(
        &ca,
        answer(
            200,
            &[
                ("content-type", "application/json"),
                ("request-id", "req_0001"),
                ("set-cookie", "session=1"),
                ("location", "https://elsewhere.example/"),
                ("x-unlisted", "1"),
                ("keep-alive", "timeout=5"),
            ],
            br#"{"type":"message","content":[]}"#,
        ),
    );
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let token = broker.token.clone();
    let response = broker.send(&broker.request(
        "POST",
        "/v1/messages?beta=true",
        &[
            ("authorization", &format!("Bearer {token}")),
            ("content-type", "application/json"),
            ("anthropic-version", "2023-06-01"),
            ("user-agent", "Anthropic/Python 9.9"),
            ("accept-encoding", "gzip, br"),
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("cookie", "a=b"),
            ("openai-organization", "org-1"),
            ("x-forwarded-for", "10.0.0.1"),
            ("proxy-authorization", "Basic Zm9vOmJhcg=="),
            ("te", "trailers"),
            ("trailer", "x-checksum"),
        ],
        body,
    ));
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, br#"{"type":"message","content":[]}"#);
    assert!(response.complete);
    // The destination's headers, but its framing and hop-by-hop ones; the
    // body chunked: never the destination's length.
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.header("request-id"), Some("req_0001"));
    assert_eq!(response.header("set-cookie"), Some("session=1"));
    assert_eq!(
        response.header("location"),
        Some("https://elsewhere.example/")
    );
    assert_eq!(response.header("x-unlisted"), Some("1"));
    for dropped in ["content-length", "keep-alive"] {
        assert_eq!(response.header(dropped), None, "{dropped}: {response:?}");
    }
    assert_eq!(response.header("transfer-encoding"), Some("chunked"));

    let received = destination.wait_for(1);
    let got = &received[0];
    assert_eq!(got.method, "POST");
    assert_eq!(got.target, "/v1/messages?beta=true");
    assert_eq!(got.version, "HTTP/1.1");
    assert_eq!(got.body, body);
    // Host and SNI from the approved origin; HTTP/1.1 only.
    assert_eq!(
        got.values("host"),
        vec![format!("localhost:{}", destination.port)]
    );
    assert_eq!(got.sni.as_deref(), Some("localhost"));
    assert_eq!(got.alpn.as_deref(), Some(&b"http/1.1"[..]));
    // The key where the client put the token, in both headers; the token
    // nowhere.
    assert_eq!(got.values("x-api-key"), vec![CREDENTIAL.to_string()]);
    assert_eq!(
        got.values("authorization"),
        vec![format!("Bearer {CREDENTIAL}")]
    );
    assert!(!got.head_text().contains(&token), "{}", got.head_text());
    assert_eq!(got.values("accept-encoding"), vec!["identity".to_string()]);
    assert_eq!(got.values("content-length"), vec![body.len().to_string()]);
    // Every other header as the client sent it, but the hop-by-hop ones.
    assert_eq!(got.values("cookie"), vec!["a=b".to_string()]);
    assert_eq!(got.values("x-forwarded-for"), vec!["10.0.0.1".to_string()]);
    let mut names = got.names();
    names.sort();
    assert_eq!(
        names,
        vec![
            "accept-encoding",
            "anthropic-version",
            "authorization",
            "content-length",
            "content-type",
            "cookie",
            "host",
            "openai-organization",
            "user-agent",
            "x-api-key",
            "x-forwarded-for",
        ]
    );
    // The admission named the method's label, never the method, the target
    // or a header; the end came with the status and the sizes.
    assert_eq!(
        broker.wait_admit(1),
        FromBroker::Admit {
            request: 1,
            method: MethodLabel::Post,
        }
    );
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::Completed,
            status: Some(200),
            bytes_sent: body.len() as u64,
            bytes_received: 31,
        }
    );
}

#[test]
fn requests_without_this_grants_token_are_refused() {
    let ca = TestCa::new();
    let broker =
        Broker::start(Options::nowhere(&ca).admit(Admit::Refuse(AdmissionRefusal::Exhausted)));
    let other = Broker::start(Options::nowhere(&ca));
    let port = broker.port;
    let token = broker.token.clone();
    let upper = token.to_uppercase();
    let wrong = foreign_token();
    let cases: Vec<(&str, Headers, &str)> = vec![
        ("missing", vec![], MISSING),
        ("empty", owned(&[("x-api-key", "")]), MISSING),
        ("short", owned(&[("x-api-key", "rh_123")]), MISSING),
        ("cut short", owned(&[("x-api-key", &token[..66])]), MISSING),
        ("the real key", owned(&[("x-api-key", CREDENTIAL)]), MISSING),
        ("uppercase", owned(&[("x-api-key", &upper)]), FOREIGN),
        (
            "an uppercase prefix",
            owned(&[("x-api-key", &format!("RH_{}", &token[3..]))]),
            FOREIGN,
        ),
        ("wrong", owned(&[("x-api-key", &wrong)]), FOREIGN),
        (
            "another grant's",
            owned(&[("x-api-key", &other.token)]),
            FOREIGN,
        ),
        (
            "bearer wrong",
            owned(&[("authorization", &format!("Bearer {wrong}"))]),
            FOREIGN,
        ),
        (
            "x-api-key right, bearer wrong",
            owned(&[
                ("x-api-key", &token),
                ("authorization", &format!("Bearer {wrong}")),
            ]),
            FOREIGN,
        ),
        (
            "bearer right, x-api-key uppercase",
            owned(&[
                ("authorization", &format!("Bearer {token}")),
                ("x-api-key", &upper),
            ]),
            FOREIGN,
        ),
        (
            "x-api-key twice, one wrong",
            owned(&[("x-api-key", &token), ("x-api-key", &wrong)]),
            FOREIGN,
        ),
        (
            "another in a value beside it",
            owned(&[
                ("x-api-key", &token),
                ("user-agent", &format!("agent/1 {}", other.token)),
            ]),
            FOREIGN,
        ),
        (
            "another inside a word",
            owned(&[("x-api-key", &token), ("x-trace", &format!("ab{wrong}cd"))]),
            FOREIGN,
        ),
        (
            "only in a header the broker drops",
            owned(&[("proxy-authorization", &format!("Bearer {token}"))]),
            MISPLACED,
        ),
    ];
    for (why, headers, expected) in &cases {
        let response = broker.send(&raw_request("GET", "/v1/models", port, headers, b""));
        response.assert_local(401);
        assert_eq!(message(&response), *expected, "{why}");
        assert!(!response.text().contains(&token), "{why}");
        assert!(!response.text().contains(CREDENTIAL), "{why}");
    }
    assert_eq!(broker.admits(), 0, "nothing was asked");
    // The token, in any header the broker forwards, with any prefix, alone
    // or in several headers, goes on to the admission (which this agent
    // refuses).
    let accepted: Vec<Headers> = vec![
        owned(&[("x-api-key", &token)]),
        owned(&[("authorization", &format!("Bearer {token}"))]),
        owned(&[("authorization", &format!("bearer {token}"))]),
        owned(&[("authorization", &format!("Bearer  {token}"))]),
        owned(&[("authorization", &format!("Basic {token}"))]),
        owned(&[("authorization", &format!("Token {token}"))]),
        owned(&[("authorization", &token)]),
        owned(&[("x-goog-api-key", &token)]),
        owned(&[("x-anything", &format!("k={token};"))]),
        owned(&[
            ("x-api-key", &token),
            ("authorization", &format!("Bearer {token}")),
        ]),
    ];
    for headers in &accepted {
        broker
            .send(&raw_request("GET", "/v1/models", port, headers, b""))
            .assert_local(403);
    }
    assert_eq!(broker.admits(), accepted.len());
    // Each refusal before admission was counted; the agent's were not.
    broker.revoke(EndReason::Revoked);
    assert_eq!(broker.wait_revoked(), cases.len() as u64);
}

/// The token, or any token-shaped string, in the method, the target, a
/// header name or a header the broker drops or rebuilds: refused, whatever
/// the case, even beside the token where it belongs, and nothing is asked.
#[test]
fn a_token_outside_the_forwarded_header_values_is_refused() {
    let ca = TestCa::new();
    let broker =
        Broker::start(Options::nowhere(&ca).admit(Admit::Refuse(AdmissionRefusal::Exhausted)));
    let port = broker.port;
    let token = broker.token.clone();
    let upper = token.to_uppercase();
    let wrong = foreign_token();
    let key = owned(&[("x-api-key", &token)]);
    let with = |extra: &[(&str, &str)]| {
        let mut headers = key.clone();
        headers.extend(owned(extra));
        headers
    };
    let named = format!("x-{token}");
    let named_upper = format!("X-{upper}");
    let named_foreign = format!("x-stainless-{wrong}");
    let cases: Vec<(&str, String, String, Headers)> = vec![
        ("the method", token.clone(), "/v1/x".into(), key.clone()),
        (
            "inside the method",
            format!("GET{upper}"),
            "/v1/x".into(),
            key.clone(),
        ),
        (
            "the path",
            "GET".into(),
            format!("/v1/{token}"),
            key.clone(),
        ),
        (
            "the query",
            "GET".into(),
            format!("/v1/x?key={token}"),
            key.clone(),
        ),
        (
            "the query, uppercase",
            "GET".into(),
            format!("/v1/x?key={upper}"),
            key.clone(),
        ),
        (
            "another in the path",
            "GET".into(),
            format!("/{wrong}"),
            key.clone(),
        ),
        (
            "a header name",
            "GET".into(),
            "/".into(),
            with(&[(&named, "1")]),
        ),
        (
            "a header name, uppercase",
            "GET".into(),
            "/".into(),
            with(&[(&named_upper, "1")]),
        ),
        (
            "another in a header name",
            "GET".into(),
            "/".into(),
            with(&[(&named_foreign, "1")]),
        ),
        (
            "keep-alive",
            "GET".into(),
            "/".into(),
            with(&[("keep-alive", &token)]),
        ),
        ("te", "GET".into(), "/".into(), with(&[("te", &token)])),
        (
            "trailer",
            "GET".into(),
            "/".into(),
            with(&[("trailer", &token)]),
        ),
        (
            "proxy-authorization",
            "GET".into(),
            "/".into(),
            with(&[("proxy-authorization", &format!("Bearer {token}"))]),
        ),
        (
            "proxy-connection, uppercase",
            "GET".into(),
            "/".into(),
            with(&[("proxy-connection", &upper)]),
        ),
        (
            "accept-encoding",
            "GET".into(),
            "/".into(),
            with(&[("accept-encoding", &token)]),
        ),
        (
            "another in accept-encoding",
            "GET".into(),
            "/".into(),
            with(&[("accept-encoding", &wrong)]),
        ),
    ];
    for (why, method, target, headers) in &cases {
        let response = broker.send(&raw_request(method, target, port, headers, b""));
        response.assert_local(401);
        assert_eq!(message(&response), MISPLACED, "{why}");
        assert!(!response.text().contains(&token), "{why}");
    }
    // Those the framing refuses first: refused too.
    for (name, value) in [
        ("connection", token.clone()),
        ("upgrade", token.clone()),
        ("origin", token.clone()),
        ("host", token.clone()),
    ] {
        let mut headers = key.clone();
        headers.push((name.into(), value));
        let raw = raw_request("GET", "/", port, &headers, b"");
        let response = broker.send(&raw);
        assert_eq!(response.status, 400, "{name}: {response:?}");
    }
    assert_eq!(broker.admits(), 0, "nothing was asked");
    broker.revoke(EndReason::Revoked);
    assert_eq!(broker.wait_revoked(), cases.len() as u64 + 4);
}

/// The key itself anywhere in the request's head — beside the token — is
/// refused before anything is asked, and never echoed.
#[test]
fn a_request_that_holds_the_key_itself_is_refused() {
    let ca = TestCa::new();
    let broker =
        Broker::start(Options::nowhere(&ca).admit(Admit::Refuse(AdmissionRefusal::Exhausted)));
    let port = broker.port;
    let token = broker.token.clone();
    let key = owned(&[("x-api-key", &token)]);
    let with = |extra: &[(&str, &str)]| {
        let mut headers = key.clone();
        headers.extend(owned(extra));
        headers
    };
    let cases: Vec<(&str, &str, String, Headers)> = vec![
        ("the method", CREDENTIAL, "/".into(), key.clone()),
        ("the path", "GET", format!("/v1/{CREDENTIAL}"), key.clone()),
        (
            "the query",
            "GET",
            format!("/?key={CREDENTIAL}"),
            key.clone(),
        ),
        (
            "a header",
            "GET",
            "/".into(),
            with(&[("x-api-key", CREDENTIAL)]),
        ),
        (
            "inside a value",
            "GET",
            "/".into(),
            with(&[("user-agent", &format!("agent/1 ({CREDENTIAL})"))]),
        ),
        (
            "beside the token",
            "GET",
            "/".into(),
            owned(&[("authorization", &format!("Bearer {token} {CREDENTIAL}"))]),
        ),
        (
            "a header the broker drops",
            "GET",
            "/".into(),
            with(&[("proxy-authorization", CREDENTIAL)]),
        ),
    ];
    for (why, method, target, headers) in &cases {
        let response = broker.send(&raw_request(method, target, port, headers, b""));
        response.assert_local(401);
        assert_eq!(message(&response), KEY, "{why}");
        assert!(!response.text().contains(CREDENTIAL), "{why}");
    }
    assert_eq!(broker.admits(), 0, "nothing was asked");
    // Part of it, or another case of it, is not the key.
    let lower = CREDENTIAL.to_lowercase();
    for value in [&CREDENTIAL[..CREDENTIAL.len() - 1], lower.as_str()] {
        broker
            .send(&raw_request(
                "GET",
                "/",
                port,
                &with(&[("x-other", value)]),
                b"",
            ))
            .assert_local(403);
    }
    assert_eq!(broker.admits(), 2);
}

/// With a key of 4096 characters, a header that presents the token seven
/// times fits the head's 32 KiB once the key is in, and goes, the key in
/// each place; eight times does not, and is refused before anything is
/// asked, though its head was small when it arrived.
#[cfg(feature = "test-upstream")]
#[test]
fn a_head_too_large_once_the_key_is_in_is_refused() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let mut options = Options::new(&destination.origin(), &ca);
    let key = format!("sk-{}", "k".repeat(4093));
    options.credential = key.clone();
    let broker = Broker::start(options);
    let token = broker.token.clone();
    let presented = |times: usize| vec![token.as_str(); times].join(",");
    let raw = |times: usize| {
        raw_request(
            "GET",
            "/v1/x",
            broker.port,
            &owned(&[("x-api-key", &presented(times))]),
            b"",
        )
    };
    let response = broker.send(&raw(7));
    assert_eq!(response.status, 200, "{response:?}");
    let got = &destination.wait_for(1)[0];
    assert_eq!(got.values("x-api-key"), vec![[key.as_str(); 7].join(",")]);
    let head = raw(8);
    assert!(head.len() < 2048, "a small head: {}", head.len());
    let response = broker.send(&head);
    response.assert_local(401);
    assert_eq!(message(&response), TOO_LARGE);
    assert_eq!(broker.admits(), 1);
    assert_eq!(destination.received().len(), 1);
}

/// The key takes the token's place wherever the client put it: in any
/// header the broker forwards, with any prefix, inside larger values, as
/// often as it is there, and in duplicate headers; nothing else changes.
#[cfg(feature = "test-upstream")]
#[test]
fn the_key_takes_the_tokens_place_in_every_header_that_holds_it() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let token = broker.token.clone();
    let headers = owned(&[
        ("authorization", &format!("Token {token}")),
        ("x-api-key", &token),
        ("x-goog-api-key", &token),
        ("x-custom", &format!("a {token}, {token} b")),
        ("x-glued", &format!("abc{token}def")),
        ("x-api-key", &format!("2 {token}")),
        ("x-plain", "no token here"),
    ]);
    let response = broker.send(&raw_request("GET", "/v1/x", broker.port, &headers, b""));
    assert_eq!(response.status, 200, "{response:?}");
    let got = &destination.wait_for(1)[0];
    assert_eq!(
        got.values("authorization"),
        vec![format!("Token {CREDENTIAL}")]
    );
    assert_eq!(
        got.values("x-api-key"),
        vec![CREDENTIAL.to_string(), format!("2 {CREDENTIAL}")]
    );
    assert_eq!(got.values("x-goog-api-key"), vec![CREDENTIAL.to_string()]);
    assert_eq!(
        got.values("x-custom"),
        vec![format!("a {CREDENTIAL}, {CREDENTIAL} b")]
    );
    assert_eq!(got.values("x-glued"), vec![format!("abc{CREDENTIAL}def")]);
    assert_eq!(got.values("x-plain"), vec!["no token here".to_string()]);
    assert!(!got.head_text().contains(&token), "{}", got.head_text());
    assert_eq!(got.head_text().matches(CREDENTIAL).count(), 7);
}

/// The key goes in once for each token, in one pass: a key that holds the
/// token itself is not replaced again.
#[cfg(feature = "test-upstream")]
#[test]
fn the_key_goes_in_once_for_each_token_whatever_it_holds() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let mut options = Options::new(&destination.origin(), &ca);
    let key = format!("x{}y", options.token);
    options.credential = key.clone();
    let broker = Broker::start(options);
    let token = broker.token.clone();
    let response = broker.send(&broker.request(
        "GET",
        "/v1/x",
        &[("authorization", &format!("Bearer {token} {token}"))],
        b"",
    ));
    assert_eq!(response.status, 200, "{response:?}");
    let got = &destination.wait_for(1)[0];
    assert_eq!(got.values("x-api-key"), vec![key.clone()]);
    assert_eq!(
        got.values("authorization"),
        vec![format!("Bearer {key} {key}")]
    );
}

#[test]
fn check_answers_the_contract_of_check_program() {
    let checked = rusthorse::helper_program::check_program(
        std::path::Path::new(program()),
        Duration::from_secs(10),
    );
    let (version, protocol) = if TEST_UPSTREAM {
        // A build with the test feature is refused by check_program (and
        // so by rusthorse doctor), whatever its version.
        let refusal = checked.expect_err("a build for tests is refused");
        assert!(format!("{refusal:#}").contains("for tests"), "{refusal:#}");
        (
            env!("CARGO_PKG_VERSION").to_string(),
            rusthorse::broker_protocol::VERSION,
        )
    } else {
        checked.expect("--check")
    };
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    assert_eq!(protocol, rusthorse::broker_protocol::VERSION);
    // The whole answer: a build with the test feature says so, so that it
    // cannot pass for a release; a release says nothing more.
    let output = std::process::Command::new(program())
        .arg("--check")
        .env_clear()
        .output()
        .expect("--check");
    assert!(output.status.success(), "{output:?}");
    let answer: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let mut expected = serde_json::json!({ "version": version, "protocol": protocol });
    if TEST_UPSTREAM {
        expected["test_upstream"] = serde_json::Value::Bool(true);
    }
    assert_eq!(answer, expected);
}

#[test]
fn the_channel_ending_ends_the_broker_at_once() {
    let ca = TestCa::new();
    let mut broker = Broker::start(Options::nowhere(&ca));
    let started = Instant::now();
    broker.close_channel();
    let status = broker.exit_within(Duration::from_secs(5)).expect("exits");
    assert!(status.success(), "{status:?}");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
}

// ===== Targets, methods and framing =====

#[test]
fn any_target_and_method_go_on_to_the_admission_by_its_label_only() {
    let ca = TestCa::new();
    let broker =
        Broker::start(Options::nowhere(&ca).admit(Admit::Refuse(AdmissionRefusal::Exhausted)));
    let cases: &[(&str, &str, MethodLabel)] = &[
        ("POST", "/v1/messages/batches", MethodLabel::Post),
        ("GET", "/v1/organizations/me", MethodLabel::Get),
        ("PUT", "/v1//messages", MethodLabel::Put),
        ("PATCH", "//v1/./messages", MethodLabel::Patch),
        ("DELETE", "/v1/../v1/files/1", MethodLabel::Delete),
        ("GET", "/v1/%2e%2e/%6dessages", MethodLabel::Get),
        ("GET", "/v1/messages;x=1", MethodLabel::Get),
        ("GET", "/v1\\messages", MethodLabel::Get),
        ("GET", "/?beta=true&beta=false&x", MethodLabel::Get),
        ("post", "/v1/messages", MethodLabel::Other),
        ("PROPFIND", "/dav", MethodLabel::Other),
        ("M-SEARCH", "/ssdp", MethodLabel::Other),
    ];
    for (n, (method, target, _)) in cases.iter().enumerate() {
        let response = broker.send(&broker.request(method, target, &[], b""));
        response.assert_local(403);
        assert!(!response.text().contains(target), "{response:?}");
        broker.wait_admit(n as u64 + 1);
    }
    // HEAD, whose answer has no body.
    let mut client = broker.connect();
    client.write(&broker.request("HEAD", "/v1/models", &[], b""));
    assert_eq!(client.head().0, 403);
    broker.wait_admit(cases.len() as u64 + 1);
    let labels: Vec<MethodLabel> = broker
        .messages()
        .iter()
        .filter_map(|m| match m {
            FromBroker::Admit { method, .. } => Some(*method),
            _ => None,
        })
        .collect();
    let mut expected: Vec<MethodLabel> = cases.iter().map(|(_, _, label)| *label).collect();
    expected.push(MethodLabel::Head);
    assert_eq!(labels, expected);
}

/// The target goes to the approved origin exactly as the client sent it,
/// and a body with its length goes with any method.
#[cfg(feature = "test-upstream")]
#[test]
fn targets_go_as_sent_and_a_body_goes_with_any_method() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let body = br#"{"x":1}"#;
    let cases: &[(&str, &str, &[u8], MethodLabel)] = &[
        ("GET", "/v1/files?limit=2&limit=3", body, MethodLabel::Get),
        ("PUT", "/v1//a/../b;c", body, MethodLabel::Put),
        ("PATCH", "/%2e%2e/x%20y", body, MethodLabel::Patch),
        ("DELETE", "/v1/files/f_1", body, MethodLabel::Delete),
        ("PROPFIND", "/dav/", body, MethodLabel::Other),
        ("GET", "/v1/models", b"", MethodLabel::Get),
    ];
    for (n, (method, target, body, label)) in cases.iter().enumerate() {
        let response = broker.send(&broker.request(method, target, &[], body));
        assert_eq!(response.status, 200, "{method} {target}: {response:?}");
        let got = &destination.wait_for(n + 1)[n];
        assert_eq!(
            (got.method.as_str(), got.target.as_str()),
            (*method, *target)
        );
        assert_eq!(got.body, *body, "{method}");
        let length = (!body.is_empty()).then(|| body.len().to_string());
        assert_eq!(
            got.values("content-length"),
            length.into_iter().collect::<Vec<_>>()
        );
        assert_eq!(
            broker.wait_admit(n as u64 + 1),
            FromBroker::Admit {
                request: n as u64 + 1,
                method: *label,
            }
        );
    }
    // A length of zero, declared, is declared to the destination too.
    let raw = raw_request(
        "POST",
        "/v1/x",
        broker.port,
        &owned(&[("x-api-key", &broker.token), ("content-length", "0")]),
        b"",
    );
    assert_eq!(broker.send(&raw).status, 200);
    let got = &destination.wait_for(cases.len() + 1)[cases.len()];
    assert_eq!(got.values("content-length"), vec!["0".to_string()]);
}

#[test]
fn framing_errors_are_refused_with_400_and_the_connection_closed() {
    let ca = TestCa::new();
    let broker =
        Broker::start(Options::nowhere(&ca).admit(Admit::Refuse(AdmissionRefusal::Exhausted)));
    let port = broker.port;
    let token = broker.token.clone();
    let key = format!("x-api-key: {token}\r\n");
    let host = format!("host: 127.0.0.1:{port}\r\n");
    let cases: Vec<(&str, String)> = vec![
        (
            "absolute form",
            format!("GET http://127.0.0.1:{port}/v1/models HTTP/1.1\r\n{host}{key}\r\n"),
        ),
        (
            "absolute form elsewhere",
            format!("GET https://api.anthropic.com/v1/models HTTP/1.1\r\n{host}{key}\r\n"),
        ),
        ("asterisk", format!("GET * HTTP/1.1\r\n{host}{key}\r\n")),
        ("no host", format!("GET /v1/models HTTP/1.1\r\n{key}\r\n")),
        (
            "localhost",
            format!("GET /v1/models HTTP/1.1\r\nhost: localhost:{port}\r\n{key}\r\n"),
        ),
        (
            "another port",
            format!(
                "GET /v1/models HTTP/1.1\r\nhost: 127.0.0.1:{}\r\n{key}\r\n",
                port.wrapping_add(1)
            ),
        ),
        (
            "the destination",
            format!("GET /v1/models HTTP/1.1\r\nhost: api.anthropic.com\r\n{key}\r\n"),
        ),
        (
            "no port",
            format!("GET /v1/models HTTP/1.1\r\nhost: 127.0.0.1\r\n{key}\r\n"),
        ),
        (
            "two hosts",
            format!("GET /v1/models HTTP/1.1\r\n{host}{host}{key}\r\n"),
        ),
        (
            "origin",
            format!("GET /v1/models HTTP/1.1\r\n{host}{key}origin: https://evil.example\r\n\r\n"),
        ),
        (
            "connect",
            format!(
                "CONNECT api.anthropic.com:443 HTTP/1.1\r\nhost: api.anthropic.com:443\r\n{key}\r\n"
            ),
        ),
        (
            "trace",
            format!("TRACE /v1/models HTTP/1.1\r\n{host}{key}\r\n"),
        ),
        (
            "options",
            format!("OPTIONS /v1/messages HTTP/1.1\r\n{host}{key}\r\n"),
        ),
        (
            "options *",
            format!("OPTIONS * HTTP/1.1\r\n{host}{key}\r\n"),
        ),
        (
            "websocket",
            format!(
                "GET /v1/models HTTP/1.1\r\n{host}{key}connection: upgrade\r\nupgrade: websocket\r\n\r\n"
            ),
        ),
        (
            "h2c",
            format!("GET /v1/models HTTP/1.1\r\n{host}{key}upgrade: h2c\r\n\r\n"),
        ),
        (
            "chunked",
            format!(
                "POST /v1/messages HTTP/1.1\r\n{host}{key}transfer-encoding: chunked\r\n\r\n2\r\n{{}}\r\n0\r\n\r\n"
            ),
        ),
        (
            "chunked with a length",
            format!(
                "POST /v1/messages HTTP/1.1\r\n{host}{key}content-length: 2\r\ntransfer-encoding: chunked\r\n\r\n{{}}"
            ),
        ),
        (
            "a length then chunked",
            format!(
                "POST /v1/messages HTTP/1.1\r\n{host}{key}transfer-encoding: chunked\r\ncontent-length: 2\r\n\r\n{{}}"
            ),
        ),
        (
            "connection naming a forwarded header",
            format!("GET /v1/models HTTP/1.1\r\n{host}{key}connection: content-type\r\n\r\n"),
        ),
        (
            "connection naming the token header",
            format!("GET /v1/models HTTP/1.1\r\n{host}{key}connection: close, x-api-key\r\n\r\n"),
        ),
    ];
    for (why, raw) in &cases {
        let mut client = broker.connect();
        client.write(raw.as_bytes());
        let response = client.response();
        response.assert_local(400);
        assert_eq!(response.header("connection"), Some("close"), "{why}");
        assert!(
            client.closed_within(Duration::from_secs(5)),
            "{why}: left open"
        );
    }
    // HTTP/1.0 is another version.
    let response = broker.send(format!("GET /v1/models HTTP/1.0\r\n{host}{key}\r\n").as_bytes());
    response.assert_local(505);
    assert_eq!(broker.admits(), 0, "nothing was asked");
}

#[test]
fn malformed_messages_are_refused_by_the_http_library() {
    let ca = TestCa::new();
    let broker =
        Broker::start(Options::nowhere(&ca).admit(Admit::Refuse(AdmissionRefusal::Exhausted)));
    let port = broker.port;
    let key = format!("x-api-key: {}\r\n", broker.token);
    let host = format!("host: 127.0.0.1:{port}\r\n");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "conflicting lengths",
            format!("POST /v1/messages HTTP/1.1\r\n{host}{key}content-length: 2\r\ncontent-length: 3\r\n\r\n{{}}")
                .into_bytes(),
        ),
        (
            "a length that is not a number",
            format!("POST /v1/messages HTTP/1.1\r\n{host}{key}content-length: +2\r\n\r\n{{}}")
                .into_bytes(),
        ),
        (
            "a folded line",
            format!("GET /v1/models HTTP/1.1\r\n{host}{key}x-stainless-lang: a\r\n b\r\n\r\n")
                .into_bytes(),
        ),
        (
            "a space before the colon",
            format!("GET /v1/models HTTP/1.1\r\n{host}{key}accept : */*\r\n\r\n").into_bytes(),
        ),
        ("garbage", b"\x16\x03\x01\x02\x00 hello\r\n\r\n".to_vec()),
        (
            "a target that is not ASCII",
            [
                b"GET /v1/models/\xc3\xa9 HTTP/1.1\r\n".as_slice(),
                host.as_bytes(),
                key.as_bytes(),
                b"\r\n",
            ]
            .concat(),
        ),
        (
            "a control character in a value",
            format!("GET /v1/models HTTP/1.1\r\n{host}{key}accept: a\x01b\r\n\r\n").into_bytes(),
        ),
    ];
    for (why, raw) in &cases {
        let mut client = broker.connect();
        client.write(raw);
        let response = client.response();
        assert_eq!(response.status, 400, "{why}: {response:?}");
        assert!(
            client.closed_within(Duration::from_secs(5)),
            "{why}: left open"
        );
    }
    assert_eq!(broker.admits(), 0, "nothing was asked");
    // Each counted as refused before admission.
    broker.revoke(EndReason::Revoked);
    assert_eq!(broker.wait_revoked(), cases.len() as u64);
}

#[test]
fn oversized_heads_and_bodies_are_refused() {
    let ca = TestCa::new();
    let broker = Broker::start(Options::nowhere(&ca).admit(Admit::Manual));
    // A head over 32 KiB: 431, from the HTTP library.
    let big = "a".repeat(33 * 1024);
    let mut client = broker.connect();
    client.write(&broker.request("GET", "/v1/models", &[("x-stainless-pad", &big)], b""));
    assert_eq!(client.response().status, 431);
    // A body over 16 MiB: 413 from its declared length, before any of it
    // is read (none is sent here).
    let mut client = broker.connect();
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: 127.0.0.1:{}\r\nx-api-key: {}\r\ncontent-length: {}\r\n\r\n",
        broker.port,
        broker.token,
        16 * 1024 * 1024 + 1
    );
    client.write(head.as_bytes());
    let response = client.response();
    response.assert_local(413);
    assert_eq!(response.header("connection"), Some("close"));
    assert_eq!(broker.admits(), 0, "nothing was asked");
    // Exactly 16 MiB is asked for.
    let mut client = broker.connect();
    client.write(head.replace("16777217", "16777216").as_bytes());
    broker.wait_admit(1);
    broker.refused(1, AdmissionRefusal::Exhausted);
    client.response().assert_local(403);
}

#[test]
fn identical_duplicate_lengths_are_one_length() {
    let ca = TestCa::new();
    let broker = Broker::start(Options::nowhere(&ca).admit(Admit::Manual));
    let mut client = broker.connect();
    client.write(
        format!(
            "POST /v1/messages HTTP/1.1\r\nhost: 127.0.0.1:{}\r\nx-api-key: {}\r\ncontent-length: 2\r\ncontent-length: 2\r\n\r\n{{}}",
            broker.port, broker.token
        )
        .as_bytes(),
    );
    broker.wait_admit(1);
    broker.refused(1, AdmissionRefusal::Exhausted);
    client.response().assert_local(403);
}

// ===== Limits =====

#[test]
fn the_body_budget_holds_and_refusals_give_it_back() {
    let ca = TestCa::new();
    let broker = Broker::start(Options::nowhere(&ca).admit(Admit::Manual));
    let head = |length: usize| {
        format!(
            "POST /v1/messages HTTP/1.1\r\nhost: 127.0.0.1:{}\r\nx-api-key: {}\r\ncontent-length: {length}\r\n\r\n",
            broker.port, broker.token
        )
    };
    // Four bodies of 16 MiB fill the 64 MiB; nothing of them is read yet.
    let mut held = Vec::new();
    for n in 1..=4 {
        let mut client = broker.connect();
        client.write(head(16 * 1024 * 1024).as_bytes());
        broker.wait_admit(n);
        held.push(client);
    }
    // One byte more does not fit: 503, retry after a second, not asked.
    let response = broker.send(head(1).as_bytes());
    response.assert_local(503);
    assert_eq!(response.header("retry-after"), Some("1"));
    assert_eq!(broker.admits(), 4);
    // A body that the agent refuses is given back.
    broker.refused(1, AdmissionRefusal::TooManyInFlight);
    held[0].response().assert_local(429);
    let mut client = broker.connect();
    client.write(head(1).as_bytes());
    broker.wait_admit(5);
    for n in 2..=5 {
        broker.refused(n, AdmissionRefusal::Exhausted);
    }
    client.response().assert_local(403);
}

/// The largest request body: 16 MiB.
#[cfg(feature = "test-upstream")]
const LARGEST_BODY: usize = 16 * 1024 * 1024;

/// The head of a request for `/v1/messages` that declares the largest body.
#[cfg(feature = "test-upstream")]
fn largest_head(broker: &Broker) -> Vec<u8> {
    format!(
        "POST /v1/messages HTTP/1.1\r\nhost: 127.0.0.1:{}\r\nx-api-key: {}\r\ncontent-length: {LARGEST_BODY}\r\n\r\n",
        broker.port, broker.token
    )
    .into_bytes()
}

/// Send four requests of 16 MiB, which fill the 64 MiB budget, to
/// `destination`; `sent` runs on each once it reached the destination.
/// While the broker may still hold any of the bodies, a fifth request does
/// not fit: `503`, retry after a second, not asked.
#[cfg(feature = "test-upstream")]
fn fill_the_budget(
    broker: &Broker,
    destination: &Destination,
    sent: impl Fn(&mut Client),
) -> Vec<Client> {
    let body = vec![b'x'; LARGEST_BODY];
    let request = broker.request("POST", "/v1/messages", &[], &body);
    let mut held = Vec::new();
    for n in 1..=4 {
        let mut client = broker.connect();
        client.write(&request);
        destination.wait_for(n);
        sent(&mut client);
        held.push(client);
    }
    let mut fifth = broker.connect();
    fifth.write(&largest_head(broker));
    // Answered at once; let in, it would wait for its body instead.
    fifth
        .stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    assert!(
        matches!(fifth.stream.peek(&mut [0u8; 1]), Ok(1)),
        "a fifth body was let in: {} asked",
        broker.admits()
    );
    let response = fifth.response();
    response.assert_local(503);
    assert_eq!(response.header("retry-after"), Some("1"));
    assert_eq!(broker.admits(), 4);
    held
}

/// Once the four requests have ended, their room has come back: a request
/// of 16 MiB is asked for.
#[cfg(feature = "test-upstream")]
fn assert_the_room_came_back(broker: &Broker) {
    for request in 1..=4 {
        broker.wait_finished(request);
    }
    let mut client = broker.connect();
    client.write(&largest_head(broker));
    broker.wait_admit(5);
}

#[cfg(feature = "test-upstream")]
#[test]
fn bodies_a_destination_does_not_read_keep_their_room() {
    use std::sync::Arc;
    let ca = TestCa::new();
    // It reads each head, then neither reads nor answers.
    let (release, wait) = signal();
    let destination = Destination::head_only(
        &ca,
        Arc::new(move |_, _| {
            let _ = wait.lock().expect("lock").recv_timeout(PATIENCE);
        }),
    );
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let _held = fill_the_budget(&broker, &destination, |_| {});
    drop(release);
    assert_the_room_came_back(&broker);
}

#[cfg(feature = "test-upstream")]
#[test]
fn bodies_keep_their_room_until_the_destination_answers() {
    use std::sync::Arc;
    let ca = TestCa::new();
    // It reads each body whole, then does not answer: the broker holds none
    // of the bytes, and keeps the room until the answer.
    let (release, wait) = signal();
    let destination = Destination::new(
        &ca,
        Arc::new(move |_, _| {
            let _ = wait.lock().expect("lock").recv_timeout(PATIENCE);
        }),
    );
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let _held = fill_the_budget(&broker, &destination, |_| {});
    drop(release);
    assert_the_room_came_back(&broker);
}

#[cfg(feature = "test-upstream")]
#[test]
fn bodies_the_broker_has_not_written_keep_their_room_after_the_answer() {
    use std::sync::Arc;
    // The broker's send buffer must hold much less than a body, for most of
    // it to stay with the broker (Linux's default largest is 4 MiB).
    if largest_send_buffer().is_none_or(|largest| largest > LARGEST_BODY / 2) {
        eprintln!("skipped: the kernel's send buffers may hold a whole body");
        return;
    }
    let ca = TestCa::new();
    // It reads each head, answers at once with the start of a stream, and
    // reads nothing more.
    let (release, wait) = signal();
    let destination = Destination::head_only(
        &ca,
        Arc::new(move |_, peer| {
            let _ = peer.send(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
            let _ = peer.chunk(b"data: 1\n\n");
            let _ = wait.lock().expect("lock").recv_timeout(PATIENCE);
        }),
    );
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let _held = fill_the_budget(&broker, &destination, |client| {
        // The answer reached the client: the broker has the head.
        assert_eq!(client.head().0, 200);
        assert_eq!(client.chunk().as_deref(), Some(&b"data: 1\n\n"[..]));
    });
    drop(release);
    assert_the_room_came_back(&broker);
}

#[test]
fn connections_beyond_the_limit_are_closed_at_once() {
    let ca = TestCa::new();
    let mut options = Options::nowhere(&ca).admit(Admit::Refuse(AdmissionRefusal::Exhausted));
    options.max_connections = 2;
    let broker = Broker::start(options);
    let mut first = broker.connect();
    let mut second = broker.connect();
    // Both are served (the requests make sure both were accepted).
    for client in [&mut first, &mut second] {
        client.write(&broker.request("GET", "/v1/models", &[], b""));
        client.response().assert_local(403);
    }
    let mut third = broker.connect();
    assert!(
        third.closed_within(Duration::from_secs(5)),
        "a third connection"
    );
    // Once one ends, another is served.
    drop(first);
    let deadline = Instant::now() + PATIENCE;
    loop {
        let mut client = broker.connect();
        if client.try_write(&broker.request("GET", "/v1/models", &[], b""))
            && !client.closed_within(Duration::from_millis(500))
        {
            client.response().assert_local(403);
            break;
        }
        assert!(Instant::now() < deadline, "no connection served again");
    }
}

#[test]
fn requests_beyond_the_in_flight_limit_get_429() {
    let ca = TestCa::new();
    let mut options = Options::nowhere(&ca).admit(Admit::Manual);
    options.max_in_flight = 2;
    let broker = Broker::start(options);
    let mut waiting = Vec::new();
    for n in 1..=2 {
        let mut client = broker.connect();
        client.write(&broker.request("GET", "/v1/models", &[], b""));
        broker.wait_admit(n);
        waiting.push(client);
    }
    let response = broker.send(&broker.request("GET", "/v1/models", &[], b""));
    response.assert_local(429);
    assert_eq!(response.header("retry-after"), Some("1"));
    assert_eq!(broker.admits(), 2);
    // A refusal frees its slot.
    broker.refused(1, AdmissionRefusal::Exhausted);
    waiting[0].response().assert_local(403);
    let mut client = broker.connect();
    client.write(&broker.request("GET", "/v1/models", &[], b""));
    broker.wait_admit(3);
    broker.refused(2, AdmissionRefusal::Exhausted);
    broker.refused(3, AdmissionRefusal::Exhausted);
    client.response().assert_local(403);
}

#[test]
fn refused_admissions_are_answered_locally() {
    let ca = TestCa::new();
    let broker = Broker::start(Options::nowhere(&ca).admit(Admit::Manual));
    let cases = [
        (AdmissionRefusal::Revoked, 403, None),
        (AdmissionRefusal::Expired, 403, None),
        (AdmissionRefusal::Exhausted, 403, None),
        (AdmissionRefusal::TooManyInFlight, 429, Some("1")),
        (AdmissionRefusal::AuditFailed, 503, None),
    ];
    for (n, (reason, status, retry_after)) in cases.into_iter().enumerate() {
        let request = n as u64 + 1;
        let mut client = broker.connect();
        client.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
        broker.wait_admit(request);
        broker.refused(request, reason);
        let response = client.response();
        response.assert_local(status);
        assert_eq!(response.header("retry-after"), retry_after, "{reason:?}");
        // The body was never read: the connection closes.
        assert_eq!(response.header("connection"), Some("close"), "{reason:?}");
    }
    // A refused request never finishes.
    assert!(
        !broker
            .messages()
            .iter()
            .any(|m| matches!(m, FromBroker::Finished { .. })),
        "{:?}",
        broker.messages()
    );
}

#[test]
fn a_grant_past_its_lifetime_refuses_new_requests() {
    let ca = TestCa::new();
    let mut options = Options::nowhere(&ca);
    options.lifetime_secs = 1;
    let broker = Broker::start(options);
    let left = Duration::from_millis(1300).saturating_sub(broker.started.elapsed());
    std::thread::sleep(left);
    broker
        .send(&broker.request("GET", "/v1/models", &[], b""))
        .assert_local(403);
    assert_eq!(broker.admits(), 0);
}

// ===== Revocation =====

#[test]
fn an_admission_answered_after_revoke_is_not_forwarded() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(Options::new(&destination.origin(), &ca).admit(Admit::Manual));
    let mut client = broker.connect();
    client.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    broker.wait_admit(1);
    broker.revoke(EndReason::Locked);
    // Not confirmed while the admission is unanswered.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !broker
            .messages()
            .iter()
            .any(|m| matches!(m, FromBroker::Revoked { .. })),
        "{:?}",
        broker.messages()
    );
    broker.admitted(1);
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::Revoked,
            status: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    );
    assert_eq!(broker.wait_revoked(), 0);
    // The open connection was closed, and nothing reached the destination.
    assert!(client.closed_within(Duration::from_secs(5)));
    assert_eq!(destination.connections(), 0);
    // From then on: 403, nothing asked, nothing after `revoked`.
    broker
        .send(&broker.request("POST", "/v1/messages", &[], b"{}"))
        .assert_local(403);
    std::thread::sleep(Duration::from_millis(100));
    let messages = broker.messages();
    assert!(
        matches!(messages.last(), Some(FromBroker::Revoked { .. })),
        "{messages:?}"
    );
    assert_eq!(broker.admits(), 1);
}

#[test]
fn a_revocation_with_nothing_open_is_confirmed_with_the_refusals() {
    let ca = TestCa::new();
    let broker =
        Broker::start(Options::nowhere(&ca).admit(Admit::Refuse(AdmissionRefusal::Exhausted)));
    // Refused by the broker before admission: no token, a token in the
    // target, framing, and hyper's own refusal of a malformed head.
    broker
        .send(&raw_request("GET", "/v1/models", broker.port, &[], b""))
        .assert_local(401);
    broker
        .send(&broker.request("GET", &format!("/v1/{}", broker.token), &[], b""))
        .assert_local(401);
    broker
        .send(&broker.request("GET", "/v1/models", &[("origin", "null")], b""))
        .assert_local(400);
    assert_eq!(broker.send(b"NOT HTTP\r\n\r\n").status, 400);
    // Refused by the agent: not counted by the broker.
    broker
        .send(&broker.request("GET", "/v1/models", &[], b""))
        .assert_local(403);
    broker.revoke(EndReason::Revoked);
    assert_eq!(broker.wait_revoked(), 4);
    broker
        .send(&broker.request("GET", "/v1/models", &[], b""))
        .assert_local(403);
    assert_eq!(broker.admits(), 1);
}

// ===== Failures =====

/// The ways a broker can fail before `ready`: each ends it with status 1
/// and nothing answered.
fn assert_refused_install(mut process: Process, why: &str) {
    let status = process
        .exit_within(Duration::from_secs(10))
        .unwrap_or_else(|| panic!("{why}: still running"));
    assert_eq!(status.code(), Some(1), "{why}: {status:?}");
    assert!(
        process.read(Duration::from_secs(1)).is_err(),
        "{why}: answered"
    );
    let said = process.stderr();
    assert!(!said.contains(CREDENTIAL), "{why}: {said}");
}

fn install_env(ca: &TestCa) -> Vec<(String, String)> {
    Options::nowhere(ca).env
}

#[test]
fn a_broker_whose_channel_closes_before_the_install_exits_without_answering() {
    let ca = TestCa::new();
    let process = Process::spawn(&install_env(&ca));
    let _ = process.agent.shutdown(std::net::Shutdown::Both);
    assert_refused_install(process, "no install");
}

#[test]
fn installs_without_exactly_one_listening_socket_are_refused() {
    let ca = TestCa::new();
    let options = Options::nowhere(&ca);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let other = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let connected =
        std::net::TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp");
    let everywhere = std::net::TcpListener::bind("0.0.0.0:0").expect("bind");
    let ipv6 = std::net::TcpListener::bind("[::1]:0").ok();
    let dir = tempfile::tempdir().expect("tempdir");
    let unix = std::os::unix::net::UnixListener::bind(dir.path().join("s")).expect("unix");
    let (pipe, _writer) = nix::unistd::pipe().expect("pipe");
    use std::os::fd::AsFd;
    let mut cases: Vec<(&str, Vec<std::os::fd::BorrowedFd<'_>>)> = vec![
        ("no descriptor", vec![]),
        ("two descriptors", vec![listener.as_fd(), other.as_fd()]),
        ("a connected socket", vec![connected.as_fd()]),
        ("a datagram socket", vec![udp.as_fd()]),
        ("every address", vec![everywhere.as_fd()]),
        ("a Unix socket", vec![unix.as_fd()]),
        ("a pipe", vec![pipe.as_fd()]),
    ];
    if let Some(ipv6) = &ipv6 {
        cases.push(("IPv6 loopback", vec![ipv6.as_fd()]));
    }
    for (why, fds) in cases {
        let process = Process::spawn(&options.env);
        process.send(
            &rusthorse::broker_protocol::ToBroker::Install(options.install()),
            &fds,
        );
        assert_refused_install(process, why);
    }
}

#[test]
fn bad_installs_are_refused() {
    use rusthorse::broker_protocol::{Install, ToBroker};
    use rusthorse::protocol::SecretString;
    let ca = TestCa::new();
    let options = Options::nowhere(&ca);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    use std::os::fd::AsFd;
    type Spoil = fn(&mut Install);
    let cases: &[(&str, Spoil)] = &[
        ("version 1", |i| i.version = 1),
        ("another version", |i| i.version += 1),
        ("a malformed grant", |i| i.grant = "g1".into()),
        ("a malformed token", |i| {
            i.token = SecretString::new("rh_1".into())
        }),
        ("an uppercase token", |i| {
            i.token = SecretString::new(i.token.to_uppercase())
        }),
        ("a short credential", |i| {
            i.credential = SecretString::new("sk-1234".into())
        }),
        ("a credential with a line break", |i| {
            i.credential = SecretString::new("sk-ant-test\r\nx-evil: 1".into())
        }),
        ("an origin over http", |i| {
            i.origin = "http://localhost:9".into()
        }),
        ("an origin with a path", |i| {
            i.origin = "https://localhost:9/v1".into()
        }),
        ("an origin with user information", |i| {
            i.origin = "https://user@localhost:9".into()
        }),
        ("an IP address", |i| i.origin = "https://127.0.0.1:9".into()),
        ("an uppercase host", |i| {
            i.origin = "https://LOCALHOST:9".into()
        }),
        ("no origin", |i| i.origin = String::new()),
        ("no requests in flight", |i| i.max_in_flight = 0),
        ("too many connections", |i| i.max_connections = 65),
        ("a lifetime longer than a day", |i| {
            i.lifetime_secs = 24 * 60 * 60 + 1
        }),
    ];
    for (why, spoil) in cases {
        let mut install = options.install();
        spoil(&mut install);
        let process = Process::spawn(&options.env);
        process.send(&ToBroker::Install(install), &[listener.as_fd()]);
        assert_refused_install(process, why);
    }
}

/// An install of control channel 1, which carried a profile, or of
/// channel 2 with a profile in it, is refused: the broker serves nothing
/// and answers nothing.
#[test]
fn installs_of_phase_1_or_with_a_profile_are_refused() {
    use rusthorse::broker_protocol::{self, ToBroker};
    use std::os::fd::AsFd;
    let ca = TestCa::new();
    let options = Options::nowhere(&ca);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let install = serde_json::to_value(ToBroker::Install(options.install())).expect("json");
    assert_eq!(install["version"], 2);
    let profile = serde_json::json!({
        "version": 1,
        "preset": "anthropic",
        "revision": 1,
        "origin": "https://localhost:9",
        "base_path": "",
        "automatic_locks": "continue",
        "max_lifetime_minutes": 720,
    });
    let mut with_profile = install.clone();
    with_profile["profile"] = profile.clone();
    let mut phase_1 = install.clone();
    phase_1["version"] = 1.into();
    phase_1["profile"] = profile;
    phase_1.as_object_mut().expect("object").remove("origin");
    let mut version_1 = install.clone();
    version_1["version"] = 1.into();
    for (why, message) in [
        ("a profile beside the origin", with_profile),
        ("phase 1's install", phase_1),
        ("version 1", version_1),
    ] {
        let process = Process::spawn(&options.env);
        broker_protocol::write_message(&process.agent, &message, &[listener.as_fd()])
            .expect("send");
        assert_refused_install(process, why);
    }
    // The same install, as it is, is served.
    let process = Process::spawn(&options.env);
    broker_protocol::write_message(&process.agent, &install, &[listener.as_fd()]).expect("send");
    assert!(matches!(
        process.read(PATIENCE),
        Ok(FromBroker::Ready { version: 2, .. })
    ));
}

#[test]
fn garbage_before_the_install_is_refused() {
    use rusthorse::broker_protocol::ToBroker;
    use std::io::Write;
    let ca = TestCa::new();
    let env = install_env(&ca);
    // A length larger than a frame (the first four bytes of "hello").
    let process = Process::spawn(&env);
    (&process.agent).write_all(b"hello world").expect("write");
    assert_refused_install(process, "a frame too large");
    // A frame that is not JSON.
    let process = Process::spawn(&env);
    (&process.agent)
        .write_all(&[0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'])
        .expect("write");
    assert_refused_install(process, "not JSON");
    // A message that is not an install.
    let process = Process::spawn(&env);
    process.send(&ToBroker::Admitted { request: 1 }, &[]);
    assert_refused_install(process, "not an install");
    // Half a frame, then nothing.
    let process = Process::spawn(&env);
    (&process.agent).write_all(&[0, 0, 1]).expect("write");
    let _ = process.agent.shutdown(std::net::Shutdown::Write);
    assert_refused_install(process, "half a frame");
}

#[cfg(feature = "test-upstream")]
#[test]
fn an_install_that_does_not_arrive_in_time_is_refused() {
    let ca = TestCa::new();
    let mut env = install_env(&ca);
    env.push(("RUSTHORSE_BROKER_TEST_TIMEOUTS".into(), "ready=300".into()));
    let started = Instant::now();
    let process = Process::spawn(&env);
    assert_refused_install(process, "no install in time");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn unexpected_messages_from_the_agent_end_the_broker() {
    use rusthorse::broker_protocol::ToBroker;
    use std::io::Write;
    let ca = TestCa::new();
    type Break = fn(&Broker);
    let cases: &[(&str, Break)] = &[
        ("a second install", |b| {
            b.tell(&ToBroker::Install(
                Options::nowhere(&TestCa::new()).install(),
            ))
        }),
        ("an answer for a request never asked", |b| b.admitted(7)),
        ("a refusal for a request never asked", |b| {
            b.refused(1, AdmissionRefusal::Exhausted)
        }),
        ("a second revoke", |b| {
            b.revoke(EndReason::Locked);
            b.revoke(EndReason::Locked);
        }),
        ("an answer after revoked", |b| {
            b.revoke(EndReason::Locked);
            b.wait_revoked();
            b.admitted(1);
        }),
        ("a frame too large", |b| {
            let stream = b.raw_channel();
            (&stream)
                .write_all(&[0xff, 0xff, 0xff, 0xff])
                .expect("write");
        }),
        ("a frame that is not JSON", |b| {
            let stream = b.raw_channel();
            (&stream)
                .write_all(&[0, 0, 0, 2, b'{', b'x'])
                .expect("write");
        }),
        ("an unknown message", |b| {
            let stream = b.raw_channel();
            let body = br#"{"type":"unlock"}"#;
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(body);
            (&stream).write_all(&frame).expect("write");
        }),
    ];
    for (why, act) in cases {
        let mut broker = Broker::start(Options::nowhere(&ca));
        act(&broker);
        let status = broker
            .exit_within(Duration::from_secs(5))
            .unwrap_or_else(|| panic!("{why}: still running"));
        assert_eq!(status.code(), Some(3), "{why}: {status:?}");
    }
    // An answer given twice, too.
    let mut broker = Broker::start(Options::nowhere(&ca).admit(Admit::Manual));
    let mut client = broker.connect();
    client.write(&broker.request("GET", "/v1/models", &[], b""));
    broker.wait_admit(1);
    broker.refused(1, AdmissionRefusal::Exhausted);
    broker.refused(1, AdmissionRefusal::Exhausted);
    let status = broker.exit_within(Duration::from_secs(5)).expect("exits");
    assert_eq!(status.code(), Some(3), "{status:?}");
}

// ===== The destination =====

/// The destination's response headers reach the client, but the hop-by-hop
/// ones, its framing, and any that carries the key, in any case, or a
/// token-shaped string — the grant's token or another, in a name or a
/// value; the body goes out chunked whatever framing it came with.
#[cfg(feature = "test-upstream")]
#[test]
fn response_headers_are_relayed_but_their_framing_and_any_secret() {
    use std::sync::Arc;
    let ca = TestCa::new();
    let mut options = Options::nowhere(&ca);
    let token = options.token.clone();
    let handler: Handler = Arc::new(move |_, peer| {
        let head = format!(
            "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\nlocation: /v1/files/f_1\r\n\
             set-cookie: a=b\r\nwww-authenticate: Bearer\r\nx-ratelimit-remaining: 9\r\n\
             connection: keep-alive\r\nkeep-alive: timeout=5\r\nproxy-authenticate: Basic\r\n\
             trailer: x-sum\r\nx-key: {CREDENTIAL}\r\nx-key-lower: k {}\r\n\
             x-token: Bearer {token}\r\nx-token-upper: {}\r\nx-other: {}\r\nx-{token}: 1\r\n\
             content-length: 2\r\n\r\n{{}}",
            CREDENTIAL.to_lowercase(),
            token.to_uppercase(),
            foreign_token(),
        );
        let _ = peer.send(head.as_bytes());
    });
    let destination = Destination::new(&ca, handler);
    options.origin = destination.origin();
    let broker = Broker::start(options);
    let response = broker.send(&broker.request("POST", "/v1/files", &[], b"{}"));
    assert_eq!(response.status, 201, "{response:?}");
    assert_eq!(response.body, b"{}");
    assert!(response.complete);
    // Those of the destination, and the broker's own framing (hyper adds
    // its `date` when the destination's is not there).
    let mut relayed: Vec<String> = response
        .headers
        .iter()
        .map(|(n, v)| format!("{}: {v}", n.to_ascii_lowercase()))
        .filter(|line| !line.starts_with("date: "))
        .collect();
    relayed.sort();
    assert_eq!(
        relayed,
        vec![
            "content-type: application/json",
            "location: /v1/files/f_1",
            "set-cookie: a=b",
            "transfer-encoding: chunked",
            "www-authenticate: Bearer",
            "x-ratelimit-remaining: 9",
        ]
    );
}

#[cfg(feature = "test-upstream")]
#[test]
fn the_token_never_leaves_in_a_header() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let token = broker.token.clone();
    // Where it may be, it is replaced; anywhere else, the request is
    // refused and nothing is sent.
    let response = broker.send(&broker.request(
        "GET",
        "/v1/models",
        &[
            ("user-agent", &format!("agent/1 {token}")),
            ("accept", "application/json"),
        ],
        b"",
    ));
    assert_eq!(response.status, 200, "{response:?}");
    for refused in [
        broker.request(
            "GET",
            "/v1/models",
            &[(&format!("x-stainless-{token}"), "1")],
            b"",
        ),
        broker.request(
            "GET",
            "/v1/models",
            &[("x-stainless-arch", &token.to_uppercase())],
            b"",
        ),
        broker.request("GET", "/v1/models", &[("keep-alive", &token)], b""),
        broker.request("GET", &format!("/v1/models?t={token}"), &[], b""),
    ] {
        broker.send(&refused).assert_local(401);
    }
    let received = destination.received();
    assert_eq!(received.len(), 1);
    let got = &received[0];
    let head = got.head_text().to_ascii_lowercase();
    assert!(!head.contains(&token), "{head}");
    assert_eq!(got.values("x-api-key"), vec![CREDENTIAL.to_string()]);
    assert_eq!(
        got.values("user-agent"),
        vec![format!("agent/1 {CREDENTIAL}")]
    );
    assert_eq!(got.values("accept"), vec!["application/json".to_string()]);
    // A GET without a body has no length.
    assert!(got.values("content-length").is_empty());
    assert!(got.body.is_empty());
}

#[cfg(feature = "test-upstream")]
#[test]
fn the_proxy_and_certificate_variables_have_no_effect() {
    let ca = TestCa::new();
    let other = TestCa::new();
    let proxy = Counter::new();
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
    let with_variables = |options: Options| {
        let mut options = options;
        for name in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            options = options.env(name, &proxy_url);
        }
        options
            .env("NO_PROXY", "")
            .env("SSL_CERT_FILE", &other.roots().display().to_string())
            .env(
                "SSL_CERT_DIR",
                &other.roots().parent().expect("dir").display().to_string(),
            )
            .env("RUSTHORSE_SOCKET", "/nonexistent/agent.sock")
            .env("RUSTHORSE_VAULT", "/nonexistent/vault.kdbx")
    };
    // Trusted through the test's own variable: reached directly.
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(with_variables(Options::new(&destination.origin(), &ca)));
    let response = broker.send(&broker.request("GET", "/v1/models", &[], b""));
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(destination.received().len(), 1);
    assert_eq!(proxy.count(), 0, "the proxy was used");
    // Signed by the authority SSL_CERT_FILE names: not trusted.
    let elsewhere = Destination::new(&other, answer(200, &[], b"{}"));
    let broker = Broker::start(with_variables(Options::new(&elsewhere.origin(), &ca)));
    broker
        .send(&broker.request("GET", "/v1/models", &[], b""))
        .assert_unreachable();
    assert!(elsewhere.received().is_empty());
    assert_eq!(proxy.count(), 0, "the proxy was used");
}

#[cfg(feature = "test-upstream")]
#[test]
fn private_addresses_are_refused() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    // The destination's own address, as an IPv4-mapped IPv6 address: it
    // would reach it, but it is not public.
    for addresses in [
        "::ffff:127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "fd00::1",
        "0.0.0.0",
    ] {
        let options = Options::new(&destination.origin(), &ca)
            .env("RUSTHORSE_BROKER_TEST_ADDRESSES", addresses)
            .timeouts("connect=3000");
        let broker = Broker::start(options);
        let started = Instant::now();
        broker
            .send(&broker.request("GET", "/v1/models", &[], b""))
            .assert_unreachable();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{addresses}: {:?}",
            started.elapsed()
        );
        assert_eq!(
            broker.wait_finished(1),
            FromBroker::Finished {
                request: 1,
                outcome: RequestOutcome::NotForwarded,
                status: Some(502),
                bytes_sent: 0,
                bytes_received: 0,
            },
            "{addresses}"
        );
    }
    assert_eq!(destination.connections(), 0);
    // Each address is checked: with a loopback one too (allowed for tests),
    // only that one is used.
    let broker = Broker::start(Options::new(&destination.origin(), &ca).env(
        "RUSTHORSE_BROKER_TEST_ADDRESSES",
        "::ffff:127.0.0.1,127.0.0.1",
    ));
    let response = broker.send(&broker.request("GET", "/v1/models", &[], b""));
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(destination.connections(), 1);
}

#[cfg(feature = "test-upstream")]
#[test]
fn the_system_resolver_is_used_when_no_address_is_fixed() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    // localhost resolves to loopback addresses, allowed for tests; the
    // destination listens on 127.0.0.1 only.
    let broker = Broker::start(
        Options::new(&destination.origin(), &ca).without_env("RUSTHORSE_BROKER_TEST_ADDRESSES"),
    );
    let response = broker.send(&broker.request("GET", "/v1/models", &[], b""));
    assert_eq!(response.status, 200, "{response:?}");
}

#[cfg(not(feature = "test-upstream"))]
#[test]
fn a_build_without_the_test_feature_refuses_a_loopback_destination() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    // The test variables are set, and not read.
    for fixed in [true, false] {
        let mut options = Options::new(&destination.origin(), &ca);
        if !fixed {
            options = options.without_env("RUSTHORSE_BROKER_TEST_ADDRESSES");
        }
        let broker = Broker::start(options);
        broker
            .send(&broker.request("GET", "/v1/models", &[], b""))
            .assert_unreachable();
        assert_eq!(
            broker.wait_finished(1),
            FromBroker::Finished {
                request: 1,
                outcome: RequestOutcome::NotForwarded,
                status: Some(502),
                bytes_sent: 0,
                bytes_received: 0,
            }
        );
    }
    assert_eq!(
        destination.connections(),
        0,
        "a loopback destination was reached"
    );
}

/// The agent starts every broker with an empty environment: a build with
/// the test feature then runs as a release one, and its destination may not
/// be on loopback any more than a release build's.
#[test]
fn a_broker_started_with_an_empty_environment_refuses_a_loopback_destination() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let mut options = Options::new(&destination.origin(), &ca);
    options.env.clear();
    let broker = Broker::start(options);
    // localhost resolves to loopback addresses, on the system's resolver.
    broker
        .send(&broker.request("GET", "/v1/models", &[], b""))
        .assert_unreachable();
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::NotForwarded,
            status: Some(502),
            bytes_sent: 0,
            bytes_received: 0,
        }
    );
    assert_eq!(
        destination.connections(),
        0,
        "a loopback destination was reached"
    );
}

/// Without the test's authority in its environment, a build with the test
/// feature reads none of the other test variables: not those that would
/// stop it, nor a fixed address, nor a panic.
#[cfg(feature = "test-upstream")]
#[test]
fn without_a_test_authority_a_test_build_reads_no_test_variable() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    // Options fix the address 127.0.0.1, which the system's resolver gives
    // too: the address does not matter, loopback does.
    let options = Options::new(&destination.origin(), &ca)
        .without_env("RUSTHORSE_BROKER_TEST_ROOTS")
        .timeouts("nap=1")
        .env("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS", "soon")
        .env("RUSTHORSE_BROKER_TEST_LIFETIME_LAG_MS", "later")
        .env("RUSTHORSE_BROKER_TEST_PANIC", "request");
    assert!(
        options
            .env
            .iter()
            .any(|(name, _)| name == "RUSTHORSE_BROKER_TEST_ADDRESSES")
    );
    let mut broker = Broker::start(options);
    broker
        .send(&broker.request("GET", "/v1/models", &[], b""))
        .assert_unreachable();
    assert!(matches!(
        broker.wait_finished(1),
        FromBroker::Finished {
            outcome: RequestOutcome::NotForwarded,
            status: Some(502),
            ..
        }
    ));
    assert_eq!(destination.connections(), 0);
    assert!(
        broker.exit_within(Duration::from_millis(200)).is_none(),
        "the broker stopped"
    );
}

#[cfg(not(feature = "test-upstream"))]
#[test]
fn a_build_without_the_test_feature_ignores_the_test_variables() {
    // Variables that a build with the feature refuses to start with.
    let ca = TestCa::new();
    let options = Options::nowhere(&ca)
        .timeouts("nap=1")
        .env("RUSTHORSE_BROKER_TEST_ADDRESSES", "not an address")
        .env("RUSTHORSE_BROKER_TEST_ROOTS", "/nonexistent/roots.pem");
    let broker = Broker::start(options);
    broker
        .send(&raw_request("GET", "/v1/models", broker.port, &[], b""))
        .assert_local(401);
}

#[cfg(feature = "test-upstream")]
#[test]
fn test_variables_that_do_not_parse_stop_a_test_build() {
    let ca = TestCa::new();
    for (name, value) in [
        ("RUSTHORSE_BROKER_TEST_TIMEOUTS", "nap=1"),
        ("RUSTHORSE_BROKER_TEST_ADDRESSES", "not an address"),
        ("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS", "soon"),
        ("RUSTHORSE_BROKER_TEST_LIFETIME_LAG_MS", "later"),
        ("RUSTHORSE_BROKER_TEST_ROOTS", "/nonexistent/roots.pem"),
        ("RUSTHORSE_BROKER_TEST_PANIC", "later"),
    ] {
        let options = Options::nowhere(&ca).env(name, value);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let process = Process::spawn(&options.env);
        use std::os::fd::AsFd;
        // The variables are read first: the broker may be gone already.
        let _ = process.try_send(
            &rusthorse::broker_protocol::ToBroker::Install(options.install()),
            &[listener.as_fd()],
        );
        assert_refused_install(process, name);
    }
}

#[cfg(feature = "test-upstream")]
#[test]
fn redirects_reach_the_client_as_502_without_location() {
    let ca = TestCa::new();
    for status in [301, 302, 303, 307, 308] {
        let destination = Destination::new(
            &ca,
            answer(
                status,
                &[("location", "https://evil.example/steal")],
                b"moved: SECRET-BODY",
            ),
        );
        let broker = Broker::start(Options::new(&destination.origin(), &ca));
        let response = broker.send(&broker.request("POST", "/v1/messages", &[], b"{}"));
        response.assert_local(502);
        assert_eq!(response.header("location"), None);
        assert!(!response.text().contains("evil") && !response.text().contains("SECRET-BODY"));
        assert_eq!(
            broker.wait_finished(1),
            FromBroker::Finished {
                request: 1,
                outcome: RequestOutcome::Unknown,
                status: Some(status),
                bytes_sent: 2,
                bytes_received: 0,
            }
        );
        assert_eq!(destination.received().len(), 1, "followed nowhere");
    }
}

#[cfg(feature = "test-upstream")]
#[test]
fn encoded_responses_are_refused_before_anything_reaches_the_client() {
    use std::sync::Arc;
    let ca = TestCa::new();
    let raw = |head: &'static str| -> Handler {
        Arc::new(move |_, peer| {
            let _ = peer.send(head.as_bytes());
        })
    };
    let cases: Vec<(&str, Handler)> = vec![
        (
            "gzip",
            answer(200, &[("content-encoding", "gzip")], b"SECRET-BODY"),
        ),
        (
            "br",
            answer(200, &[("content-encoding", "br")], b"SECRET-BODY"),
        ),
        (
            "identity, gzip",
            answer(
                200,
                &[("content-encoding", "identity, gzip")],
                b"SECRET-BODY",
            ),
        ),
        (
            "identity, then deflate",
            answer(
                200,
                &[
                    ("content-encoding", "identity"),
                    ("content-encoding", "deflate"),
                ],
                b"SECRET-BODY",
            ),
        ),
        (
            "gzip, chunked",
            raw(
                "HTTP/1.1 200 OK\r\ntransfer-encoding: gzip, chunked\r\n\r\nb\r\nSECRET-BODY\r\n0\r\n\r\n",
            ),
        ),
        (
            "gzip",
            raw(
                "HTTP/1.1 200 OK\r\ntransfer-encoding: gzip\r\nconnection: close\r\n\r\nSECRET-BODY",
            ),
        ),
    ];
    for (why, handler) in cases {
        let destination = Destination::new(&ca, handler);
        let broker = Broker::start(Options::new(&destination.origin(), &ca));
        let response = broker.send(&broker.request("POST", "/v1/messages", &[], b"{}"));
        response.assert_local(502);
        assert!(
            !response.text().contains("SECRET-BODY"),
            "{why}: {response:?}"
        );
        assert_eq!(response.header("content-encoding"), None, "{why}");
        assert!(matches!(
            broker.wait_finished(1),
            FromBroker::Finished {
                outcome: RequestOutcome::Unknown,
                status: Some(200),
                ..
            }
        ));
    }
    // Identity, and chunked alone, pass.
    for handler in [
        answer(200, &[("content-encoding", "identity")], b"PLAIN-BODY"),
        raw("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\na\r\nPLAIN-BODY\r\n0\r\n\r\n"),
    ] {
        let destination = Destination::new(&ca, handler);
        let broker = Broker::start(Options::new(&destination.origin(), &ca));
        let response = broker.send(&broker.request("POST", "/v1/messages", &[], b"{}"));
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(response.body, b"PLAIN-BODY");
    }
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_resolution_that_hangs_ends_within_its_deadline() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(
        Options::new(&destination.origin(), &ca)
            .env("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS", "60000")
            .timeouts("connect=500"),
    );
    let started = Instant::now();
    broker
        .send(&broker.request("GET", "/v1/models", &[], b""))
        .assert_unreachable();
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(450) && took < Duration::from_secs(3),
        "{took:?}"
    );
    assert!(matches!(
        broker.wait_finished(1),
        FromBroker::Finished {
            outcome: RequestOutcome::NotForwarded,
            status: Some(502),
            ..
        }
    ));
    assert_eq!(destination.connections(), 0);
}

#[cfg(feature = "test-upstream")]
#[test]
fn the_destination_must_prove_the_origins_host() {
    let ca = TestCa::new();
    let other = TestCa::new();
    let cases = [
        (
            "another name",
            Destination::with_config(
                ca.server_config(&["other.example"], BOTH_VERSIONS),
                answer(200, &[], b"{}"),
            ),
        ),
        (
            "another authority",
            Destination::new(&other, answer(200, &[], b"{}")),
        ),
    ];
    for (why, destination) in &cases {
        let broker = Broker::start(Options::new(&destination.origin(), &ca));
        broker
            .send(&broker.request("GET", "/v1/models", &[], b""))
            .assert_unreachable();
        assert!(destination.received().is_empty(), "{why}");
        assert!(matches!(
            broker.wait_finished(1),
            FromBroker::Finished {
                outcome: RequestOutcome::NotForwarded,
                status: Some(502),
                ..
            }
        ));
    }
}

#[cfg(feature = "test-upstream")]
#[test]
fn destinations_of_tls_1_2_and_1_3_are_reached() {
    let ca = TestCa::new();
    for (version, expected) in [
        (&rustls::version::TLS12, rustls::ProtocolVersion::TLSv1_2),
        (&rustls::version::TLS13, rustls::ProtocolVersion::TLSv1_3),
    ] {
        let destination = Destination::with_config(
            ca.server_config(&["localhost"], &[version]),
            answer(200, &[], b"{}"),
        );
        let broker = Broker::start(Options::new(&destination.origin(), &ca));
        let response = broker.send(&broker.request("GET", "/v1/models", &[], b""));
        assert_eq!(response.status, 200, "{response:?}");
        let got = &destination.wait_for(1)[0];
        assert_eq!(got.tls, Some(expected));
        assert_eq!(got.alpn.as_deref(), Some(&b"http/1.1"[..]));
    }
}

// ===== Redaction and streaming =====

#[cfg(feature = "test-upstream")]
#[test]
fn the_credential_echoed_by_the_destination_is_removed() {
    use std::sync::Arc;
    let ca = TestCa::new();
    let handler: Handler = Arc::new(|_, peer| {
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-request-id: req-{CREDENTIAL}\r\nrequest-id: {}\r\nanthropic-ratelimit-tokens-remaining: 7\r\nretry-after: {}\r\ntransfer-encoding: chunked\r\n\r\n",
            CREDENTIAL.to_ascii_uppercase(),
            &CREDENTIAL[..8],
        );
        let _ = peer.send(head.as_bytes());
        // Split across chunks, and across writes.
        let (a, rest) = CREDENTIAL.split_at(5);
        let (b, c) = rest.split_at(9);
        for piece in [
            format!("{{\"echo\":\"{a}"),
            b.to_string(),
            format!(
                "{c}\",\"twice\":\"{CREDENTIAL}{CREDENTIAL}\",\"start\":\"{}",
                &CREDENTIAL[..12]
            ),
            "\"}".to_string(),
        ] {
            let _ = peer.chunk(piece.as_bytes());
            std::thread::sleep(Duration::from_millis(30));
        }
        let _ = peer.end_chunks();
    });
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let response = broker.send(&broker.request("POST", "/v1/messages", &[], b"{}"));
    assert_eq!(response.status, 200, "{response:?}");
    assert!(response.complete);
    let text = response.text();
    assert!(!text.contains(CREDENTIAL), "{text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("still JSON");
    assert_eq!(json["echo"], "[REDACTED:credential]");
    assert_eq!(json["twice"], "[REDACTED:credential][REDACTED:credential]");
    // A start of the credential alone is not the credential.
    assert_eq!(json["start"], &CREDENTIAL[..12]);
    // Headers that carry it, in any case, are dropped; the others pass.
    assert_eq!(response.header("x-request-id"), None);
    assert_eq!(response.header("request-id"), None);
    assert_eq!(
        response.header("anthropic-ratelimit-tokens-remaining"),
        Some("7")
    );
    assert_eq!(response.header("retry-after"), Some(&CREDENTIAL[..8]));
    let all = format!("{:?}", response.headers).to_ascii_lowercase();
    assert!(!all.contains(&CREDENTIAL.to_ascii_lowercase()), "{all}");
}

#[cfg(feature = "test-upstream")]
#[test]
fn server_sent_events_flow_as_they_arrive() {
    use std::sync::Arc;
    let ca = TestCa::new();
    let (go, wait) = signal();
    let handler: Handler = Arc::new(move |_, peer| {
        let _ = peer.send(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\ntransfer-encoding: chunked\r\n\r\n",
        );
        let _ = peer.chunk(b"event: message_start\ndata: {\"n\":1}\n\n");
        let _ = wait.lock().expect("lock").recv_timeout(PATIENCE);
        let _ = peer.chunk(b"event: message_stop\ndata: {\"n\":2}\n\n");
        let _ = peer.end_chunks();
    });
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let mut client = broker.connect();
    client.write(&broker.request(
        "POST",
        "/v1/messages",
        &[("accept", "text/event-stream")],
        br#"{"stream":true}"#,
    ));
    let (status, headers) = client.head();
    assert_eq!(status, 200);
    assert!(
        headers
            .iter()
            .any(|(n, v)| n == "content-type" && v == "text/event-stream")
    );
    // The first event arrives while the destination still holds the second.
    let mut first = Vec::new();
    while !first.ends_with(b"\n\n") {
        first.extend(client.chunk().expect("the first event"));
    }
    assert_eq!(first, b"event: message_start\ndata: {\"n\":1}\n\n");
    go.send(()).expect("go");
    let mut rest = Vec::new();
    loop {
        let chunk = client.chunk().expect("more");
        if chunk.is_empty() {
            break;
        }
        rest.extend(chunk);
    }
    assert_eq!(rest, b"event: message_stop\ndata: {\"n\":2}\n\n");
    assert!(matches!(
        broker.wait_finished(1),
        FromBroker::Finished {
            outcome: RequestOutcome::Completed,
            status: Some(200),
            bytes_received: 71,
            ..
        }
    ));
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_response_without_a_body_is_passed_on() {
    let ca = TestCa::new();
    let destination = Destination::new(
        &ca,
        std::sync::Arc::new(|_, peer: &mut Peer| {
            let _ = peer.send(b"HTTP/1.1 204 No Content\r\nrequest-id: r1\r\n\r\n");
        }),
    );
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let response = broker.send(&broker.request("POST", "/v1/messages/count_tokens", &[], b"{}"));
    assert_eq!(response.status, 204, "{response:?}");
    assert!(response.body.is_empty());
    assert_eq!(response.header("request-id"), Some("r1"));
    assert!(matches!(
        broker.wait_finished(1),
        FromBroker::Finished {
            outcome: RequestOutcome::Completed,
            status: Some(204),
            ..
        }
    ));
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_response_longer_than_the_limit_is_cut() {
    use std::sync::Arc;
    let ca = TestCa::new();
    let handler: Handler = Arc::new(|_, peer| {
        let _ = peer.send(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
        let block = vec![b'x'; 1024 * 1024];
        for _ in 0..65 {
            if peer.chunk(&block).is_err() {
                return;
            }
        }
        let _ = peer.end_chunks();
    });
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let response = broker.send(&broker.request("GET", "/v1/models", &[], b""));
    assert_eq!(response.status, 200);
    assert!(
        !response.complete,
        "a cut stream ends without its last chunk"
    );
    assert_eq!(response.body.len(), 64 * 1024 * 1024);
    assert!(matches!(
        broker.wait_finished(1),
        FromBroker::Finished {
            outcome: RequestOutcome::Unknown,
            status: Some(200),
            ..
        }
    ));
}

// ===== Revocation of open requests =====

/// A destination that starts a stream, sends `first`, and holds it open
/// until the broker closes the connection; `closed` says it did.
#[cfg(feature = "test-upstream")]
fn holding_stream(
    first: &'static [u8],
) -> (Handler, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let closed = Arc::new(AtomicBool::new(false));
    let seen = closed.clone();
    let handler: Handler = Arc::new(move |_, peer| {
        let _ = peer.send(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
        );
        let _ = peer.chunk(first);
        if peer.closed_within(PATIENCE) {
            seen.store(true, Ordering::SeqCst);
        }
    });
    (handler, closed)
}

#[cfg(feature = "test-upstream")]
#[test]
fn revocation_ends_open_streams_and_then_everything_is_refused() {
    use std::sync::atomic::Ordering;
    let ca = TestCa::new();
    let (handler, closed) = holding_stream(b"data: {\"n\":1}\n\n");
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    broker
        .send(&raw_request("GET", "/v1/files", broker.port, &[], b""))
        .assert_local(401);
    let mut stream = broker.connect();
    stream.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    assert_eq!(stream.head().0, 200);
    assert_eq!(stream.chunk().expect("an event"), b"data: {\"n\":1}\n\n");
    // An idle connection, open too.
    let mut idle = broker.connect();
    idle.write(&raw_request("GET", "/v1/files", broker.port, &[], b""));
    idle.response().assert_local(401);

    broker.revoke(EndReason::EntryChanged);
    let revoked = Instant::now();
    // The stream is cut, the idle connection closed, the destination's
    // connection closed, all at once; the request's end is unknown.
    assert_eq!(stream.chunk(), None, "the stream went on");
    assert!(idle.closed_within(Duration::from_secs(5)));
    assert!(
        revoked.elapsed() < Duration::from_secs(2),
        "{:?}",
        revoked.elapsed()
    );
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::Unknown,
            status: Some(200),
            bytes_sent: 2,
            bytes_received: 15,
        }
    );
    assert_eq!(broker.wait_revoked(), 2);
    let deadline = Instant::now() + PATIENCE;
    while !closed.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < deadline,
            "the destination's connection stayed open"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // Nothing more is forwarded, or asked.
    for _ in 0..3 {
        broker
            .send(&broker.request("POST", "/v1/messages", &[], b"{}"))
            .assert_local(403);
    }
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(destination.received().len(), 1);
    assert_eq!(broker.admits(), 1);
    assert!(matches!(
        broker.messages().last(),
        Some(FromBroker::Revoked { .. })
    ));
}

#[cfg(feature = "test-upstream")]
#[test]
fn revocation_is_confirmed_once_every_admission_is_answered_and_every_request_ended() {
    let ca = TestCa::new();
    let (handler, _closed) = holding_stream(b"data: 1\n\n");
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca).admit(Admit::Manual));
    // Request 1 streams; request 2 waits for its admission.
    let mut first = broker.connect();
    first.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    broker.wait_admit(1);
    broker.admitted(1);
    assert_eq!(first.head().0, 200);
    let mut second = broker.connect();
    second.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    broker.wait_admit(2);

    broker.revoke(EndReason::Locked);
    broker.wait_finished(1);
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        !broker
            .messages()
            .iter()
            .any(|m| matches!(m, FromBroker::Revoked { .. })),
        "confirmed with an admission unanswered: {:?}",
        broker.messages()
    );
    broker.refused(2, AdmissionRefusal::Revoked);
    assert_eq!(broker.wait_revoked(), 0);
    // In that order, and nothing after.
    let ends: Vec<FromBroker> = broker
        .messages()
        .into_iter()
        .filter(|m| !matches!(m, FromBroker::Admit { .. }))
        .collect();
    assert!(
        matches!(
            ends.as_slice(),
            [
                FromBroker::Finished {
                    request: 1,
                    outcome: RequestOutcome::Unknown,
                    ..
                },
                FromBroker::Revoked { refused: 0 }
            ]
        ),
        "{ends:?}"
    );
    assert_eq!(destination.received().len(), 1);
}

/// Requests open at once in the tests of a revocation of open requests. A
/// revocation closes their clients' connections too, so each sees both at
/// once and must report the revocation's outcome: each is one more chance
/// to catch it reported otherwise.
#[cfg(feature = "test-upstream")]
const OPEN_AT_THE_REVOCATION: u64 = 10;

/// Start that many requests, admitted by hand, and give the broker time to
/// take each to its next step.
#[cfg(feature = "test-upstream")]
fn admitted_requests(broker: &Broker, raw: &[u8]) -> Vec<Client> {
    let mut clients = Vec::new();
    for request in 1..=OPEN_AT_THE_REVOCATION {
        let mut client = broker.connect();
        client.write(raw);
        broker.wait_admit(request);
        broker.admitted(request);
        clients.push(client);
    }
    std::thread::sleep(Duration::from_millis(300));
    clients
}

/// Revoke while the admitted requests have sent nothing yet: each ends
/// `revoked`, the revocation is confirmed within the time the agent allows,
/// and the clients' connections are closed (a request may get its `403`
/// first: closing it and answering it race).
#[cfg(feature = "test-upstream")]
fn assert_revoked_before_anything_was_sent(broker: &Broker, clients: &mut [Client]) {
    use rusthorse::broker_protocol::REVOKE_CONFIRM_TIMEOUT;
    broker.revoke(EndReason::Revoked);
    let revoked = Instant::now();
    assert_eq!(broker.wait_revoked(), 0);
    let took = revoked.elapsed();
    assert!(took < REVOKE_CONFIRM_TIMEOUT, "{took:?}");
    for request in 1..=OPEN_AT_THE_REVOCATION {
        assert_eq!(
            broker.wait_finished(request),
            FromBroker::Finished {
                request,
                outcome: RequestOutcome::Revoked,
                status: None,
                bytes_sent: 0,
                bytes_received: 0,
            }
        );
    }
    for client in clients {
        assert_closed_or_refused(client);
    }
}

/// A client's connection closed by a revocation, after a `403` or not.
#[cfg(feature = "test-upstream")]
fn assert_closed_or_refused(client: &mut Client) {
    if !client.closed_within(Duration::from_secs(5)) {
        let response = client.response();
        response.assert_local(403);
        assert_eq!(response.header("connection"), Some("close"));
        assert!(client.closed_within(Duration::from_secs(5)));
    }
}

/// Revoke while the admitted requests may have reached the destination:
/// each ends `unknown`, with `status`, and the revocation is confirmed
/// within the time the agent allows.
#[cfg(feature = "test-upstream")]
fn assert_revoked_once_sent(broker: &Broker, status: Option<u16>) {
    use rusthorse::broker_protocol::REVOKE_CONFIRM_TIMEOUT;
    broker.revoke(EndReason::Revoked);
    let revoked = Instant::now();
    assert_eq!(broker.wait_revoked(), 0);
    let took = revoked.elapsed();
    assert!(took < REVOKE_CONFIRM_TIMEOUT, "{took:?}");
    for request in 1..=OPEN_AT_THE_REVOCATION {
        let finished = broker.wait_finished(request);
        assert!(
            matches!(
                finished,
                FromBroker::Finished {
                    outcome: RequestOutcome::Unknown,
                    status: got,
                    bytes_sent: 2,
                    ..
                } if got == status
            ),
            "{finished:?}"
        );
    }
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_revocation_before_the_destination_answers_ends_unknown() {
    use std::sync::Arc;
    let ca = TestCa::new();
    // It reads each request whole, and does not answer.
    let (_release, wait) = signal();
    let destination = Destination::new(
        &ca,
        Arc::new(move |_, _| {
            let _ = wait.lock().expect("lock").recv_timeout(PATIENCE);
        }),
    );
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let raw = broker.request("POST", "/v1/messages", &[], b"{}");
    let mut clients = Vec::new();
    for _ in 1..=OPEN_AT_THE_REVOCATION {
        let mut client = broker.connect();
        client.write(&raw);
        clients.push(client);
    }
    destination.wait_for(OPEN_AT_THE_REVOCATION as usize);
    assert_revoked_once_sent(&broker, None);
    for client in &mut clients {
        assert_closed_or_refused(client);
    }
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_revocation_while_clients_fall_behind_ends_unknown() {
    use std::sync::Arc;
    let ca = TestCa::new();
    // Each stream is more than the sockets and the broker's queues between
    // the two ends hold: once its client stops reading, the broker waits to
    // pass a piece on.
    let handler: Handler = Arc::new(|_, peer| {
        let _ = peer.send(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
        let block = vec![b'x'; 64 * 1024];
        for _ in 0..512 {
            if peer.chunk(&block).is_err() {
                return;
            }
        }
        let _ = peer.end_chunks();
    });
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let raw = broker.request("POST", "/v1/messages", &[], b"{}");
    let mut clients = Vec::new();
    for _ in 1..=OPEN_AT_THE_REVOCATION {
        let mut client = broker.connect();
        client.write(&raw);
        assert_eq!(client.head().0, 200);
        clients.push(client);
    }
    // Time for each stream to fill what lies between.
    std::thread::sleep(Duration::from_millis(500));
    assert_revoked_once_sent(&broker, Some(200));
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_revocation_while_bodies_arrive_sends_nothing() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(Options::new(&destination.origin(), &ca).admit(Admit::Manual));
    let full = broker.request("POST", "/v1/messages", &[], b"{\"twenty bytes\":1}");
    let mut clients = admitted_requests(&broker, &full[..full.len() - 5]);
    assert_revoked_before_anything_was_sent(&broker, &mut clients);
    assert_eq!(destination.connections(), 0);
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_revocation_during_resolutions_sends_nothing() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    // Four resolve, the others wait for a place.
    let broker = Broker::start(
        Options::new(&destination.origin(), &ca)
            .admit(Admit::Manual)
            .env("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS", "60000")
            .timeouts("connect=120000"),
    );
    let raw = broker.request("POST", "/v1/messages", &[], b"{}");
    let mut clients = admitted_requests(&broker, &raw);
    assert_revoked_before_anything_was_sent(&broker, &mut clients);
    assert_eq!(destination.connections(), 0);
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_revocation_during_tls_handshakes_sends_nothing() {
    let ca = TestCa::new();
    let silent = Silent::new();
    let broker = Broker::start(
        Options::new(&silent.origin(), &ca)
            .admit(Admit::Manual)
            .timeouts("tls=60000"),
    );
    let raw = broker.request("POST", "/v1/messages", &[], b"{}");
    let mut clients = admitted_requests(&broker, &raw);
    // The broker started each handshake, which waits for an answer.
    let open = OPEN_AT_THE_REVOCATION as usize;
    for connection in 0..open {
        silent.wait_for_data(connection);
    }
    assert_revoked_before_anything_was_sent(&broker, &mut clients);
    // Each handshake is dropped with its connection.
    for connection in 0..open {
        assert!(silent.closed_within(connection, Duration::from_secs(5)));
    }
    assert_eq!(silent.connections(), open);
}

#[cfg(feature = "test-upstream")]
#[test]
fn requests_that_end_in_another_order_are_reported_by_number() {
    use std::sync::Arc;
    let ca = TestCa::new();
    let (go, wait) = signal();
    let handler: Handler = Arc::new(move |request, peer| {
        if request.target.ends_with("slow") {
            let _ = wait.lock().expect("lock").recv_timeout(PATIENCE);
        }
        let _ = peer.send(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}");
    });
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let mut slow = broker.connect();
    slow.write(&broker.request("GET", "/v1/models/slow", &[], b""));
    broker.wait_admit(1);
    destination.wait_for(1);
    let fast = broker.send(&broker.request("GET", "/v1/models/fast", &[], b""));
    assert_eq!(fast.status, 200);
    broker.wait_finished(2);
    go.send(()).expect("go");
    assert_eq!(slow.response().status, 200);
    broker.wait_finished(1);
    let finished: Vec<u64> = broker
        .messages()
        .iter()
        .filter_map(|m| match m {
            FromBroker::Finished {
                request,
                outcome: RequestOutcome::Completed,
                ..
            } => Some(*request),
            _ => None,
        })
        .collect();
    assert_eq!(finished, vec![2, 1]);
}

// ===== The end of the lifetime =====
//
// The broker ends a grant when its lifetime passes, without waiting for the
// agent's `revoke`: the fake agent here never sends one before the end.

/// The lifetime of the grants in the tests of its end: long enough for
/// their requests to start before it ends, on a busy computer too.
#[cfg(feature = "test-upstream")]
const LIFETIME: Duration = Duration::from_secs(3);

/// `options` for a grant of [`LIFETIME`]. With `late`, the broker's task
/// that watches the lifetime sees its end a minute late, as it may after a
/// resume: what then stops at the end is each request, by itself.
#[cfg(feature = "test-upstream")]
fn ending(options: Options, late: bool) -> Options {
    let mut options = if late {
        options.env("RUSTHORSE_BROKER_TEST_LIFETIME_LAG_MS", "60000")
    } else {
        options
    };
    options.lifetime_secs = LIFETIME.as_secs();
    options
}

/// Sleep until `when`.
#[cfg(feature = "test-upstream")]
fn sleep_until(when: Instant) {
    std::thread::sleep(when.saturating_duration_since(Instant::now()));
}

/// A destination that starts a stream, sends `data: 1`, and `data: 2`
/// `later` after the request arrived unless the broker closed the
/// connection first, then holds it open until the broker closes it;
/// `closed` says that the broker did.
#[cfg(feature = "test-upstream")]
fn stream_with_a_late_event(
    later: Duration,
) -> (Handler, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let closed = Arc::new(AtomicBool::new(false));
    let seen = closed.clone();
    let handler: Handler = Arc::new(move |_, peer| {
        let _ = peer.send(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
        );
        let _ = peer.chunk(b"data: 1\n\n");
        let closed = peer.closed_within(later) || {
            let _ = peer.chunk(b"data: 2\n\n");
            peer.closed_within(PATIENCE)
        };
        seen.store(closed, Ordering::SeqCst);
    });
    (handler, closed)
}

/// Once the lifetime has passed: a new request gets `403` without being
/// asked for, the broker said nothing of its own — `admits` admissions
/// asked, no `revoked` — and the agent's `revoke`, which its own clock
/// sends, is confirmed as any, with `refused` requests refused before
/// admission (that `403` included).
#[cfg(feature = "test-upstream")]
fn assert_ended_without_a_word(broker: &Broker, admits: usize, refused: u64) {
    broker
        .send(&broker.request("POST", "/v1/messages", &[], b"{}"))
        .assert_local(403);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(broker.admits(), admits);
    assert!(
        !broker
            .messages()
            .iter()
            .any(|m| matches!(m, FromBroker::Revoked { .. })),
        "{:?}",
        broker.messages()
    );
    broker.revoke(EndReason::Expired);
    assert_eq!(broker.wait_revoked(), refused);
}

#[cfg(feature = "test-upstream")]
#[test]
fn the_end_of_the_lifetime_ends_every_request_without_the_agents_word() {
    use std::sync::atomic::Ordering;
    let ca = TestCa::new();
    // The stream's next event would come long after the end.
    let (handler, closed) = stream_with_a_late_event(LIFETIME + Duration::from_secs(2));
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(ending(
        Options::new(&destination.origin(), &ca).admit(Admit::Manual),
        false,
    ));
    // Request 1 streams.
    let mut stream = broker.connect();
    stream.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    broker.wait_admit(1);
    broker.admitted(1);
    assert_eq!(stream.head().0, 200);
    assert_eq!(stream.chunk().expect("an event"), b"data: 1\n\n");
    // Request 2 is admitted, and its body is still arriving.
    let mut uploading = broker.connect();
    let full = broker.request("POST", "/v1/messages", &[], b"{\"twenty bytes\":1}");
    uploading.write(&full[..full.len() - 5]);
    broker.wait_admit(2);
    broker.admitted(2);
    // Request 3 waits for its admission, which the agent does not answer.
    let mut pending = broker.connect();
    pending.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    broker.wait_admit(3);
    // And a connection with no request in progress.
    let mut idle = broker.connect();
    idle.write(&raw_request("GET", "/v1/files", broker.port, &[], b""));
    idle.response().assert_local(401);
    assert!(broker.started.elapsed() < LIFETIME, "started too late");

    // At the end of the lifetime the stream is cut, and every connection
    // open then is closed.
    assert_eq!(stream.chunk(), None, "the stream went on");
    let ended = broker.started.elapsed();
    assert!(
        ended >= LIFETIME - Duration::from_millis(100)
            && ended < LIFETIME + Duration::from_millis(1500),
        "{ended:?}"
    );
    assert!(idle.closed_within(Duration::from_secs(5)));
    assert_closed_or_refused(&mut uploading);
    assert_closed_or_refused(&mut pending);
    // Each admitted request finished: the stream unknown, the request whose
    // body was arriving revoked, nothing of it sent.
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::Unknown,
            status: Some(200),
            bytes_sent: 2,
            bytes_received: 9,
        }
    );
    assert_eq!(
        broker.wait_finished(2),
        FromBroker::Finished {
            request: 2,
            outcome: RequestOutcome::Revoked,
            status: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    );
    // The destination's connection was closed too.
    let deadline = Instant::now() + PATIENCE;
    while !closed.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < deadline,
            "the destination's connection stayed open"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // The agent's late answer is taken: admitted, request 3 ends unsent.
    broker.admitted(3);
    assert_eq!(
        broker.wait_finished(3),
        FromBroker::Finished {
            request: 3,
            outcome: RequestOutcome::Revoked,
            status: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    );
    // Refused before admission: the 401 and the 403 after the end.
    assert_ended_without_a_word(&broker, 3, 2);
    assert_eq!(destination.received().len(), 1);
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_lifetime_seen_late_still_keeps_the_next_event_of_a_stream() {
    let ca = TestCa::new();
    // The next event comes after the end, before the task sees it.
    let (handler, _closed) = stream_with_a_late_event(LIFETIME + Duration::from_millis(500));
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(ending(Options::new(&destination.origin(), &ca), true));
    let mut stream = broker.connect();
    stream.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    assert_eq!(stream.head().0, 200);
    assert_eq!(stream.chunk().expect("an event"), b"data: 1\n\n");
    // That event is not passed on: the stream is cut.
    assert_eq!(stream.chunk(), None, "the stream went on");
    let ended = broker.started.elapsed();
    assert!(
        ended >= LIFETIME + Duration::from_millis(400) && ended < LIFETIME + Duration::from_secs(5),
        "{ended:?}"
    );
    let finished = broker.wait_finished(1);
    assert!(
        matches!(
            finished,
            FromBroker::Finished {
                request: 1,
                outcome: RequestOutcome::Unknown,
                status: Some(200),
                bytes_sent: 2,
                ..
            }
        ),
        "{finished:?}"
    );
    assert_ended_without_a_word(&broker, 1, 1);
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_lifetime_seen_late_still_keeps_a_body_that_arrives_after_it_from_being_sent() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(ending(Options::new(&destination.origin(), &ca), true));
    let mut uploading = broker.connect();
    let full = broker.request("POST", "/v1/messages", &[], b"{\"twenty bytes\":1}");
    uploading.write(&full[..full.len() - 5]);
    broker.wait_admit(1);
    // The rest of the body, after the end.
    sleep_until(broker.started + LIFETIME + Duration::from_millis(500));
    uploading.write(&full[full.len() - 5..]);
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::Revoked,
            status: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    );
    assert_closed_or_refused(&mut uploading);
    assert_eq!(destination.connections(), 0, "the destination was reached");
    assert_ended_without_a_word(&broker, 1, 1);
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_lifetime_seen_late_still_keeps_a_request_reached_after_it_from_being_sent() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    // Resolving the destination ends after the end of the lifetime.
    let delay = (LIFETIME + Duration::from_millis(500))
        .as_millis()
        .to_string();
    let broker = Broker::start(ending(
        Options::new(&destination.origin(), &ca)
            .env("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS", &delay),
        true,
    ));
    let mut client = broker.connect();
    client.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::Revoked,
            status: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    );
    assert!(broker.started.elapsed() >= LIFETIME);
    assert_closed_or_refused(&mut client);
    // Reached, and nothing of the request sent.
    std::thread::sleep(Duration::from_millis(200));
    assert!(destination.received().is_empty(), "the request was sent");
    assert_ended_without_a_word(&broker, 1, 1);
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_lifetime_seen_late_still_keeps_an_answer_that_comes_after_it_from_the_client() {
    use std::sync::Arc;
    let ca = TestCa::new();
    // The destination answers after the end of the lifetime.
    let handler: Handler = Arc::new(|_, peer| {
        std::thread::sleep(LIFETIME + Duration::from_millis(500));
        let _ = peer.send(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}");
    });
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(ending(Options::new(&destination.origin(), &ca), true));
    let mut client = broker.connect();
    client.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::Unknown,
            status: Some(200),
            bytes_sent: 2,
            bytes_received: 0,
        }
    );
    assert!(broker.started.elapsed() >= LIFETIME);
    // Not passed on: the client gets the broker's 403, or its connection
    // closed.
    assert_closed_or_refused(&mut client);
    assert_eq!(destination.received().len(), 1);
    assert_ended_without_a_word(&broker, 1, 1);
}

// ===== Deadlines =====

#[cfg(feature = "test-upstream")]
#[test]
fn a_body_that_does_not_arrive_in_time_is_not_forwarded() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(Options::new(&destination.origin(), &ca).timeouts("body=500"));
    let mut client = broker.connect();
    let full = broker.request("POST", "/v1/messages", &[], b"{\"twenty bytes\":1}");
    client.write(&full[..full.len() - 5]);
    let started = Instant::now();
    let response = client.response();
    response.assert_local(408);
    assert_eq!(response.header("connection"), Some("close"));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(400) && took < Duration::from_secs(5),
        "{took:?}"
    );
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::NotForwarded,
            status: Some(408),
            bytes_sent: 0,
            bytes_received: 0,
        }
    );
    assert_eq!(destination.connections(), 0);
}

#[test]
fn a_client_that_leaves_before_its_body_spends_the_use_without_forwarding() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(Options::new(&destination.origin(), &ca).admit(Admit::Manual));
    let mut client = broker.connect();
    let full = broker.request("POST", "/v1/messages", &[], b"{\"twenty bytes\":1}");
    client.write(&full[..full.len() - 5]);
    broker.wait_admit(1);
    drop(client);
    broker.admitted(1);
    assert!(matches!(
        broker.wait_finished(1),
        FromBroker::Finished {
            outcome: RequestOutcome::NotForwarded,
            bytes_sent: 0,
            ..
        }
    ));
    assert_eq!(destination.connections(), 0);
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_destination_that_does_not_answer_in_time_is_an_unknown_outcome() {
    use std::sync::Arc;
    let ca = TestCa::new();
    let (_go, wait) = signal();
    let handler: Handler = Arc::new(move |_, _| {
        let _ = wait.lock().expect("lock").recv_timeout(PATIENCE);
    });
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca).timeouts("response=500"));
    let started = Instant::now();
    let response = broker.send(&broker.request("POST", "/v1/messages", &[], b"{}"));
    response.assert_local(504);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(400) && took < Duration::from_secs(5),
        "{took:?}"
    );
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::Unknown,
            status: Some(504),
            bytes_sent: 2,
            bytes_received: 0,
        }
    );
    assert_eq!(destination.received().len(), 1);
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_response_body_that_pauses_too_long_is_cut() {
    let ca = TestCa::new();
    let (handler, _closed) = holding_stream(b"data: 1\n\n");
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca).timeouts("pause=500"));
    let mut client = broker.connect();
    client.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    assert_eq!(client.head().0, 200);
    assert_eq!(client.chunk().expect("the first event"), b"data: 1\n\n");
    let started = Instant::now();
    assert_eq!(client.chunk(), None, "the stream went on");
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(400) && took < Duration::from_secs(5),
        "{took:?}"
    );
    assert!(matches!(
        broker.wait_finished(1),
        FromBroker::Finished {
            outcome: RequestOutcome::Unknown,
            status: Some(200),
            bytes_received: 9,
            ..
        }
    ));
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_tls_handshake_that_stalls_ends_within_its_deadline() {
    let ca = TestCa::new();
    let silent = Silent::new();
    let broker = Broker::start(Options::new(&silent.origin(), &ca).timeouts("tls=500"));
    let started = Instant::now();
    broker
        .send(&broker.request("GET", "/v1/models", &[], b""))
        .assert_unreachable();
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(450) && took < Duration::from_secs(3),
        "{took:?}"
    );
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::NotForwarded,
            status: Some(502),
            bytes_sent: 0,
            bytes_received: 0,
        }
    );
    assert_eq!(silent.connections(), 1);
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_client_that_stops_reading_is_gone_after_the_longest_pause() {
    use std::sync::Arc;
    let ca = TestCa::new();
    // More than the sockets and the broker's queues between the two ends
    // hold, and less than the most relayed: the stream stops only because
    // the client takes nothing.
    let handler: Handler = Arc::new(|_, peer| {
        let _ = peer.send(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
        let block = vec![b'x'; 64 * 1024];
        for _ in 0..512 {
            if peer.chunk(&block).is_err() {
                return;
            }
        }
        let _ = peer.end_chunks();
    });
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca).timeouts("pause=500"));
    let mut client = broker.connect();
    client.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    assert_eq!(client.head().0, 200);
    // It reads nothing more.
    let finished = broker.wait_finished(1);
    assert!(
        matches!(
            finished,
            FromBroker::Finished {
                outcome: RequestOutcome::ClientClosed,
                status: Some(200),
                bytes_sent: 2,
                ..
            }
        ),
        "{finished:?}"
    );
}

#[cfg(feature = "test-upstream")]
#[test]
fn heads_must_arrive_within_their_deadline() {
    let ca = TestCa::new();
    let broker = Broker::start(
        Options::nowhere(&ca)
            .admit(Admit::Refuse(AdmissionRefusal::Exhausted))
            .timeouts("header=600,idle=60000"),
    );
    // A head that trickles in is cut at the deadline, unanswered.
    let mut client = broker.connect();
    let started = Instant::now();
    let raw = broker.request("GET", "/v1/models", &[], b"");
    let mut sent = 0;
    while sent < raw.len() - 2 && client.try_write(&raw[sent..sent + 1]) {
        sent += 1;
        std::thread::sleep(Duration::from_millis(50));
        if started.elapsed() > Duration::from_secs(5) {
            break;
        }
    }
    assert!(
        client.closed_within(Duration::from_secs(5)),
        "answered or left open"
    );
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(550) && took < Duration::from_secs(3),
        "{took:?}"
    );
    // The deadline counts again from the previous response.
    let mut client = broker.connect();
    client.write(&broker.request("GET", "/v1/models", &[], b""));
    client.response().assert_local(403);
    let answered = Instant::now();
    assert!(client.closed_within(Duration::from_secs(5)));
    let idle = answered.elapsed();
    assert!(
        idle >= Duration::from_millis(500) && idle < Duration::from_secs(3),
        "{idle:?}"
    );
    assert_eq!(broker.admits(), 1);
}

#[cfg(feature = "test-upstream")]
#[test]
fn idle_connections_are_closed() {
    let ca = TestCa::new();
    let broker = Broker::start(Options::nowhere(&ca).timeouts("idle=400,header=60000"));
    let mut client = broker.connect();
    let started = Instant::now();
    assert!(client.closed_within(Duration::from_secs(5)));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(350) && took < Duration::from_secs(3),
        "{took:?}"
    );
}

// ===== The control channel ending =====

#[cfg(feature = "test-upstream")]
#[test]
fn the_channel_closing_during_a_request_ends_the_broker_at_once() {
    let ca = TestCa::new();
    let (handler, _closed) = holding_stream(b"data: 1\n\n");
    let destination = Destination::new(&ca, handler);
    let mut broker = Broker::start(Options::new(&destination.origin(), &ca));
    let mut client = broker.connect();
    client.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
    assert_eq!(client.head().0, 200);
    assert_eq!(client.chunk().as_deref(), Some(&b"data: 1\n\n"[..]));
    let started = Instant::now();
    broker.close_channel();
    let status = broker.exit_within(Duration::from_secs(5)).expect("exits");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(status.code(), Some(0));
    // The stream ends with the broker, cut short.
    assert_eq!(client.chunk(), None);
}

#[cfg(feature = "test-upstream")]
#[test]
fn the_channel_closing_during_a_hanging_resolution_ends_the_broker_at_once() {
    let ca = TestCa::new();
    let mut broker = Broker::start(
        Options::nowhere(&ca)
            .env("RUSTHORSE_BROKER_TEST_RESOLVE_DELAY_MS", "120000")
            .timeouts("connect=120000"),
    );
    let mut clients = Vec::new();
    for n in 1..=3 {
        let mut client = broker.connect();
        client.write(&broker.request("GET", "/v1/models", &[], b""));
        broker.wait_admit(n);
        clients.push(client);
    }
    std::thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    broker.close_channel();
    let status = broker.exit_within(Duration::from_secs(10)).expect("exits");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(status.code(), Some(0));
}

// ===== Connections =====

#[cfg(feature = "test-upstream")]
#[test]
fn a_connection_carries_one_request_after_another() {
    let ca = TestCa::new();
    let destination = Destination::new(&ca, answer(200, &[], b"{}"));
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let mut client = broker.connect();
    for _ in 0..3 {
        client.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
        let response = client.response();
        assert_eq!(response.status, 200, "{response:?}");
        assert!(response.complete);
    }
    // Two at once, answered in order.
    let mut two = broker.request("GET", "/v1/models/a", &[], b"");
    two.extend(raw_request("GET", "/v1/files", broker.port, &[], b""));
    client.write(&two);
    assert_eq!(client.response().status, 200);
    client.response().assert_local(401);
    assert_eq!(destination.received().len(), 4);
    // One connection to the destination per request.
    assert_eq!(destination.connections(), 4);
}

#[cfg(feature = "test-upstream")]
#[test]
fn a_response_in_progress_keeps_its_connection_from_idling() {
    use std::sync::Arc;
    let ca = TestCa::new();
    // Events far apart: the stream lasts four times the idle limit.
    let handler: Handler = Arc::new(|_, peer| {
        let _ = peer.send(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
        );
        for n in 0..5 {
            let _ = peer.chunk(format!("data: {n}\n\n").as_bytes());
            std::thread::sleep(Duration::from_millis(250));
        }
        let _ = peer.end_chunks();
    });
    let destination = Destination::new(&ca, handler);
    let broker =
        Broker::start(Options::new(&destination.origin(), &ca).timeouts("idle=300,header=60000"));
    let started = Instant::now();
    let response = broker.send(&broker.request("POST", "/v1/messages", &[], b"{}"));
    assert!(started.elapsed() >= Duration::from_millis(1200));
    assert_eq!(response.status, 200, "{response:?}");
    assert!(response.complete, "the stream was cut: {response:?}");
    assert_eq!(
        response.text(),
        "data: 0\n\ndata: 1\n\ndata: 2\n\ndata: 3\n\ndata: 4\n\n"
    );
    assert_eq!(
        broker.wait_finished(1),
        FromBroker::Finished {
            request: 1,
            outcome: RequestOutcome::Completed,
            status: Some(200),
            bytes_sent: 2,
            bytes_received: 45,
        }
    );
}

#[test]
fn a_client_that_expects_100_continue_gets_it_only_once_admitted() {
    let ca = TestCa::new();
    let broker = Broker::start(Options::nowhere(&ca).admit(Admit::Manual));
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: 127.0.0.1:{}\r\nx-api-key: {}\r\ncontent-length: 2\r\nexpect: 100-continue\r\n\r\n",
        broker.port, broker.token
    );
    // Refused: the final answer, and no 100.
    let mut client = broker.connect();
    client.write(head.as_bytes());
    broker.wait_admit(1);
    broker.refused(1, AdmissionRefusal::Exhausted);
    client.response().assert_local(403);
    // Admitted: 100 once the body is wanted, then the body is read (and
    // here, with nowhere to send it, not forwarded).
    let mut client = broker.connect();
    client.write(head.as_bytes());
    broker.wait_admit(2);
    assert!(
        !client.closed_within(Duration::from_millis(200)),
        "answered before the admission"
    );
    broker.admitted(2);
    assert_eq!(client.head().0, 100);
    client.write(b"{}");
    assert_eq!(client.response().status, 502);
    assert!(matches!(
        broker.wait_finished(2),
        FromBroker::Finished {
            outcome: RequestOutcome::NotForwarded,
            status: Some(502),
            ..
        }
    ));
}

// ===== The process =====

#[test]
fn a_serving_broker_is_not_dumpable_and_makes_no_core_files() {
    use std::os::unix::fs::MetadataExt;
    if nix::unistd::geteuid().is_root() {
        return; // every process's files belong to root then
    }
    let ca = TestCa::new();
    let broker = Broker::start(Options::nowhere(&ca));
    let pid = broker.pid();
    // A process that is not dumpable has its /proc files owned by root.
    let environ = std::fs::metadata(format!("/proc/{pid}/environ")).expect("environ");
    assert_eq!(environ.uid(), 0, "the broker is dumpable");
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).expect("limits");
    let core = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .expect("a core limit");
    let values: Vec<&str> = core.split_whitespace().skip(4).take(2).collect();
    assert_eq!(values, vec!["0", "0"], "{core}");
}

#[cfg(feature = "test-upstream")]
#[test]
fn an_internal_error_ends_the_broker_at_once() {
    let ca = TestCa::new();
    let mut broker =
        Broker::start(Options::nowhere(&ca).env("RUSTHORSE_BROKER_TEST_PANIC", "request"));
    let mut client = broker.connect();
    client.write(&broker.request("GET", "/v1/models", &[], b""));
    // The panic hook ends the process, rather than let the runtime go on
    // without the task that failed.
    let status = broker.exit_within(Duration::from_secs(5)).expect("exits");
    assert_eq!(status.code(), Some(5), "{status:?}");
    assert!(broker.channel_ended(Duration::from_secs(5)));
    assert!(client.closed_within(Duration::from_secs(5)), "answered");
}

#[cfg(feature = "test-upstream")]
#[test]
fn every_stream_open_at_a_revocation_ends_unknown() {
    let ca = TestCa::new();
    let (handler, _closed) = holding_stream(b"data: 1\n\n");
    let destination = Destination::new(&ca, handler);
    let broker = Broker::start(Options::new(&destination.origin(), &ca));
    let mut streams = Vec::new();
    for _ in 0..6 {
        let mut client = broker.connect();
        client.write(&broker.request("POST", "/v1/messages", &[], b"{}"));
        assert_eq!(client.head().0, 200);
        assert_eq!(client.chunk().as_deref(), Some(&b"data: 1\n\n"[..]));
        streams.push(client);
    }
    broker.revoke(EndReason::Suspend);
    let revoked = Instant::now();
    for client in &mut streams {
        assert_eq!(client.chunk(), None);
    }
    assert!(
        revoked.elapsed() < Duration::from_secs(2),
        "{:?}",
        revoked.elapsed()
    );
    assert_eq!(broker.wait_revoked(), 0);
    for request in 1..=6 {
        assert!(
            matches!(
                broker.wait_finished(request),
                FromBroker::Finished {
                    outcome: RequestOutcome::Unknown,
                    status: Some(200),
                    ..
                }
            ),
            "{:?}",
            broker.messages()
        );
    }
}
