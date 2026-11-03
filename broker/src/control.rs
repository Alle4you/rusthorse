//! The control channel once the broker is ready: one task reads the agent's
//! messages and applies them to the grant, another writes the broker's, in
//! the order the grant queued them.
//!
//! The channel ending — the end of the stream or an error — ends the broker
//! at once, without waiting for anything (a name resolution that hangs
//! included). So does anything the agent may not send: a second install,
//! an answer for a number that is not waiting, a second revoke, a frame
//! that is too large or does not decode.

use rusthorse::broker_protocol::{self, FromBroker, MAX_FRAME, ToBroker};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::grant::{Answer, Grant, Violation};
use crate::{EXIT_CHANNEL_ENDED, EXIT_CHANNEL_FAILED, EXIT_VIOLATION};

/// Read the agent's messages until the channel ends or the agent breaks
/// the conversation; returns the broker's exit status.
///
/// The buffer holds one frame at its largest from the start and never
/// grows (a frame larger than `MAX_FRAME` is refused from its header), and
/// it is wiped on drop: a second install, refused, would carry a token and
/// a credential.
pub async fn read(mut channel: OwnedReadHalf, grant: &Grant) -> u8 {
    let mut buffer = Zeroizing::new(Vec::with_capacity(4 + MAX_FRAME));
    loop {
        // Every whole frame the buffer holds.
        loop {
            let (message, used) = match broker_protocol::split_frame(&buffer) {
                Ok(Some((body, used))) => match broker_protocol::decode::<ToBroker>(body) {
                    Ok(message) => (message, used),
                    Err(_) => return EXIT_VIOLATION,
                },
                Ok(None) => break,
                Err(_) => return EXIT_VIOLATION,
            };
            buffer.drain(..used);
            if apply(grant, message).is_err() {
                return EXIT_VIOLATION;
            }
        }
        match channel.read_buf(&mut *buffer).await {
            Ok(0) if buffer.is_empty() => return EXIT_CHANNEL_ENDED,
            // A frame cut short.
            Ok(0) => return EXIT_VIOLATION,
            Ok(_) => {}
            Err(_) => return EXIT_CHANNEL_FAILED,
        }
    }
}

/// Apply one message of the agent to the grant.
fn apply(grant: &Grant, message: ToBroker) -> Result<(), Violation> {
    match message {
        ToBroker::Install(_) => Err(Violation("a second install")),
        ToBroker::Admitted { request } => grant.on_answer(request, Answer::Admitted),
        ToBroker::Refused { request, reason } => grant.on_answer(request, Answer::Refused(reason)),
        ToBroker::Revoke { .. } => grant.on_revoke(),
    }
}

/// Write the broker's messages as the grant queues them; returns the
/// broker's exit status if writing fails.
pub async fn write(
    mut channel: OwnedWriteHalf,
    mut queue: mpsc::UnboundedReceiver<FromBroker>,
) -> u8 {
    while let Some(message) = queue.recv().await {
        let Ok(frame) = broker_protocol::encode(&message) else {
            return EXIT_CHANNEL_FAILED;
        };
        if channel.write_all(&frame).await.is_err() {
            return EXIT_CHANNEL_FAILED;
        }
    }
    // The grant, which holds the queue's other end, lives as long as the
    // broker: this is not reached.
    std::future::pending().await
}
