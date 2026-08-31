//! Opt-in zstd decompression of inbound WebSocket data frames.
//!
//! ## Wire rule
//!
//! The rule is by OPCODE, never by channel. A BINARY frame is one standard
//! zstd frame whose decompressed payload is exactly the JSON text a plain
//! connection would carry. A TEXT frame is plain JSON. Control frames
//! (`subscriptionResponse`, `error`, `pong`, `post` replies) stay TEXT in every
//! mode. Outbound stays text-only.
//!
//! ## Negotiation
//!
//! The client offers `mtf-zstd.v1.d<id>` then `mtf-zstd.v1` in
//! `Sec-WebSocket-Protocol`. The server echoes the token it selected, so the
//! mode is known before the first frame. A server that echoes nothing keeps
//! today's text stream, byte for byte.
//!
//! A stale dictionary id degrades AT THE HANDSHAKE: the stale token matches
//! nothing on the server, so plain `mtf-zstd.v1` matches instead. There is no
//! per-frame fallback, and none is possible — a dictionary-compressed frame
//! cannot be decoded without those exact bytes.

use ruzstd::decoding::{Dictionary, FrameDecoder, StreamingDecoder};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// The dictionary the gateway ships, embedded at compile time. It rides the
/// same release as the code, so the two can never drift.
const EMBEDDED_DICT: &[u8] = include_bytes!("../../assets/ws-dict/current.dict");

/// Subprotocol token for zstd without a dictionary.
const PROTO_PLAIN: &str = "mtf-zstd.v1";

/// Subprotocol token for zstd with the embedded dictionary.
///
/// DERIVED from [`EMBEDDED_DICT`], never written down. A literal id that drifts
/// from the bytes beside it is silent and permanent: the gateway grants dict
/// mode, compresses with the dictionary it holds, every decode returns `None`,
/// and the data stream goes quiet with no error.
fn proto_dict() -> &'static str {
    static TOKEN: OnceLock<String> = OnceLock::new();
    TOKEN.get_or_init(|| {
        let digest = Sha256::digest(EMBEDDED_DICT);
        let id: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
        format!("{PROTO_PLAIN}.d{id}")
    })
}

/// The offer, in client preference order. There is NO space after the comma:
/// tungstenite matches the echoed token against `split(",")` and does not trim,
/// so a space makes the second token unmatchable and fails the handshake.
pub(crate) fn offer() -> &'static str {
    static OFFER: OnceLock<String> = OnceLock::new();
    OFFER.get_or_init(|| format!("{},{PROTO_PLAIN}", proto_dict()))
}

/// A decoded frame over this bound is dropped. The gateway sends book and
/// trade frames; nothing legitimate approaches this.
const MAX_DECODED_BYTES: u64 = 16 << 20;

/// How one connection reads its inbound data frames.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum WireMode {
    /// Plain JSON text frames — the pre-compression behavior, byte for byte.
    #[default]
    Text,
    /// zstd binary frames, no dictionary.
    Zstd,
    /// zstd binary frames with the embedded dictionary.
    ZstdDict,
}

impl WireMode {
    /// The mode the echoed subprotocol token names.
    pub(crate) fn from_selected(token: Option<&str>) -> Self {
        match token {
            Some(t) if t == proto_dict() => Self::ZstdDict,
            Some(PROTO_PLAIN) => Self::Zstd,
            _ => Self::Text,
        }
    }
}

/// One connection's zstd decoder. It lives for the connection so the
/// dictionary is parsed once, not once per frame.
pub(crate) struct Decoder(FrameDecoder);

impl Decoder {
    /// `None` in [`WireMode::Text`], where no binary frame is expected.
    pub(crate) fn new(mode: WireMode) -> Option<Self> {
        let mut decoder = FrameDecoder::new();
        match mode {
            WireMode::Text => return None,
            WireMode::Zstd => {}
            WireMode::ZstdDict => {
                decoder
                    .add_dict(Dictionary::decode_dict(EMBEDDED_DICT).ok()?)
                    .ok()?;
            }
        }
        Some(Self(decoder))
    }

    /// The JSON text inside one standard zstd frame. `None` drops the frame:
    /// frames are independent, so one bad frame spoils no later one.
    pub(crate) fn decode(&mut self, frame: &[u8]) -> Option<String> {
        use std::io::Read;

        let mut stream = StreamingDecoder::new_with_decoder(frame, &mut self.0).ok()?;
        let mut out = Vec::new();
        stream
            .by_ref()
            .take(MAX_DECODED_BYTES)
            .read_to_end(&mut out)
            .ok()?;
        String::from_utf8(out).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One real `l2_book` frame, captured from the public socket. Real market
    /// behaviour is what compresses: a maker quotes the SAME `sz` down dozens
    /// of levels, and mock JSON does not reproduce that.
    const FRAME: &str = r#"{"channel":"l2_book","data":{"coin":"BTC","levels":[[{"n":1,"px":"78657.1","sz":"0.47166"},{"n":1,"px":"78650.6","sz":"0.47166"},{"n":1,"px":"78635.9","sz":"0.47166"},{"n":1,"px":"78615","sz":"0.47166"},{"n":1,"px":"78588.5","sz":"0.47166"},{"n":1,"px":"78556.8","sz":"0.47166"},{"n":1,"px":"78520.4","sz":"0.47166"},{"n":1,"px":"78479.4","sz":"0.47166"},{"n":1,"px":"78434.1","sz":"0.47166"},{"n":1,"px":"78384.7","sz":"0.47166"},{"n":1,"px":"78331.3","sz":"0.47166"},{"n":1,"px":"78274","sz":"0.47166"},{"n":1,"px":"78212.9","sz":"0.47166"},{"n":1,"px":"78148.2","sz":"0.47166"},{"n":1,"px":"78079.9","sz":"0.47166"},{"n":1,"px":"78008","sz":"0.47166"},{"n":1,"px":"77932.8","sz":"0.47166"},{"n":1,"px":"77854.1","sz":"0.47166"},{"n":1,"px":"77772.2","sz":"0.47166"},{"n":1,"px":"77687","sz":"0.47166"}],[{"n":1,"px":"78696.5","sz":"0.45618"},{"n":1,"px":"78703","sz":"0.45618"},{"n":1,"px":"78717.6","sz":"0.45618"},{"n":1,"px":"78738.6","sz":"0.45618"},{"n":1,"px":"78765.1","sz":"0.45618"},{"n":1,"px":"78796.8","sz":"0.45618"},{"n":1,"px":"78833.2","sz":"0.45618"},{"n":1,"px":"78874.2","sz":"0.45618"},{"n":1,"px":"78919.4","sz":"0.45618"},{"n":1,"px":"78968.9","sz":"0.45618"},{"n":1,"px":"79025.2","sz":"0.45618"},{"n":1,"px":"79082.5","sz":"0.45618"},{"n":1,"px":"79143.5","sz":"0.45618"},{"n":1,"px":"79208.3","sz":"0.45618"},{"n":1,"px":"79276.6","sz":"0.45618"},{"n":1,"px":"79348.4","sz":"0.45618"},{"n":1,"px":"79423.7","sz":"0.45618"},{"n":1,"px":"79502.3","sz":"0.45618"},{"n":1,"px":"79584.3","sz":"0.45618"},{"n":1,"px":"79669.5","sz":"0.45618"}]],"time":1788103269757},"is_snapshot":true}"#;

    /// `FRAME` compressed by the `zstd` tool at level 3 WITH the shipped
    /// dictionary. Cross-implementation proof: these bytes are produced by an
    /// independent zstd, not by this crate, and the TypeScript SDK asserts
    /// against the no-dictionary twin.
    const GOLDEN_DICT: &str = "28b52ffd6766103d2c48056d070043050b6d3865100319d2b9271be2a5921d968db616f374af5749a9b9d7d467a6f5368914abeceece6e55d79d7c5f3356fc6902cf086d5c739905b36b3020ad4285253c813e45db7067041b4e8fe048a5774b51aca856abb81f909cd71a0dd33be0466154adb862c989d42b2e94e7b2537a35d06aa9a6d05a666c0026fcca278b0286a0ed5a060aa6ce77e75fef42e8006e6e1ca92a8289cd6e309b3b87f5257ff6b939442cbad39c262e6bf1767d180791651b69c79cf668a51c56ba1dcf00f7f05eb842e4b9328dbc255a25b06c7f0e823d12eba9a49984decc5dc51ec8ac69519232c5e039f71a4ee4db414020e2d6d1";

    /// `FRAME` compressed by the `zstd` tool at level 3, no dictionary.
    const GOLDEN_NODICT: &str = "28b52ffd6448053d0a0086d031206069d3068873e81bc5b69ee8b67d7b7f15c183d34864f7d2ca04d99082208a0b2e00250023005f5760fcd8fa7287c1b0de284942a2fc3c4000e0ebcb8249dcb18e3410829f1730cc00e294af2bc9b2208ac41d017b880c71916254d8ab144a978c34331173a6354a5494cee3aab60aa5af2f343f37b4a9bc01a8ac8f53e7a566b5568bc89dcab896964d53fb1c58f77637790f7b53ea4d8758d9d9a98f04e1a0b1de60140d03591a44b3f8796c6eeb6132e6b5f5c460d1f8391c5a55715e4a3cd5acb075395d3320d0626a460f0d4b8624e4b0899c14f0df8334c821cb1d741dcef21892241945876c72a80fe4f040eab0511943a27588e91814a8a77cd461c1819fc4c43a64cc81e73a7cc6613cf24507aed78cf3c21b3f3b44d5e408c5217b31620fc89118b5bdc9611c8f9a518b0189a725477dd48f1a463d1ff10e81335b9a851920e2d6d1";

    fn golden(hex_bytes: &str) -> Vec<u8> {
        hex::decode(hex_bytes).expect("golden is hex")
    }

    /// A dictionary-compressed golden frame decodes to the EXACT source JSON.
    ///
    /// This does NOT guard the dictionary's content. A flipped content byte
    /// leaves the id in bytes 4..8 intact, so this test stays green unless the
    /// flip happens to sit in a range the frame references.
    /// `embedded_dictionary_is_the_shipped_one` is the content guard.
    #[test]
    fn dict_golden_decodes_byte_for_byte() {
        let mut decoder = Decoder::new(WireMode::ZstdDict).expect("dict decoder");
        let out = decoder.decode(&golden(GOLDEN_DICT)).expect("decode");
        assert_eq!(out, FRAME);
    }

    /// The same source JSON, compressed with no dictionary, decodes to the
    /// EXACT source JSON.
    #[test]
    fn nodict_golden_decodes_byte_for_byte() {
        let mut decoder = Decoder::new(WireMode::Zstd).expect("plain decoder");
        let out = decoder.decode(&golden(GOLDEN_NODICT)).expect("decode");
        assert_eq!(out, FRAME);
    }

    /// One decoder serves a whole connection, so it must stay usable frame
    /// after frame.
    #[test]
    fn one_decoder_serves_many_frames() {
        let mut decoder = Decoder::new(WireMode::ZstdDict).expect("dict decoder");
        let frame = golden(GOLDEN_DICT);
        for _ in 0..3 {
            assert_eq!(decoder.decode(&frame).as_deref(), Some(FRAME));
        }
    }

    /// A dictionary-compressed frame cannot be read without the dictionary,
    /// and rubbish is dropped rather than panicking.
    #[test]
    fn undecodable_frames_are_dropped() {
        let mut plain = Decoder::new(WireMode::Zstd).expect("plain decoder");
        assert!(plain.decode(&golden(GOLDEN_DICT)).is_none());
        assert!(plain.decode(b"not a zstd frame").is_none());
        assert!(plain.decode(b"").is_none());
    }

    /// The shipped dictionary is the real artifact, byte for byte.
    ///
    /// The CONTENT hash is the assertion that matters. Length and magic survive
    /// a flipped content byte, and so does the golden decode when the flip sits
    /// outside the bytes that frame back-references. Pinning the digest also
    /// pins the token [`proto_dict`] derives from it.
    #[test]
    fn embedded_dictionary_is_the_shipped_one() {
        assert_eq!(EMBEDDED_DICT.len(), 16_384);
        assert_eq!(
            &EMBEDDED_DICT[..4],
            &[0x37, 0xa4, 0x30, 0xec],
            "ZSTD_MAGIC_DICTIONARY"
        );
        assert_eq!(
            hex::encode(Sha256::digest(EMBEDDED_DICT)),
            "e3e136e4f5db027f2215319497ae0b2103514e41d9f837c1c5ee7e8208a00012"
        );
        assert_eq!(proto_dict(), "mtf-zstd.v1.de3e136e4");
    }

    /// A server that echoes nothing, or a token this client does not know,
    /// leaves the connection on text.
    #[test]
    fn only_the_two_offered_tokens_leave_text_mode() {
        assert_eq!(WireMode::from_selected(None), WireMode::Text);
        assert_eq!(WireMode::from_selected(Some("graphql-ws")), WireMode::Text);
        assert_eq!(
            WireMode::from_selected(Some("mtf-zstd.v1.dbaadf00d")),
            WireMode::Text,
            "a dictionary this client does not hold can only be text"
        );
        assert_eq!(WireMode::from_selected(Some(PROTO_PLAIN)), WireMode::Zstd);
        assert_eq!(
            WireMode::from_selected(Some(proto_dict())),
            WireMode::ZstdDict
        );
        assert!(Decoder::new(WireMode::Text).is_none());
    }

    /// The offer must stay parseable by tungstenite's untrimmed `split(",")`,
    /// or the plain token can never be selected.
    #[test]
    fn offer_has_no_space_after_the_comma() {
        let tokens: Vec<&str> = offer().split(',').collect();
        assert_eq!(tokens, vec![proto_dict(), PROTO_PLAIN]);
    }
}
