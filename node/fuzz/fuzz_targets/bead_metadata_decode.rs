#![no_main]

use bitcoin::consensus::encode::Decodable;
use libfuzzer_sys::fuzz_target;
use node::bead::BeadResponse;

/// A valid 80-byte Bitcoin block header, taken from a bead this crate builds.
const HEADER: [u8; 80] = [
    0x02, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x00, 0x1d, 0x25, 0x4f, 0x2a, 0x6f,
];

// The byte-oriented targets saturate almost at once: `bead_request_decode` found
// its last new edge after 243 executions out of 468,840, because a random first
// byte is an invalid variant 251 times in 256 and the decoder returns before
// reaching anything. Every defect found so far instead lives in
// `CommittedMetadata`, behind a valid header that random bytes do not produce.
//
// So hand the fuzzer a frame that is already valid up to that point and let it
// own the metadata: variant, bead count, a real header, then its own bytes.
fuzz_target!(|data: &[u8]| {
    let mut frame = Vec::with_capacity(2 + HEADER.len() + data.len());
    frame.push(0x00); // BeadResponse::Beads
    frame.push(0x01); // VarInt: one bead
    frame.extend_from_slice(&HEADER);
    frame.extend_from_slice(data);

    let _ = BeadResponse::consensus_decode(&mut &frame[..]);
});
