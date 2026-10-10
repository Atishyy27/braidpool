#![no_main]

use bitcoin::consensus::encode::Decodable;
use libfuzzer_sys::fuzz_target;
use node::bead::BeadRequest;

// `bead_request_decode` reaches 81 edges and finds its last new one after 243
// of 468,840 executions: a random first byte is an invalid variant 251 times
// in 256, and three of the five valid ones carry no payload, so almost nothing
// ever reaches `BeadHashes`.
//
// Pin the variant to one that does carry hashes and let the fuzzer own the rest,
// so the budget is spent in the vector decoder instead of on the discriminant.
fuzz_target!(|data: &[u8]| {
    let mut frame = Vec::with_capacity(1 + data.len());
    frame.push(0x00); // BeadRequest::GetBeads
    frame.extend_from_slice(data);

    let _ = BeadRequest::consensus_decode(&mut &frame[..]);
});
