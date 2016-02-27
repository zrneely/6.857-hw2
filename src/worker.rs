
use rand::distributions::{IndependentSample, Range};
use rand::thread_rng;
use session_types::*;

use std::collections::HashSet;

use Block;

pub struct Triple {
    pub start_point: u64,
    pub end_point: u64,
    pub chain_length: u64
}

pub type SendTriple = Choose<Send<Triple, RecvTriples>, Eps>;
pub type RecvTriples = Recv<Vec<Triple>, Send<Results, Eps>>;
pub type Results = Option<Vec<u64>>;

/// Runs a worker thread. Returns the number of hashes this thread did.
pub fn worker(c: Chan<(), Recv<Block, SendTriple>>) -> u64 {
    let mut rng = thread_rng();
    let (c, block) = c.recv();
    let mut hashes = 0;

    // max_distinguished = 2^(2N/3)
    let max_distinguished = 2f64.powf(
        2f64 * (block.difficulty as f64 / 3f64)).ceil() as u64;
    // max_length = 20 * 2^(N/3)
    let max_length = 20 * 2f64.powf(block.difficulty as f64 / 3f64).ceil() as u64;

    // Construct triples, looking for distinguished points
    let range = Range::new(0, 2u64.pow(block.difficulty as u32));
    let start_point = range.ind_sample(&mut rng);
    let mut test_point = start_point;
    for len in 0..max_length {
        test_point = block.hash_with_nonce(test_point).to_u64(block.difficulty);
        hashes += 1;
        if test_point < max_distinguished {
            let c = c.sel1().send(Triple {
                start_point: start_point,
                end_point: test_point,
                chain_length: len,
            });
            return hashes + acquire_triples(c, block);
        }
    }
    c.sel2().close();
    return hashes;
}

fn acquire_triples(c: Chan<(), RecvTriples>, block: Block) -> u64 {
    let mut hashes = 0;

    // receive the triples
    let (c, mut triples) = c.recv();
    (&mut triples[..]).sort_by_key(|&Triple { end_point, .. }| end_point);

    // process the triples
    let num_triples = triples.len();
    let mut i = 0;
    while i < num_triples {
        // Find two triples with different endpoints
        let mut j = i + 1;
        while j < num_triples && triples[j].end_point == triples[i].end_point {
            j += 1;
        }
        if j >= i + 3 {
            let max_length = (&triples[i..j-1]).iter()
                .map(|&Triple { chain_length, .. }| chain_length).max().unwrap();
            for length in (0..max_length).rev() {
                for k in i..j-1 {
                    if triples[k].chain_length >= length {
                        triples[k].end_point = triples[k].start_point;
                        triples[k].start_point =
                            block.hash_with_nonce(triples[k].start_point).to_u64(block.difficulty);
                        hashes += 1;
                    }
                }
                // Check for 3 values in the triples where the start points are the same and
                // the end points are different
                let mut starts = HashSet::new();
                for triple in &triples[i..j-1] {
                    starts.insert(triple.start_point);
                }
                for start in starts {
                    let mut ends = HashSet::new();
                    let mut points = Vec::new();
                    for triple in &triples[i..j-1] {
                        if triple.start_point == start && ends.insert(triple.end_point) {
                            points.push(triple.end_point);
                        }
                    }
                    if points.len() >= 3 {
                        c.send(Some(points)).close();
                        return hashes;
                    }
                }
            }
        }
        i = j;
    }

    c.send(None).close();
    hashes
}
