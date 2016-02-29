
extern crate byteorder;
extern crate crypto;
extern crate hyper;
extern crate rand;
extern crate rustc_serialize;
#[macro_use]
extern crate session_types;
extern crate time;

mod worker;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hyper::client::{Body, Client};
use rustc_serialize::{Encodable, Encoder};
use rustc_serialize::json::{encode, Json};
use rustc_serialize::hex::{FromHex, ToHex};
use session_types::{session_channel, Left, Right};

use worker::worker;

use std::collections::HashMap;
use std::io::Read;
use std::fmt;
use std::mem::replace;
use std::ops::{Deref, Index, RangeFrom};
use std::thread::spawn;

/// The URL of the server
const NODE_URL: &'static str = "http://6857coin.csail.mit.edu:8080";
/// A tunable parameter; how many worker threads to spawn.
const NUM_WORKERS: usize = 100;
const BLOCK: &'static str = "bxie, emzhang, zrneely";

#[derive(Clone)]
struct Hash(Vec<u8>);
impl Encodable for Hash {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_str(&self.0.to_hex())
    }
}
impl fmt::Debug for Hash {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(fmt, "{}", self.0.to_hex())
    }
}
impl Deref for Hash {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Index<usize> for Hash {
    type Output = u8;
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}
impl Index<RangeFrom<usize>> for Hash {
    type Output = [u8];
    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        &self.0[index]
    }
}
impl Hash {
    fn to_u64(mut self, difficulty: u64) -> u64 {
        let mask = 2u64.pow(difficulty as u32) - 1;
        self.0.reverse();
        (&self.0[..]).read_u64::<LittleEndian>().unwrap() & mask
    }
}

macro_rules! be_expand {
    ($x:expr) => {{
        let mut tmp = vec![];
        tmp.write_u64::<BigEndian>($x).unwrap();
        tmp
    }};
}

#[derive(Debug, RustcEncodable, Clone)]
pub struct Block {
    version: u8,
    root: Hash,
    parent_id: Hash,
    difficulty: u64,
    timestamp: u64,
    nonces: [u64; 3],
}

#[derive(RustcEncodable)]
struct BlockForServer<'a> {
    // stupid names but required by the remote
    header: &'a Block,
    block: String,
}

impl Block {

    /// Parses json into a block.
    fn new(json: Json) -> Block {
        let json = json.as_object().expect("response not object");
        Block {
            version: json.get("version")
                         .expect("version not found")
                         .as_u64()
                         .expect("version not u64") as u8,
            root: Hash(json.get("root")
                           .expect("root not found")
                           .as_string()
                           .expect("root not string")
                           .from_hex()
                           .expect("root not hex")),
            parent_id: Hash(json.get("parentid")
                                .expect("parentid not found")
                                .as_string()
                                .expect("parentid not string")
                                .from_hex()
                                .expect("parentid not hex")),
            difficulty: json.get("difficulty")
                            .expect("difficulty not found")
                            .as_u64()
                            .expect("difficulty not u64"),
            timestamp: json.get("timestamp")
                           .expect("timestamp not found")
                           .as_u64()
                           .expect("timestamp not u64"),
            nonces: [0; 3],
        }
    }
    /// Gets a template for the next block.
    fn get_next() -> Block {
        let mut result = Client::new()
                             .get(&format!("{}/next", NODE_URL))
                             .send()
                             .expect("result not ok");
        assert_eq!(result.status, hyper::Ok);
        let input = {
            let mut input = String::new();
            result.read_to_string(&mut input).expect("could not read result");
            Json::from_str(&input).expect("result not valid json")
        };
        let block = Block::new(input);
        println!("Got new block with difficulty {}", block.difficulty);
        block
    }

    /// Tries to post this block to the public ledger.
    fn send_to_server(&self, contents: String) {
        let block_for_server = encode(&BlockForServer {
                                   header: &self,
                                   block: contents,
                               })
                                   .unwrap();
        let mut result = Client::new()
                             .post(&format!("{}/add", NODE_URL))
                             .body(Body::BufBody(block_for_server.as_bytes(),
                                                 block_for_server.len()))
                             .send()
                             .expect("result not ok");
        println!("\tSent block to server. Server Response: {}\n\n", {
            let mut response = String::new();
            result.read_to_string(&mut response).expect("could not read result");
            response
        });
    }

    /// Hashes a block using the specified nonce.
    fn hash(&self, i: usize) -> Hash {
        self.hash_with_nonce(self.nonces[i])
    }

    fn hash_with_nonce(&self, nonce: u64) -> Hash {
        let mut digest = Sha256::new();

        digest.input(&self.parent_id);
        digest.input(&self.root);
        digest.input(&be_expand!(self.difficulty));
        digest.input(&be_expand!(self.timestamp));
        digest.input(&be_expand!(nonce));
        digest.input(&[self.version]);

        let mut hash = vec![0u8; 32];
        digest.result(&mut hash);
        Hash(hash)
    }

    /// Computes the hash of a block header.
    ///
    /// Not used for mining since it includes all 3 nonces, but serves as a UID
    /// when querying the explorer.
    fn hash_for_explorer(&self) -> Hash {
        let mut digest = Sha256::new();

        digest.input(&self.parent_id);
        digest.input(&self.root);
        digest.input(&be_expand!(self.difficulty));
        digest.input(&be_expand!(self.timestamp));
        for i in 0..self.nonces.len() {
            digest.input(&be_expand!(self.nonces[i]));
        }
        digest.input(&[self.version]);

        let mut hash = vec![0u8; 32];
        digest.result(&mut hash);
        Hash(hash)
    }

    /// Constructs a block from /next header information with the specified
    /// contents.
    fn make_block(next: &Block, contents: String) -> Block {
        Block {
            version: next.version,
            root: {
                let mut digest = Sha256::new();
                digest.input_str(&contents);

                let mut hash = vec![0u8; 32];
                digest.result(&mut hash);
                Hash(hash)
            },
            parent_id: next.parent_id.clone(),
            timestamp: {
                // nanoseconds since epoch
                let time = time::now().to_timespec();
                (time.sec as u64) * 1000000000u64 + (time.nsec as u64)
            },
            difficulty: next.difficulty,
            nonces: [0; 3],
        }
    }

    /// Returns true when this block has a valid proof of work.
    fn has_valid_proof_of_work(&self) -> bool {
        if self.nonces[0] == self.nonces[1] || self.nonces[0] == self.nonces[2] ||
           self.nonces[1] == self.nonces[2] {
            return false;
        }
        let hashes = [self.hash(0).to_u64(self.difficulty),
                      self.hash(1).to_u64(self.difficulty),
                      self.hash(2).to_u64(self.difficulty)];
        if !(hashes[0] == hashes[1] && hashes[1] == hashes[2]) {
            return false;
        }
        println!("\tBlock has valid proof of work: {} {} {}",
                 hashes[0],
                 hashes[1],
                 hashes[2]);
        true
    }
}

fn main() {
    let mut total_hashes = 0;
    let mut next_block = Block::get_next();
    let mut block = Block::make_block(&next_block, BLOCK.to_string());
    let mut start_time = time::now();
    // Keep trying to solve blocks forever
    loop {
        // If we've taken too long, start over
        if (time::now() - start_time).num_minutes() >= 10 {
            println!("Taken too long; restarting.");
            next_block = Block::get_next();
            block = Block::make_block(&next_block, BLOCK.to_string());
            total_hashes = 0;
            start_time = time::now();
        }

        let mut workers_triple_send = Vec::with_capacity(NUM_WORKERS);
        for _ in 0..NUM_WORKERS {
            let (c1, c2) = session_channel();
            workers_triple_send.push(Some((spawn(move || worker(c2)), c1.send(block.clone()))));
        }

        let mut map = HashMap::new();
        for i in 0..NUM_WORKERS as u64 {
            map.insert(i, Vec::new());
        }
        // First, get triples from all the workers
        let mut workers_triples_send = Vec::with_capacity(NUM_WORKERS);
        for mut worker in workers_triple_send.into_iter() {
            let (thread, c) = worker.take().unwrap();
            let c = offer! { c,
                FOUND_TRIPLE => {
                    let (c, triple) = c.recv();
                    let target_worker = triple.end_point % NUM_WORKERS as u64;
                    let current_triples = map.get_mut(&target_worker).unwrap();
                    current_triples.push(triple);
                    c
                },
                NO_TRIPLE => { c }
            };
            workers_triples_send.push(Some((thread, c)));
        }
        // Send the triples to the appropriate workers
        let mut finished_workers = Vec::with_capacity(NUM_WORKERS);
        for i in 0..workers_triples_send.len() {
            let (thread, c) = workers_triples_send[i].take().unwrap();
            let c = c.send(replace(map.get_mut(&(i as u64)).unwrap(), vec![]));
            finished_workers.push(Some((thread, c)));
        }
        // Check the responses to see if we got any collisions
        for mut worker in finished_workers.into_iter() {
            let (thread, c) = worker.take().unwrap();
            let (c, result) = c.recv();
            if let Some(collision) = result {
                println!("Worker found collision!");
                for i in 0..3 {
                    block.nonces[i] = collision[i];
                }
            }
            c.close();
            total_hashes += thread.join().unwrap();
        }

        if block.has_valid_proof_of_work() {
            let duration = (time::now() - start_time).num_seconds();
            println!("\tSolved block in {} seconds ({} hashes/sec)\n\tNonces: {:?}",
                     duration,
                     if duration == 0 {
                         total_hashes as i64
                     } else {
                         total_hashes as i64 / duration
                     },
                     block.nonces);

            block.send_to_server(BLOCK.to_string());
            next_block = Block::get_next();
            block = Block::make_block(&next_block, BLOCK.to_string());
            total_hashes = 0;
            start_time = time::now();
        }
    }
}
