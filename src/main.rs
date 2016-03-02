
extern crate byteorder;
extern crate crypto;
extern crate hyper;
extern crate rand;
extern crate rustc_serialize;
extern crate time;

mod worker;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hyper::client::{Body, Client};
use rustc_serialize::{Encodable, Encoder};
use rustc_serialize::json::{encode, Json};
use rustc_serialize::hex::{FromHex, ToHex};

use worker::{memory_intensive_worker, Queue};

use std::io::Read;
use std::fmt;
use std::ops::{Deref, Index, RangeFrom};
use std::thread::{spawn, yield_now};
use std::sync::{Arc, RwLock};

/// The URL of the server
const NODE_URL: &'static str = "http://6857coin.csail.mit.edu:8080";
/// A tunable parameter; how many worker threads to spawn.
const NUM_WORKERS: usize = 4;
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
    fn to_u64(self, difficulty: u64) -> u64 {
        let mask = 2u64.pow(difficulty as u32) - 1;
        (&self.0[24..]).read_u64::<BigEndian>().unwrap() & mask
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
    fn new(json: &Json) -> Block {
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
        let block = Block::new(&input);
        println!("Got new block with difficulty {}", block.difficulty);
        block
    }

    /// Gets the origin block
    fn get_origin() -> Block {
        let mut result = Client::new()
            .get("http://6857coin.csail.mit.edu:8080/block/169740d5c4711f3cbbde6b9bfbbe8b3d236879d849d1c137660fce9e7884cae7")
            .send()
            .expect("result not ok");
        assert_eq!(result.status, hyper::Ok);
        let input = {
            let mut input = String::new();
            result.read_to_string(&mut input).expect("could not read result");
            Json::from_str(&input).expect("result not valid json")
        };
        let input = input.as_object().expect("response not object")
            .get("header")
            .expect("header not found");
        let block = Block::new(input);
        println!("Got origin block with difficulty {}", block.difficulty);
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
            parent_id: next.hash_for_explorer(),
            timestamp: {
                // nanoseconds since epoch
                let time = time::now().to_timespec();
                (time.sec as u64) * 1000000000u64 + (time.nsec as u64)
                    + 5 * 60 * 1000 * 1000 * 1000
            },
            difficulty: next.difficulty,
            nonces: [0; 3],
        }
    }

    /// Returns true when this block has a valid proof of work.
    fn has_valid_proof_of_work(&self) -> bool {
        if self.nonces[0] == self.nonces[1] || self.nonces[0] == self.nonces[2] ||
           self.nonces[1] == self.nonces[2] {
            println!("nonces are equal!");
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
    let mut start_time;
    let queue = Arc::new(RwLock::new(Queue {
        input_block: {
            start_time = time::now();
            let next_block = Block::get_origin();
            Block::make_block(&next_block, BLOCK.to_string())
        },
        solved_blocks: Vec::new(),
        most_recent: time::now(),
    }));
    for _ in 0..NUM_WORKERS {
        let queue_clone = queue.clone();
        spawn(|| memory_intensive_worker(queue_clone, 0.666f64, 0.667f64));
    }
    // Keep trying to solve blocks forever
    loop {
        yield_now();
        if (time::now() - start_time).num_minutes() >= 9 {
            let mut queue = queue.write().unwrap();
            queue.input_block = {
                println!("Took too long...");
                start_time = time::now();
                let next_block = Block::get_origin();
                Block::make_block(&next_block, BLOCK.to_string())
            };
            queue.most_recent = time::now();
        }
        yield_now();
        {
            let mut queue = queue.write().unwrap();
            for block in queue.solved_blocks.drain(..) {
                assert!(block.has_valid_proof_of_work());
                println!("{:?}", block);
                block.send_to_server(BLOCK.to_string());
            }
        }
    }
}
