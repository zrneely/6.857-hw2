
extern crate byteorder;
extern crate crypto;
extern crate hyper;
extern crate rand;
extern crate rustc_serialize;
extern crate time;

use byteorder::{BigEndian, WriteBytesExt};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hyper::client::{Body, Client};
use rand::distributions::{IndependentSample, Range};
use rustc_serialize::{Encodable, Encoder};
use rustc_serialize::json::{Json};
use rustc_serialize::hex::{FromHex, ToHex};

use std::io::Read;
use std::fmt;
use std::ops::{Deref, Index, RangeFrom};

/// The URL of the server
const NODE_URL: &'static str = "http://6857coin.csail.mit.edu:8080";

const BLOCK: &'static str = "Benjamin Xie, Emily Zhang, Zachary Neely";

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

macro_rules! be_expand {
    ($x:expr) => {{
        let mut tmp = vec![];
        tmp.write_u64::<BigEndian>($x).expect("wtf");
        tmp
    }};
}

#[derive(Debug, RustcEncodable)]
struct Block {
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
            version: json.get("version").expect("version not found")
                .as_u64().expect("version not u64") as u8,
            root: Hash(json.get("root").expect("root not found")
                .as_string().expect("root not string")
                .from_hex().expect("root not hex")),
            parent_id: Hash(json.get("parentid").expect("parentid not found")
                .as_string().expect("parentid not string")
                .from_hex().expect("parentid not hex")),
            difficulty: json.get("difficulty").expect("difficulty not found")
                .as_u64().expect("difficulty not u64"),
            timestamp: json.get("timestamp").expect("timestamp not found")
                .as_u64().expect("timestamp not u64"),
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
        Block::new(input)
    }

    /// Tries to post this block to the public ledger.
    fn send_to_server(&self, contents: String) {
        let block_for_server = rustc_serialize::json::encode(&BlockForServer {
            header: &self,
            block: contents,
        }).unwrap();
        let mut result = Client::new()
            .post(&format!("{}/add", NODE_URL))
            .body(Body::BufBody(block_for_server.as_bytes(), block_for_server.len()))
            .send()
            .expect("result not ok");
        println!("\tSent block to server. Server Response: {}", {
            let mut response = String::new();
            result.read_to_string(&mut response).expect("could not read result");
            response
        });
    }

    /// Hashes a block using the specified nonce.
    fn hash(&self, i: usize) -> Hash {
        let mut digest = Sha256::new();

        digest.input(&self.parent_id);
        digest.input(&self.root);
        digest.input(&be_expand!(self.difficulty));
        digest.input(&be_expand!(self.timestamp));
        digest.input(&be_expand!(self.nonces[i]));
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

    /// Sets the 3 nonces to random values
    fn randomize_nonces(&mut self, rng: &mut rand::ThreadRng) {
        let range = Range::new(0, 2u64.pow(self.difficulty as u32));
        self.nonces[0] = range.ind_sample(rng);
        self.nonces[1] = range.ind_sample(rng);
        self.nonces[2] = range.ind_sample(rng);
        // panic!("Any method involving this function is way to fucking slow!");
    }

    /// Find a valid proof of work (nonce triple) for this block.
    fn solve(&mut self, rng: &mut rand::ThreadRng) {
        while !self.has_valid_proof_of_work() {
            self.randomize_nonces(rng);
        }
    }

    /// Returns true when this block has a valid proof of work.
    fn has_valid_proof_of_work(&self) -> bool {
        let max_full = self.difficulty / 8;
        let partial_mask = ((2u64.pow((self.difficulty % 8u64) as u32)) - 1) as u8;
        let hashes = [self.hash(0), self.hash(1), self.hash(2)];
        for i in 0..max_full {
            let byte0 = hashes[0][31 - i as usize];
            let byte1 = hashes[1][31 - i as usize];
            let byte2 = hashes[2][31 - i as usize];
            if !(byte0 == byte1 && byte1 == byte2) {
                return false;
            }
        }
        let byte0 = hashes[0][31 - max_full as usize] & partial_mask;
        let byte1 = hashes[1][31 - max_full as usize] & partial_mask;
        let byte2 = hashes[2][31 - max_full as usize] & partial_mask;
        if !(byte0 == byte1 && byte1 == byte2) {
            return false;
        }
        if self.nonces[0] == self.nonces[1] ||
           self.nonces[0] == self.nonces[2] ||
           self.nonces[1] == self.nonces[2] {
            return false;
        }
        println!("\tBlock has valid proof of work: {} {} {}",
                 hashes[0][(31 - (max_full / 2 + 1)) as usize..].to_hex(),
                 hashes[1][(31 - (max_full / 2 + 1)) as usize..].to_hex(),
                 hashes[2][(31 - (max_full / 2 + 1)) as usize..].to_hex());
        true
    }
}

fn main() {
    let mut rng = rand::thread_rng();
    loop {
        let next_block = Block::get_next();
        let mut block = Block::make_block(&next_block, BLOCK.to_string());
        block.difficulty = 11;
        println!("Got new block:\n\t{:?}", block);

        println!("\tBlock solved in {} seconds",
                 time::Duration::span(|| block.solve(&mut rng)).num_seconds());

        println!("\tSolved block! {:?}", block.nonces);
        block.send_to_server(BLOCK.to_string());
    }
}
