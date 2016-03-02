
use rand::distributions::{IndependentSample, Range};
use rand::thread_rng;
use time::{self, Tm};

use std::sync::{Arc, RwLock};

use Block;

#[derive(Clone, Debug, Default)]
struct Triple {
    image: u64,
    pre_1: u64,
    pre_2: Option<u64>,
}

#[derive(Debug)]
pub struct Queue {
    pub input_block: Block,
    pub solved_blocks: Vec<Block>,
    pub most_recent: Tm,
}

/// Runs a worker thread.
pub fn memory_intensive_worker(queue: Arc<RwLock<Queue>>, alpha: f64, beta: f64) {

    // Assert that the constraint on alpha and beta holds
    assert!(alpha + beta - 1f64 >= alpha / 2f64);

    let mut rng = thread_rng();

    'main: loop {
        println!("worker looping!");
        let mut block = queue.read().unwrap().input_block.clone();

        let hash = |block: &Block, inp: u64| {
            block.hash_with_nonce(inp).to_u64(block.difficulty)
        };

        let n = 2f64.powf(block.difficulty as f64) as u64;
        let n_alpha = 2f64.powf(alpha * block.difficulty as f64) as usize;
        let n_beta = 2f64.powf(beta * block.difficulty as f64) as usize;

        // Heap-allocated lists
        let mut triples = vec![Triple::default(); n_alpha];

        let range = Range::new(0, n);
        for i in 0..n_alpha {
            let a = range.ind_sample(&mut rng);
            triples[i].image = hash(&block, a);
            triples[i].pre_1 = a;
        }
        triples.sort_by_key(|t| t.image);

        let mut i = 0;
        while i < n_alpha - 1 {
            let mut j = i + 1;
            while triples[i].image == triples[j].image {
                if triples[i].pre_1 != triples[j].pre_1 {
                    if triples[i].pre_2.is_none() {
                        triples[i].pre_2 = Some(triples[j].pre_1);
                    } else {
                        if triples[i].pre_2 != Some(triples[j].pre_1) {
                            queue.write().unwrap().solved_blocks.push({
                                block.nonces = [triples[i].pre_1,
                                                triples[i].pre_2.unwrap(),
                                                triples[j].pre_1];
                                block
                            });
                            continue 'main;
                        }
                    }
                }
                j += 1;
            }
            i = j;
        }

        println!("worker finished pre-step; {} triples generated", triples.len());

        for _ in 0..n_beta {
            if queue.read().unwrap().most_recent > time::now() {
                break
            }
            let a = range.ind_sample(&mut rng);
            let b = hash(&block, a);
            if let Some(j) = triples.iter().position(|x| x.image == b) {
                if triples[j].pre_1 != a {
                    if triples[j].pre_2.is_none() {
                        triples[j].pre_2 = Some(a);
                    } else {
                        if triples[j].pre_2 != Some(a) {
                            queue.write().unwrap().solved_blocks.push({
                                block.nonces = [triples[j].pre_1,
                                                triples[j].pre_2.unwrap(),
                                                a];
                                block
                            });
                            continue 'main;
                        }
                    }
                }
            }
        }
    }
}
