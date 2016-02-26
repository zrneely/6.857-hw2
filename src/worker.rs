
use rand::thread_rng;
use session_types::*;

use Block;

/// A tunable parameter; how many times to try to solve a block before checking for
/// info from the master.
const ATTEMPTS: u64 = 1_000_000;

pub type Working = Offer<Eps, Choose<Send<Block, Eps>, Var<Z>>>;

/// A worker:
///     1. Receives a block
///     2. Offers a choice: keep working, or abort
///     3. If we keep working, then we send either the solved block, or goto 2
pub type Worker = Recv<Block, Rec<Working>>;

/// Runs a worker thread. Returns the number of hashes this thread did.
pub fn worker(c: Chan<(), Worker>, index: usize) -> u64 {
    let mut rng = thread_rng();
    let (c, mut block) = c.recv();
    let mut c = c.enter();
    let mut hashes = 0;
    loop {
        c = offer! { c,
            CANCEL => {
                println!("\t\tworker {} is canceling", index);
                c.close();
                return hashes;
            },
            CONTINUE => {
                println!("\t\tworker {} is continuing", index);
                let (num, solved) = block.attempt_solve(&mut rng, ATTEMPTS);
                hashes += num;
                if solved {
                    println!("\t\tworker {} is finished", index);
                    c.sel1().send(block).close();
                    return hashes;
                }
                c.sel2().zero()
            }
        };
    }
}
