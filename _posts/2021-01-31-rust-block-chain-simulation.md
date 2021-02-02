---
layout: post
title: Hands on asynchronous Rust
subtitle: Learn by implementing a simple Blockchain simulation
tags: [rust, programming]
---

***Introduction***

One of the most celebrated aspects of the Rust programming language is its “fearless concurrency”. This is a sound claim as the language introduces several built-in
tools that help the programmer reason about the dangers of multithreaded and asynchronous programming. Some of these tools belong to the language’s syntactic
arsenal, e.g., moving the ownership of a variable within the scope of a closure helps us avoid sharing mutability between threads or even referencing values that no longer live:

```rust
use std::{thread};

fn main() {
    let mut numbers = vec![0,0,0,0,0,0];

    thread::spawn(move || { // 'numbers' is moved here
        for i in 0..5 {
            numbers[i] = i;
        }
    });

    thread::spawn(move || {
        for i in 0..5 {
            numbers[i] = numbers[i] + 1; // Illegal usage of 'numbers'
        }
    });
}
```

The previous code is disallowed by Rust because the ownership of the mutable variable `numbers` is taken over by the first closure. Thus there is no way--at least
by using safe Rust constructs--that we happen to use plain assignment in order to mutate variables among threads. In the next example, the same move mechanism
prevents us from referencing a value that might have already been dropped:

```rust
use std::{thread, time};

fn main() {
    let mut numbers = vec![0,0,0,0,0,0];

    thread::spawn(move || {
        for i in 0..5 {
            numbers[i] = i;
        }

        std::mem::drop(numbers); // Value is dropped
    });

    thread::spawn(move || {
        thread::sleep(time::Duration::from_millis(1000));
        for i in 0..5 {
            println!("{}", &numbers[i]); // Illegal usage of 'numbers'
        }
    });
}
```

On the other hand, some tools are more specific to Rust’s concurrency artifacts, e.g., the Arc/Mutex pattern that is useful when we want multiple execution threads to have exclusive access to a resource:

```rust
use std::sync::{Arc, Mutex};
use std::{thread, time};

fn main() {
    let counter = Arc::new(Mutex::new(0));

    let ct = Arc::clone(&counter); // 'counter' is cloned so it's not moved within thread scope
    let handle_0 = thread::spawn(move || {
        let mut num = ct.lock().unwrap(); // Lock to counter is requested

        for i in 1..=10 {
            thread::sleep(time::Duration::from_millis(50));
            *num += i;
        }
    });

    let ct = Arc::clone(&counter);
    let handle_1 = thread::spawn(move || {
        let mut num = ct.lock().unwrap();

        for i in 11..=20 {
            thread::sleep(time::Duration::from_millis(60));
            *num += i;
        }
    });

    handle_0.join().unwrap();
    handle_1.join().unwrap();

    println!("Result: {}", *counter.lock().unwrap());
}
```

However, as convenient and useful as these devices might be, writing non-trivial concurrent programs is no piece of cake and it usually involves more
sophisticated machinery that provides some guarantees about the program’s correctness and efficiency. That’s why in this article we will learn more about how to
build asynchronous programs in Rust by implementing a relatively complex project, namely, a simple simulation of a distributed Blockchain.

This article is not intended as a beginner’s tutorial on either the Rust programming language or its standard concurrency utilities. Rather we will tackle this
project by leveraging the power of some third party crates like *tokio* which already provides a nice suite of abstractions to model asynchronous programs. If
you are not familiar with the [tokio](https://docs.rs/tokio/1.0.1/tokio/index.html) crate, the official website provides a fairly comprehensive 
[tutorial](https://tokio.rs/tokio/tutorial) on its usage and specifics. Feel free to browse through it before moving on to the next sections.


<br/>

***Modeling our Blockchain***

A blockchain is simply a data structure that is distributed across a network, i.e., each node in the network has a copy and they should have some strategy
to reach consensus about which peer has the most up-to-date version so as to synchronize with it. Thus let’s forget about the networking details for a while
and let’s implement the data structure and types representing our blockchain:

```rust
use serde::{Deserialize, Serialize};

...

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockChain {
    chain: Vec<Block>,
    pub pending: PendingTransactions,
    difficulty: u8, // Difficulty must be an u8 between 1 and 80
}
```

The most comprehensive data type here, `Blockchain`, has three parts. First, we have a list of `Blocks` where each block groups multiple transactions. Next, there
is the `PendingTransactions` type which represents a set of transactions that haven’t yet been appended to the chain. This is so because multiple transactions
are first grouped before they are appended as a block. Finally, we have `difficulty`, which represents the computational effort that has to be exerted in order to
produce the hash that uniquely identifies each block in a chain. Notice that we have derived the `Serialized` and `Deserialized` traits from [serde](https://docs.rs/serde/1.0.118/serde/index.html)
as we are planning on sending blockchain copies over the network.

Pending transactions consist of a set of `Transactions` together with a map that associates an account-id with a balance--as transactions go to the pending area,
balances are modified, namely, some accounts get some coins added up while others get coins subtracted. When a set of pending transactions is appended to the
chain, it is transformed into a `Block`:

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingTransactions {
    pub current_balances: BTreeMap<AccountId, u32>,
    transactions: BTreeSet<Transaction>,
}

...

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct BlockHash(pub SHA512);

...

#[derive(Serialize, Deserialize, Eq, Debug, Clone)]
pub struct Block {
    pub payload: BlockPayload,
    pub hash: BlockHash,
}
```

A block has a hash which is computed from a `BlockPayload`. We have chosen *SHA512* as the format for our hashes, which can be computed with the aid of the
[sha2](https://docs.rs/sha2/0.9.2/sha2/) crate:

```rust
use sha2::{Digest, Sha512};

...

impl BlockPayload {
    pub fn new(
        id: BlockId,
        transactions: BTreeSet<Transaction>,
        balances: BTreeMap<AccountId, u32>,
        timestamp: DateTime<Utc>,
        previous_hash: BlockHash,
    ) -> Self {
        BlockPayload {
            id,
            transactions,
            balances,
            timestamp,
            previous_hash,
            nonce: (0, 0),
        }
    }

    pub fn compute_hash(&self) -> BlockHash {
        let payload = serde_json::to_string(&self).unwrap();
        compute_block_hash(payload.as_bytes())
    }
}

...

fn compute_block_hash(payload: &[u8]) -> BlockHash {
    let mut hasher = Sha512::new();

    hasher.update(payload);

    let result = hasher.finalize();

    BlockHash(result.as_slice().to_vec())
}
```

Thus the payload is first serialized into JSON and the encoded result is passed to `compute_block_hash` as a byte slice to be turned into a hash by the *SHA512* hasher instance.
Note that we have chosen JSON as the serialization format for this project but there is support for several others like [CBOR, MessagePack, Bincode](https://serde.rs/#data-formats), etc.
That is the beauty of *serde*: you just derive the `Serialize` and `Deserialize` traits, plug the data-format crate of your choice, and then you get encoders and decoders for your data types for free.

Back to the payload, here is its definition:

```rust
type Nonce = (usize, usize);

#[derive(Serialize, Deserialize, Eq, Debug, Clone)]
pub struct BlockPayload {
    id: BlockId,
    transactions: BTreeSet<Transaction>,
    pub balances: BTreeMap<AccountId, u32>,
    timestamp: DateTime<Utc>,
    pub previous_hash: BlockHash,
    nonce: Nonce,
}
```

A blockchain can be viewed as a linked list of blocks where each block stores the hash of the previous one. This way if the data in one block happens to be
tampered with, the hashes for all other blocks up in the chain would have to be recomputed as the hashes pointing to the previous block would no longer match.
Additionally, each block has a *nonce* which is just a pair of random numbers that are used to compute the hash that satisfies our cryptographic requirements.
We’ll talk more about how the nonce works when we implement block-appending or “mining”.

The two main kinds of data that are stored in a payload are `balances` and `transactions`. The former simply tracks each account’s number of coins and they are represented as a [BTreeMap](https://doc.rust-lang.org/std/collections/struct.BTreeMap.html). The latter, transactions, have the following representation:

```rust
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub struct AccountId(pub u64);

#[derive(Serialize, Deserialize, PartialEq, Eq, Ord, Debug, Clone)]
pub struct Transaction {
    pub from: AccountId,
    pub to: AccountId,
    pub amount: u32,
    pub timestamp: DateTime<Utc>,
}

impl PartialOrd for Transaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.timestamp.partial_cmp(&other.timestamp)
    }
}
```

They are meant to transfer an amount of coins from one account to another. We need to implement the `PartialOrd` trait for a transaction as it is inserted in a
[BtreeSet](https://doc.rust-lang.org/std/collections/struct.BTreeSet.html), which is a set based on a balanced binary tree.

<br/>

***Blockchain’s main operations***

The three main methods in a blockchain are *create blockchain*, *add transaction* and *mine block*. Creating a blockchain is the
same as implementing its constructor:

```rust
impl BlockChain {
    pub fn new(difficulty: u8) -> Self {
        let genesis_block = create_genesis_block(difficulty);
        let number_of_zeroes = match difficulty {
            n if n < 1 => 1,
            n if n > 80 => 80,
            _ => difficulty,
        };
        let mut chain = Vec::new();

        chain.push(genesis_block);

        BlockChain {
            chain,
            difficulty: number_of_zeroes,
            pending: PendingTransactions::new(BTreeMap::new(), BTreeSet::new()),
        }
    }
}
```

The constructor only receives the difficulty as an argument, which determines the number of zero bits--in our case the maximum difficulty is eighty zero bits--each
block’s hash has to start with in order to meet the cryptographic condition. The remaining of the definition is straightforward except, perhaps, for the genesis block.
Each block stores the hash of the previous one, but a blockchain has a beginning, therefore there must be an initial block that doesn’t point to any other:

```rust
const GENESIS_HASH_PAYLOAD: &'static [u8; 12] = b"genesis_hash";

fn create_genesis_block(difficulty: u8) -> Block {
    let utc: DateTime<Utc> = Utc::now();
    let previous_hash = compute_block_hash(GENESIS_HASH_PAYLOAD);
    let mut balances = BTreeMap::new();
    let coins_per_account = MAX_COINS / NUM_ACCOUNTS;

    for i in 0..NUM_ACCOUNTS {
        balances.insert(AccountId(i.into()), coins_per_account);
    }

    let mut payload = BlockPayload::new(BlockId(0), BTreeSet::new(), balances, utc, previous_hash);
    let hash = proof_of_work(difficulty, &mut payload);

    Block::new(payload, hash)
}
```

The previous hash of the genesis block is computed from a dummy payload. Additionally, the initial balances for all accounts are assigned for simplicity’s sake.
Note that computing the hash of the genesis block implies proof of work, but we will get to its implementation later.

Adding a transaction might rise several types of error:

```rust
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransactionError {
    NonexistentFromAccount,
    NonexistentToAccount,
    InsufficientBalance,
    InvalidAmount,
    SelfTransaction,
}
```

It might be that either source and destination accounts are the same, or that the transaction amount is invalid. Validating these conditions is easy:

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockChain {
    chain: Vec<Block>,
    pub pending: PendingTransactions,
    difficulty: u8, // Difficulty must be an u8 between 1 and 80
}

impl BlockChain {
    ...
 
    pub fn add_new_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<(), TransactionError> {
        ...

        if transaction.amount < 1 || transaction.amount > MAX_COINS {
            return Err(TransactionError::InsufficientBalance);
        }

        if transaction.from == transaction.to {
            return Err(TransactionError::SelfTransaction);
        }

        ...
    }
}
```

Validating if the source and destination accounts exist is a bit more involved and requires that we inspect the balances for pending transactions:

```rust
impl BlockChain {
    ...

    pub fn add_new_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<(), TransactionError> {
        if self.pending.current_balances.is_empty() {
            self.pending.current_balances = self.chain().last().unwrap().payload.balances.clone();
        }

        if transaction.amount < 1 || transaction.amount > MAX_COINS {
            return Err(TransactionError::InsufficientBalance);
        }

        if transaction.from == transaction.to {
            return Err(TransactionError::SelfTransaction);
        }
 
        ...
    }
}
```

If there are no balances available for pending transactions, we update the current balances to hold the ones that have been tracked down to the last block in
the chain. Finally, the balances from both the source and destination accounts are retrieved and if they are found, and the source account has enough balance, the
transaction is performed:

```rust
impl BlockChain {
    ...

    pub fn add_new_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<(), TransactionError> {
        ...

        let from = &transaction.from;
        let to = &transaction.to;
        let current_balances = &mut self.pending.current_balances;

        match (current_balances.get(from), current_balances.get(to)) {
            (Some(balance_from), Some(balance_to)) => {
                if *balance_from >= transaction.amount {
                    let new_balance_from = balance_from - transaction.amount;
                    let new_balance_to = balance_to + transaction.amount;

                    current_balances.insert(*from, new_balance_from);
                    current_balances.insert(*to, new_balance_to);
                } else {
                    return Err(TransactionError::InsufficientBalance);
                }
            }
            (_, None) => {
                return Err(TransactionError::NonexistentToAccount);
            }
            (None, _) => {
                return Err(TransactionError::NonexistentFromAccount);
            }
        }

        self.pending.transactions.insert(transaction);

        Ok(())
    }

    ...
}
```

Adding a new block to the chain--popularly known as “mining”--is the most  involved operation here:

```rust
impl BlockChain {
    ...
    
    pub fn mine(&mut self) -> bool {
        if self.pending.transactions.is_empty() {
            return false;
        }

        let now: DateTime<Utc> = Utc::now();
        let previous_hash = self.last_block().hash.clone();
        let transactions = std::mem::replace(&mut self.pending.transactions, BTreeSet::new());
        let balances = std::mem::replace(&mut self.pending.current_balances, BTreeMap::new());
        let mut new_payload = BlockPayload::new(
            BlockId(self.last_block().payload.id.0 + 1),
            transactions,
            balances,
            now,
            previous_hash,
        );

        ...
    }
    
    ...
}
```

First we need to get a timestamp for the current block via the `Utc` struct provided by the [chrono](https://docs.rs/chrono/0.4.19/chrono/) crate. Next, we get
the hash of the previous block by inspecting the last block in the chain, and finally we retrieve the transactions and balances in the pending area. In order to
clear up the staging area and get its current contents we use `std::mem:replace<T>(dest: &mut T, src: T)` which moves the source into the destination and returns
the destination’s previous value. Once the payload is constructed, a proof of work must be exerted in order to compute the hash of the new block:

```rust
fn proof_of_work(difficulty: u8, block_payload: &mut BlockPayload) -> BlockHash {
    let mut computed_hash = block_payload.compute_hash();
    let mut hash_was_found = false;

    for i in 0..std::usize::MAX {
        for j in 0..std::usize::MAX {
            block_payload.nonce = (i, j);

            computed_hash = block_payload.compute_hash();

            if starts_with_n_zeroes(&computed_hash, difficulty) {
                hash_was_found = true;
                break;
            };
        }

        if hash_was_found {
            break;
        };
    }

    computed_hash
}
```

The algorithm for the proof of work is sheer brute force for finding a payload’s nonce that results in computing a hash value satisfying our cryptographic
condition, i.e., the hash has a prefix made up of `n` zeroes, where `n == difficulty`:

```rust
fn starts_with_n_zeroes(hash: &BlockHash, n: u8) -> bool {
    if n == 0 {
        return true;
    }

    let mut consecutive_zeroes = 0;
    let mut non_zero_found = false;

    for i in 0..(n as usize) {
        let byte_array = byte_into_bit_array(hash.0[i]);

        for b in &byte_array {
            if *b == 0 {
                consecutive_zeroes = consecutive_zeroes + 1;
            } else {
                non_zero_found = true;
                break;
            }
        }

        if consecutive_zeroes >= n {
            return true;
        }

        if non_zero_found {
            break;
        }
    }

    false
}
```

To verify that a hash starts with `n` zeros, each one of its bytes is turned into a bit array of eight bytes, where each one of the array’s bytes represents an
individual bit of the original hash byte and is either zero or different to zero. In order to perform this transformation, we make use of Rust’s bitwise operators
`&` and `>>`: the target bit `i` in our source byte must be isolated and for that purpose we right-shift the first `7 - i` bits on the source byte so that the
target bit is pushed to the rightmost position. Subsequently, the first 7 bits on the resultant byte--the one representing the target bit--are switched to zeroes
by applying `&` against `0x1`--equivalent to 00000001.

With the bit array computed for each byte in the hash, it's trivial either to count the number of consecutive zeros until we reach a number `n >= difficulty`, or
to break the loop as soon as a nonzero bit is found in the prefix. Once the condition `starts_with_n_zeroes` is true for a given hash, the search is finished and
the nonce  gets updated to the particular value that met the condition. Then the proof of work (or hash) is returned and it's used to construct the new block:

```rust
impl BlockChain {
    ...

    pub fn mine(&mut self) -> bool {
        ...

        let proof = proof_of_work(self.difficulty, &mut new_payload);
        let new_block = Block::new(new_payload, proof);

        self.add_block(new_block)
    }

    ...
}
```

See that the final step is to add the block, which implies that we validate that the new block has correctly stored the hash of the last block and that its hash 
is a valid proof of work:

```rust
impl BlockChain {
   ...

   fn add_block(&mut self, block: Block) -> bool {
        let previous_hash = &self.last_block().hash;

        if previous_hash != &block.payload.previous_hash {
            return false;
        }

        if !is_valid_proof(self.difficulty, &block, &block.hash) {
            return false;
        }

        self.chain.push(block);

        true
    }

    ...
}

...

fn is_valid_proof(difficulty: u8, block: &Block, hash: &BlockHash) -> bool {
    starts_with_n_zeroes(hash, difficulty) && &block.payload.compute_hash() == hash
}
```

<br/>

***Validating a Blockchain***

A node will constantly request remote copies of the blockchain in order to synchronize:

```rust
impl BlockChain {
    ...

    pub fn update_chain(&mut self, other_chain: Vec<Block>) -> Result<(), ChainSyncError> {
        if other_chain.len() <= self.chain.len() {
            return Err(ChainSyncError::RemoteCopyNotLongerThanLocal);
        }

        if !BlockChain::is_valid_chain(self.difficulty, &other_chain) {
            return Err(ChainSyncError::InvalidRemoteCopy);
        }

        self.chain = other_chain;

        Ok(())
    }

    ...
}

```

In order for the synchronization to be successful, the remote chain has to be longer than the local one and it must pass an integrity test:

```rust
impl BlockChain {
    ...

    fn is_valid_chain(difficulty: u8, other_chain: &Vec<Block>) -> bool {
        let mut previous_hash = compute_block_hash(GENESIS_HASH_PAYLOAD);

        for block in other_chain {
            let other_block_hash = &block.hash;

            if previous_hash != block.payload.previous_hash {
                return false;
            }

            if !is_valid_proof(difficulty, block, &other_block_hash) {
                return false;
            }

            previous_hash = other_block_hash.clone();
        }

        true
    }
}
```

This integrity test simply checks that each block correctly stores the hash of the previous one and that its hash has a valid proof of work.

<br/>

***Node session basics***

In order to simulate our distributed network, we’ll implement a simple interactive command line session that receives user input from standard input, parses it,
and dispatches commands to the underlying node process. Several such processes can be launched and they communicate with one another via the *unix-socket*
protocol. Assume we have two nodes indexed by 0 and 1. Let’s explore how we would boot a node session and how two nodes should interact given some simple echo
commands:

![user_session_0](https://raw.githubusercontent.com/sebashack/sebashack.github.io/master/_custom_img/2021-01-31-rust-block-chain-simulation/user_session_0.png){: .mx-auto.d-block :}

We launch a node by running the `cargo run -- -n i` command where *i* is a natural number that uniquely identifies the node. Once a node starts, it’ll be ready to
receive user input so let’s see what happens when the user inputs the `ConnecTo` command:

![user_session_1](https://raw.githubusercontent.com/sebashack/sebashack.github.io/master/_custom_img/2021-01-31-rust-block-chain-simulation/user_session_1.png){: .mx-auto.d-block :}

Notice that node 1 got a connection from node 0, which is notified via standard output. The `EchoTo` command looks like this:

![user_session_2](https://raw.githubusercontent.com/sebashack/sebashack.github.io/master/_custom_img/2021-01-31-rust-block-chain-simulation/user_session_2.png){: .mx-auto.d-block :}

An `EchoTo 1` request is queued in node 0’s session and then delivered to node 1. Node 1, in turn, displays the echo message--”HELLO”--and queues a response to be
delivered to node 0. Finally, node 0 receives the response and displays it.

<br/>

***System architecture***

The following diagram depicts the overall flow and components in the interaction among several nodes:

![architecture](https://raw.githubusercontent.com/sebashack/sebashack.github.io/master/_custom_img/2021-01-31-rust-block-chain-simulation/architecture.png){: .mx-auto.d-block :}

A node can receive multiple connections from remote peers which will send commands to it. Additionally, a user can also deliver commands through an interactive
session. Both types of commands are queued via an inbound channel which is constantly polled by a task whose purpose is to dispatch the command’s values to the
appropriate handler. Once a handler is done processing its arguments, it can push a command to the outbound queue which is also permanently polled by a task that
does the actual networking and sends commands to the remote peers.

The goal of this architecture is to make the node’s internal processing as sequential as possible by avoiding the introduction of mutex containers. This is so
because as each command arrives, it's queued and processed synchronously by the handlers. We’ll see that except for some synchronization that has to be performed
in order to manipulate the state of connections, everything else within a node is treated synchronously.

<br/>

***Create and receive connections***

A node is represented by the following struct:

```rust
...

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

...

pub struct Node {
    id: NodeId,
    blockchain: BlockChain,
    inbound_receiver: Receiver<Message>,
    outbound_sender: Sender<NetCommand>,
    longest_peer_chain: (NodeId, ChainLength),
    connections: Arc<Mutex<Connections>>,
    socker_dir: PathBuf,
}

#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone, Copy, Debug)]
pub struct NodeId(pub u16);
```

There are quite a few fields in this type definition but we’ll cover each one as we progress. Let’s first focus on the process of listening to incoming 
connections. In our implementation a node can connect to many other nodes which are, in turn, connected to several others. To support this, we need to keep track 
of the established connections:

```rust
pub type Connection = (Serializer, JoinHandle<()>);
pub type Connections = (HashMap<NodeId, Connection>, Sender<Message>);
```

`Connections` is a synonym for a pair of a `HashMap` that associates a `NodeId` with a `Connection`, and the `Sender` part of a *mpsc* channel. A mpsc channel is
one in which there can be multiple producers--in our case, multiple remote peers sending requests which are queued through the sender end--but only one consumer--
the local node which consumes requests by polling the receiver end of the channel. The `Sender` in this definition isn't for direct usage but rather it's
intended to be cloned every time a connection is established so that each producer has an exclusive handle. Each `Connection` has two parts, i.e., a `Serializer`
which encodes the stream of commands that a node sends to its remote peers--more on this later--and a `JoinHandle` which is the handle for the task that is
spawned when a connection is received. Let's see how connections are received:

```rust
impl Node {
    ...

    pub async fn run_listener(node_addr: &PathBuf, connections: &Arc<Mutex<Connections>>) {
        let listener = UnixListener::bind(node_addr.as_path()).unwrap();
        let connections = Arc::clone(&connections);

        println!("Listening to incoming connections ...");

        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let pid: i32 = socket
                .peer_cred()
                .ok()
                .and_then(|creds| creds.pid())
                .expect("Couldn't get pid from peer connection");
            let peer_id = node_id_from_pid(pid);

            println!("Received connection from node `{}`", peer_id.0);

            ...
        }
    }
    
    ...
}
```

A unix-socket listener is bound to a specific file address and then that listener will start to accept incoming connections from remote peers. Once a remote
connection is accepted, it’s process id can be queried, which can subsequently be used to find the peer's `NodeId`:

```rust
use std::process::Command as ProcCommand;

...

fn node_id_from_pid(pid: i32) -> NodeId {
    let pid = pid.to_string();
    let mut cmd = String::new();

    cmd.push_str("lsof -p ");
    cmd.push_str(pid.as_str());
    cmd.push_str(" | awk '{print $9}' | grep _rusty_nodes");

    let output = ProcCommand::new("sh")
        .arg("-c")
        .arg(cmd.as_str())
        .output()
        .unwrap();
    let mut output = String::from_utf8(output.stdout).unwrap();

    output.pop();

    let path = Path::new(&output);
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .expect("Couldn't parse node's id");

    NodeId(extension.parse().expect("Couldn't parse node's id"))
}
```

Unix-sockets can conveniently be split into a reader half--`ReaderHalf<UnixStream>`, the read-only end of a socket stream--and a writer half--
`WriterHalf<UnixStream>`, the write-only end of a socket stream--so that it’s easier to decouple tasks that are in charge of receiving messages from the ones
that send them. This way the reader-half is to be passed to `reader_process`, i.e., the process in charge of receiving and deserializing the stream of data from
the remote peer:

```rust
impl Node {
    ...

    pub async fn run_listener(node_addr: &PathBuf, connections: &Arc<Mutex<Connections>>) {
            ...

            let (rd, wr): (ReadHalf<UnixStream>, WriteHalf<UnixStream>) = io::split(socket);
            let reader_process_connections = Arc::clone(&connections);
            let mut connections_guard: MutexGuard<Connections> = connections.lock().await;
            let sender = connections_guard.1.clone();
            let task_handle: JoinHandle<()> = tokio::spawn(async move {
                Node::reader_process(sender, rd, peer_id, reader_process_connections).await;
            });

            ...
        }
    }

    ...
}
```

Note that the `reader_process` is run in a spawned asynchronous task which enables each connection to have a dedicated task for message reception. Additionally,
the `sender` and `reader_process_connections` arguments are both cloned so that the newly spawned task can claim their ownership.

After the `reader_process` is spawned, the task handle together with the write half of the socket stream are then stored in the connections map where we keep
track of all the remote peers:

```rust
impl Node {
    ...

    pub async fn run_listener(node_addr: &PathBuf, connections: &Arc<Mutex<Connections>>) {
            ...

            connections_guard
                .0
                .insert(peer_id, (Node::create_serializer(wr), task_handle));
        }
    }

    ...
}
```

Note that the `Connections` map has always been manipulated via a `Mutex` wrapper so whenever it had to be mutated, the current task had to acquire the lock.

```rust
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_serde::formats::{Json, SymmetricalJson};
use tokio_serde::Framed;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

...


impl Node {
    ...

    pub async fn reader_process(
        inbound_sender: Sender<Message>,
        rd: ReadHalf<UnixStream>,
        peer_id: NodeId,
        connections: Arc<Mutex<Connections>>,
    ) {
        let length_delimited = FramedRead::new(rd, LengthDelimitedCodec::new());

        let mut serialized: Deserializer = tokio_serde::SymmetricallyFramed::new(
            length_delimited,
            SymmetricalJson::<Value>::default(),
        );

        while let Some(cmd) = serialized.try_next().await.unwrap() {
            let msg: NetCommand = serde_json::from_value(cmd).unwrap();
            inbound_sender.send(Message::NCommand(msg)).await.unwrap();
        }

        ...
    }

    ...
}
```

As the `reader_process` is in charge of queueing messages coming from a remote peer, it must frame the binary stream and deserialize the data. We could do it
manually but there’s no need to do so since we can leverage the [tokio-serde](https://docs.rs/tokio-serde/0.8.0/tokio_serde/) crate which already provides
utilities to implement a transport protocol via serde’s serialization and deserialization capabilities. Hence a deserializer is instantiated in the code above
whose type is the following:

```rust
pub type Deserializer = Framed<
    FramedRead<ReadHalf<UnixStream>, LengthDelimitedCodec>,
    Value,
    Value,
    Json<Value, Value>,
>;
```

A `Deserializer` is a stream of values decoded from a source that implements the [AsyncRead](https://docs.rs/tokio/1.0.1/tokio/io/trait.AsyncRead.html) trait. In
our case, the source is the `UnixStream` provided by the socket's read-half, and the codec used to serialize the stream is [Json](https://docs.rs/tokio-serde/0.8.0/tokio_serde/formats/struct.Json.html), that is, the remote stream is decoded into frames of type [Value](https://docs.serde.rs/serde_json/value/enum.Value.html). This serializer can be plugged into a while loop so every time there is a new deserialized value, it’ll be turned into a command and then queued for later processing. A network command has the following definition:

```rust
#[derive(Serialize, Deserialize, Debug)]
pub enum NetCommand {
    ...

    EchoToReq {
        from: NodeId,
        to: NodeId,
        message: String,
    },
    EchoToRes {
        from: NodeId,
        to: NodeId,
        message: String,
    },

    ...
}
```

Serde’s `Serialize` and `Deserialize` traits are derived so that we have our communication protocol for free. Later we will add more commands to this enumeration
but thus far we will focus on the actions to echo to a remote peer.

Coming back to the `reader_process`, when the loop is broken, it means that the remote peer has disconnected, which is why the connection is destroyed:

```rust
impl Node {
    ...

    pub async fn reader_process(
        inbound_sender: Sender<Message>,
        rd: ReadHalf<UnixStream>,
        peer_id: NodeId,
        connections: Arc<Mutex<Connections>>,
    ) {
        ...

        println!("+>> node `{}` disconnected ...", peer_id.0);

        Node::destroy_connection(peer_id, connections.lock().await).await;

        println!("+>> Connection to node `{}` removed ...", peer_id.0);
    }
    
    pub async fn destroy_connection<'a>(
        peer_id: NodeId,
        mut connections: MutexGuard<'a, Connections>,
    ) {
        match connections.0.get_mut(&peer_id) {
            Some(conn) => {
                conn.0.get_mut().get_mut().shutdown().await.unwrap();
                conn.1.abort();
            }
            None => {
                println!("+>> Connection to node `{}` doesn't exist", peer_id.0);
            }
        }

        connections.0.remove(&peer_id);
    }

    ...
}
```

And that’s it for the listener process. However, this is not the only way a node can establish a connection: as we saw in the command line example above, a user
can require the node to connect to a peer:

![user_session_1](https://raw.githubusercontent.com/sebashack/sebashack.github.io/master/_custom_img/2021-01-31-rust-block-chain-simulation/user_session_1.png){: .mx-auto.d-block :}

The user communicates with the node via an interactive session that has its own spawned task:

```rust
...

use tokio::{io, io::BufReader};
use tokio::signal;

...

use blockchain::node::{Connections, Message, NetCommand, Node, NodeId, UserCommand};

...

#[tokio::main]
async fn main() {

    ...

    let connections: Arc<Mutex<Connections>> =
        Arc::new(Mutex::new((HashMap::new(), inbound_sender)));

    ...

    // Client task
    let mut client_connections = Arc::clone(&connections);

    tokio::spawn(async move {
        use Message::UCommand;
        use UserCommand::*;

        let stdin = io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        // Client task
        while let Some(line) = lines.next_line().await.unwrap() {
            let self_node_id = node_id;
            let words: Vec<&str> = line.split_whitespace().collect();
            let words: Vec<&str> = words.iter().map(|&s| s.trim()).collect();

            match words.as_slice() {
                ["ConnectTo", peer_id] => match peer_id.parse() {
                    Ok(peer_id) => {
                        Node::connect_to_peers(
                            self_node_id,
                            vec![NodeId(peer_id)],
                            SOCKET_DIR.to_path_buf(),
                            &mut client_connections,
                        )
                        .await;
                    }
                    Err(_) => {
                        println!("+>> Couldn't parse node_id `{}`", peer_id);
                    }
                },

                ...
            }
        }
    });

    ...
}
```

Tokio has the [stdin()](https://docs.rs/tokio/1.0.1/tokio/io/fn.stdin.html) utility from which it's possible to read user input lines. This way we just need to
split each line into words and parse the arguments. For `ConnecTo` the  remote `peer_id` is parsed and wrapped in a vector so that we can pass it to
`connect_to_peers`:


```rust
impl Node {
    ...

    pub async fn connect_to_peers(
        self_node_id: NodeId,
        peer_ids: Vec<NodeId>,
        socker_dir: PathBuf,
        connections: &mut Arc<Mutex<Connections>>,
    ) {
        for peer_id in peer_ids {
            let peer_addr = Node::make_node_file_path(socker_dir.to_str().unwrap(), peer_id);
            let mut connections_guard: MutexGuard<Connections> = connections.lock().await;

            match (peer_id == self_node_id, peer_addr.exists()) {

            ...

            }

            std::mem::drop(connections_guard);
        }
    }

    ...
}
```

For each remote peer we want to connect to, the node path address is built, the lock to the connections object is acquired and, after applying some checks, a 
connection is created:

```rust
impl Node {
    ...

    pub async fn connect_to_peers(
        self_node_id: NodeId,
        peer_ids: Vec<NodeId>,
        socker_dir: PathBuf,
        connections: &mut Arc<Mutex<Connections>>,
    ) {
        for peer_id in peer_ids {
            let peer_addr = Node::make_node_file_path(socker_dir.to_str().unwrap(), peer_id);
            let mut connections_guard: MutexGuard<Connections> = connections.lock().await;

            match (peer_id == self_node_id, peer_addr.exists()) {
                (true, _) => {
                    println!("+>> Node can't connect to itself ...");
                }
                (_, false) => {
                    println!("+>> Node `{}` is not active", peer_id.0);
                }
                (false, true) => {
                    if connections_guard.0.contains_key(&peer_id) {
                        println!("+>> Already connected to node `{}`", peer_id.0);
                    } else {
                        println!("+>> Connecting to node `{}`", peer_id.0);

                        let sender = connections_guard.1.clone();
                        let (rd, wr) = Node::create_connection(peer_addr).await;

                        ...
                    }
                }
            }

            std::mem::drop(connections_guard);
        }
    }

    ...
}
```

Similar to what we did in the `listener_process`, here we are creating a socket by connecting to the given node address and then we are splitting it into a reader 
and a writer. This reader/writer pair is then used in pretty much the same way that was already explained for the listener process so there is no need to go 
deeper:

```rust
impl Node {
    ...

    pub async fn connect_to_peers(
        self_node_id: NodeId,
        peer_ids: Vec<NodeId>,
        socker_dir: PathBuf,
        connections: &mut Arc<Mutex<Connections>>,
    ) {
        for peer_id in peer_ids {
            let peer_addr = Node::make_node_file_path(socker_dir.to_str().unwrap(), peer_id);
            let mut connections_guard: MutexGuard<Connections> = connections.lock().await;

            match (peer_id == self_node_id, peer_addr.exists()) {
                (true, _) => {
                    println!("+>> Node can't connect to itself ...");
                }
                (_, false) => {
                    println!("+>> Node `{}` is not active", peer_id.0);
                }
                (false, true) => {
                    if connections_guard.0.contains_key(&peer_id) {
                        println!("+>> Already connected to node `{}`", peer_id.0);
                    } else {
                        println!("+>> Connecting to node `{}`", peer_id.0);

                        let sender = connections_guard.1.clone();
                        let (rd, wr) = Node::create_connection(peer_addr).await;
                        let reader_process_connections = Arc::clone(&connections);
                        let task_handle: JoinHandle<()> = tokio::spawn(async move {
                            Node::reader_process(sender, rd, peer_id, reader_process_connections)
                                .await;
                        });

                        connections_guard
                            .0
                            .insert(peer_id, (Node::create_serializer(wr), task_handle));
                    }
                }
            }

            std::mem::drop(connections_guard);
        }
    }
    
    ...
}
```

<br/>

***Sending an echo request to a peer***

A user can tell a node to echo a message to another, as we saw above:

![user_session_2](https://raw.githubusercontent.com/sebashack/sebashack.github.io/master/_custom_img/2021-01-31-rust-block-chain-simulation/user_session_2.png){: .mx-auto.d-block :}

This means that the user is also issuing commands to the node:

```rust
#[derive(Serialize, Deserialize, Debug)]
pub enum UserCommand {
    ...

    EchoTo {
        peer_id: NodeId,
        message: String,
    },

    ...
}
```

```rust
#[tokio::main]
async fn main() {

    ...

    tokio::spawn(async move {
        use Message::UCommand;
        use UserCommand::*;

        let stdin = io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        // Client task
        while let Some(line) = lines.next_line().await.unwrap() {
            let self_node_id = node_id;
            let words: Vec<&str> = line.split_whitespace().collect();
            let words: Vec<&str> = words.iter().map(|&s| s.trim()).collect();

            match words.as_slice() {
                ...

                ["EchoTo", peer_id, message] => match peer_id.parse() {
                    Ok(peer_id) => {
                    ...
                    }
                    Err(_) => {
                        println!("+>> Couldn't parse node_id `{}`", peer_id);
                    }
                },


                ...
            }
        }
    });

    ...
}
```

The `EchoTo` command is queued for later processing by the node:

```rust
pub struct Node {
    ...

    inbound_receiver: Receiver<Message>,

    ...
}
```

```rust
#[tokio::main]
async fn main() {
    let (inbound_sender, inbound_receiver): (Sender<Message>, Receiver<Message>) = channel(32);
    let client_sender = (&inbound_sender).clone();

    ...

    let mut node: Node = Node::new(
        node_id,
        inbound_receiver,
        outbound_sender.clone(),
        14,
        Arc::clone(&connections),
        SOCKET_DIR.to_path_buf(),
    );

    ...

    // Client task
    let mut client_connections = Arc::clone(&connections);
        tokio::spawn(async move {
        use Message::UCommand;
        use UserCommand::*;

        let stdin = io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        // Client task
        while let Some(line) = lines.next_line().await.unwrap() {
            let self_node_id = node_id;
            let words: Vec<&str> = line.split_whitespace().collect();
            let words: Vec<&str> = words.iter().map(|&s| s.trim()).collect();

            match words.as_slice() {
                ...

                ["EchoTo", peer_id, message] => match peer_id.parse() {
                    Ok(peer_id) => {
                        client_sender
                            .send(UCommand(EchoTo {
                                peer_id: NodeId(peer_id),
                                message: message.to_string(),
                            }))
                            .await
                            .unwrap();
                    }
                    Err(_) => {
                        println!("+>> Couldn't parse node_id `{}`", peer_id);
                    }
                },


                ...
            }
        }
    });

    ...
}
```

`client_sender` is a cloned sender whose receiver counterpart is the `inbound_receiver` field in the `Node` definition. `inbound_receiver` is constantly queuing
messages coming both from the `reader_process` explained before, and from the user. For this reason we need a task dedicated to polling this receiver end:

```rust
#[tokio::main]
async fn main() {
    ...

    let mut node: Node = Node::new(
        node_id,
        inbound_receiver,
        outbound_sender.clone(),
        14,
        Arc::clone(&connections),
        SOCKET_DIR.to_path_buf(),
    );

    ...

    // Node tasks
    tokio::spawn(async move {
        node.run_main_process().await;
    });

    ...
}
```

`run_main_process` is just a loop that is continuously checking if there are any commands due for processing:

```rust
impl Node {
    ...

    pub async fn run_main_process(&mut self) {
        use Message::*;
        use NetCommand::*;
        use UserCommand::*;

        while let Some(cmd) = self.inbound_receiver.recv().await {
            match cmd {
                // User commands
                UCommand(EchoTo { peer_id, message }) => {
                    self.handle_echo_to(peer_id, message).await
                }

                ...

                // Network commands
                NCommand(EchoToReq { from, message, .. }) => ...,
                NCommand(EchoToRes { message, .. }) => ...,

                ...
            }

            ...
        }
    }

    ...
}
```

Once a specific command is matched, its field values are passed to a handler, in the case of `EchoTo` to `handle_echo_to`:

```rust
impl Node {
    ...

    async fn handle_echo_to(&self, peer_id: NodeId, message: String) {
        use NetCommand::EchoToReq;

        let request = EchoToReq {
            from: self.id,
            to: peer_id,
            message,
        };

        self.outbound_sender.send(request).await.unwrap();
        println!("+>> Request queued ...");
    }

    ...
}
```

This handler builds an `EchoToReq`--queued via `outbound_sender`--to be sent to the remote peer. `outbound_sender` is another mpsc channel that is
part of the node definition and whose purpose is to queue the network commands that will be dispatched to remote peers:

```rust
#[tokio::main]
async fn main() {
    let (outbound_sender, outbound_receiver): (Sender<NetCommand>, Receiver<NetCommand>) =
        channel(32);

    ...

    let mut node: Node = Node::new(
        node_id,
        inbound_receiver,
        outbound_sender.clone(), // 'outbound sender' cloned
        14,
        Arc::clone(&connections),
        SOCKET_DIR.to_path_buf(),
    );
}
```

This naturally leads to another task which is constantly polling this queue and performs the actual networking:

```rust
#[tokio::main]
async fn main() {
    ...
    
    let (outbound_sender, outbound_receiver): (Sender<NetCommand>, Receiver<NetCommand>) =
        channel(32);
    
    ...
    
    // Node tasks
    ...

    let node_connections = Arc::clone(&connections);
    tokio::spawn(async move {
        Node::run_outbound_queue(outbound_receiver, node_connections).await;
    });

    ...
}
```

```rust
impl Node {
    ...

    pub async fn run_outbound_queue(
        mut outbound_receiver: Receiver<NetCommand>,
        connections: Arc<Mutex<Connections>>,
    ) {
        while let Some(cmd) = outbound_receiver.recv().await {
            send_message(get_net_cmd_id(&cmd), cmd, connections.lock().await).await;
        }
    }

    ...
}
```

`send_message` serializes the network command, gets the lock to the connections map and, if there is a connection to the remote node with id `peer_id`, it’ll
send the message via the `Serializer` for that connection:

```rust
pub type Serializer = Framed<
    FramedWrite<WriteHalf<UnixStream>, LengthDelimitedCodec>,
    Value,
    Value,
    Json<Value, Value>,
>;

pub type Connection = (Serializer, JoinHandle<()>);
```

To get the remote peer-id from network commands we are assuming that they must have a field named `to` with a value of type `NodeId`:

```rust
fn get_net_cmd_id(cmd: &NetCommand) -> NodeId {
    use NetCommand::*;

    match cmd {
        EchoToReq { to, .. }
        | EchoToRes { to, .. }
        | SyncWithReq { to, .. }
        | SyncWithRes { to, .. }
        | ChainLengthReq { to, .. }
        | ChainLengthRes { to, .. } => *to,
    }
}
```

More generally, we'll also assume that all network commands must also have a `from` field with the id of the node that is sending the request.

<br/>

***Receiving and replying to requests***

Now that we know how requests are sent, let’s see how they are handled from the perspective of the remote peer. As we should already know, when an `EchoToReq` is
sent the `reader_process` will receive and queue it for later processing by the main process:

```rust
impl Node {
    ...

    pub async fn run_main_process(&mut self) {
        use Message::*;
        use NetCommand::*;
        use UserCommand::*;

        while let Some(cmd) = self.inbound_receiver.recv().await {
            match cmd {
                // Network commands
                NCommand(EchoToReq { from, message, .. }) => {
                    self.handle_echo_to_req(from, message).await
                }

                ...
            }

            ...
        }
    }

    ...
}
```

The request is pattern matched and its field values passed to `handle_echo_to_req`:

```rust
impl Node {
    ...

    async fn handle_echo_to_req(&self, peer_id: NodeId, message: String) {
        use NetCommand::EchoToRes;

        println!("+>> Echo: `{}`", &message);

        let response = EchoToRes {
            from: self.id,
            to: peer_id,
            message,
        };

        self.outbound_sender.send(response).await.unwrap();
        println!("+>> Response queued ...");
    }

    ...
}
```


This handler does nothing more than printing the message from the request, building and `EchoToRes` and queueing that response for later sending to the remote
peer. When the remote peer--the one that originally sent the request--receives the response, a similar flow takes place:


```rust
...

match cmd {
    ...
    
    NCommand(EchoToRes { message, .. }) => self.handle_echo_to_res(message).await,

    ...
}

...
```

The response is pattern matched and its field values passed to `handle_echo_res`, which basically just prints the message in the response:

```rust
impl Node {
    ...

    async fn handle_echo_to_res(&self, message: String) {
        println!("+>> Echo: `{}`", &message);
    }

    ...
}
```

And with this we have completed our basic flow for sending commands to the node via the interactive user session and for sending and handling requests and
responses.

<br/>

***Synchronizing with another peer***

Once a node is connected to a remote peer, it can synchronize with it, that is, it can request the remote peer to send a list of other known peers in the network
together with a copy of its local blocakchain:

![user_session_3](https://raw.githubusercontent.com/sebashack/sebashack.github.io/master/_custom_img/2021-01-31-rust-block-chain-simulation/user_session_3.png){: .mx-auto.d-block :}

The first step is to add the new user command to the interactive session:

```rust
#[derive(Serialize, Deserialize, Debug)]
pub enum UserCommand {
    ...

    SyncWith {
        peer_id: NodeId,
    },

    ...
}
```

```rust
#[tokio::main]
async fn main() {

    ...

    tokio::spawn(async move {
        use Message::UCommand;
        use UserCommand::*;

        let stdin = io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        // Client task
        while let Some(line) = lines.next_line().await.unwrap() {
            let self_node_id = node_id;
            let words: Vec<&str> = line.split_whitespace().collect();
            let words: Vec<&str> = words.iter().map(|&s| s.trim()).collect();

            match words.as_slice() {
                ...

                ["SyncWith", peer_id] => match peer_id.parse() {
                    Ok(peer_id) => {
                        client_sender
                            .send(UCommand(SyncWith {
                                peer_id: NodeId(peer_id),
                            }))
                            .await
                            .unwrap();
                    }
                    Err(_) => {
                        println!("+>> Couldn't parse node_id `{}`", peer_id);
                    }
                },

                ...
            }
        }
    });

    ...
}
```

Thus the user command will be queued by the local node and processed by `handle_sync_with`, which just sends a synchronization request to the peer it wants to
sync with:


```rust
match cmd {
    ...

    UCommand(SyncWith { peer_id }) => self.handle_sync_with(peer_id).await,

    ...
}
```

```rust
impl Node {
    ...

    async fn handle_sync_with(&self, peer_id: NodeId) {
        use NetCommand::SyncWithReq;

        let request = SyncWithReq {
            from: self.id,
            to: peer_id,
        };

        self.outbound_sender.send(request).await.unwrap();
        println!("+>> Request queued ...");
    }

    ...
}
```

The remote peer on receiving this request will proceed to create a `SyncWithRes` by gathering its list of known peers and creating a copy of its local blockchain:

```rust
match cmd {
    ...

    NCommand(SyncWithReq { from, .. }) => self.handle_sync_with_req(from).await,

    ...
}
```

```rust
impl Node {
    ...

    async fn handle_sync_with_req(&self, peer_id: NodeId) {
        use NetCommand::SyncWithRes;

        let connections_guard: MutexGuard<Connections> = self.connections.lock().await;
        let mut known_peers = Vec::new();

        for node_id in connections_guard.0.keys() {
            if !(*node_id == self.id || *node_id == peer_id) {
                known_peers.push(*node_id);
            }
        }

        std::mem::drop(connections_guard);

        let response = SyncWithRes {
            from: self.id,
            to: peer_id,
            known_peers,
            chain: self.blockchain.chain().clone(),
        };

        self.outbound_sender.send(response).await.unwrap();
        println!("+>> Response queued ...");
    }

    ...
}
```

Finally, the local node on receiving the response will attempt to synchronize with the remote peer:


```rust
match cmd {
    ...

    NCommand(SyncWithRes {
        from,
        known_peers,
        chain,
        ..
    }) => self.handle_sync_with_res(from, known_peers, chain).await,

    ...
}
```

```rust
impl Node {
    ...

    async fn handle_sync_with_res(
        &mut self,
        peer_id: NodeId,
        known_peers: Vec<NodeId>,
        chain: Vec<Block>,
    ) {
        use ChainSyncError::*;

        Node::connect_to_peers(
            self.id,
            known_peers,
            self.socker_dir.clone(),
            &mut Arc::clone(&self.connections),
        )
        .await;

        match self.blockchain.update_chain(chain) {
            Ok(()) => {
                println!(
                    "+>> Local blockchain has been synchronized with node `{}`",
                    peer_id.0
                );
            }
            Err(InvalidRemoteCopy) => {
                println!(
                    "+>> WARNING: Remote copy of blockchain isn't valid. Can't sync blockchain with node `{}`",
                    peer_id.0
                );

                Node::destroy_connection(peer_id, self.connections.lock().await).await;

                println!("+>> WARNING: Connecion with node `{}` destroyed", peer_id.0);
            }
            Err(RemoteCopyNotLongerThanLocal) => {
                println!("+>> Remote copy of blockchain isn't longer than local.");
            }
        }
    }

    ...
}
```

For the list of known peers the node will attempt to connect to each one by calling the `connect_to_peers` utility explained above. Then it will try to update
its local blockchain, which might fail either if the remote chain is shorter than the local one or if the remote chain is invalid


<br/>

***Make transactions, mine and get balance***

The following operations only affect the state of the local Blockchain and don’t trigger any further interaction with a remote peer:

```rust
#[derive(Serialize, Deserialize, Debug)]
pub enum UserCommand {
    ...

    MakeTransaction {
        from: AccountId,
        to: AccountId,
        amount: u32,
    },
    Mine,
    GetBalance {
        account_id: AccountId,
    },

    ...
}
```

Making a transaction makes use of the `handle_add_transaction` method which, in turn, just calls the `add_new_transaction` method defined for a blockchain:

![user_session_4](https://raw.githubusercontent.com/sebashack/sebashack.github.io/master/_custom_img/2021-01-31-rust-block-chain-simulation/user_session_4.png){: .mx-auto.d-block :}

```rust
impl Node {
    ...

    fn handle_add_transaction(&mut self, from: AccountId, to: AccountId, amount: u32) {
        use TransactionError::*;

        let timestamp: DateTime<Utc> = Utc::now();
        let tx = Transaction {
            from,
            to,
            amount,
            timestamp,
        };

        match self.blockchain.add_new_transaction(tx) {
            Ok(_) => {
                println!("+>> Transaction of `{}` coin(s) from account `{}` to account `{}` performed successfully", amount, from.0, to.0);
            }
            Err(NonexistentFromAccount) => {
                println!("+>> Account `{}` doesn't exist", from.0);
            }
            Err(NonexistentToAccount) => {
                println!("+>> Account `{}` doesn't exist", to.0);
            }
            Err(InsufficientBalance) => {
                println!(
                    "+>> Account `{}` doesn't have enough balance to perform transaction",
                    from.0
                );
            }
            Err(InvalidAmount) => {
                println!("+>> Amount must be between 1 and {}", MAX_COINS);
            }
            Err(SelfTransaction) => {
                println!("+>> Accounts `from` and `to` cannot be the same");
            }
        }
    }

    ...
}
```

Similarly, mining requires us to call the `handle_mining` method which uses the mine method defined for a blockchain. Notice that if after a new block is added
the local chain turns out to be longer than the length stored in `self.longest_peer_chain`, this node’s field is updated. We’ll explain later the purpose of the
`longest_peer_chain` field when we talk about how to implement a simple consensus strategy.

![user_session_5](https://raw.githubusercontent.com/sebashack/sebashack.github.io/master/_custom_img/2021-01-31-rust-block-chain-simulation/user_session_5.png){: .mx-auto.d-block :}

```rust
impl Node {
    ...

    fn handle_mining(&mut self) {
        let was_block_added = self.blockchain.mine();

        if was_block_added {
            let chain_length = self.blockchain.chain().len();
            let longest_peer_chain = self.longest_peer_chain.1;

            if chain_length > longest_peer_chain {
                self.longest_peer_chain.0 = self.id;
                self.longest_peer_chain.1 = chain_length;
            }

            let last_block_id = self.blockchain.last_block().id().0;

            println!(
                "+>> Mining sucessfully processed: a new block with id {} has been added",
                last_block_id
            );
        } else {
            println!("+>> WARNING: Empty pool of pending transactions");
        }
    }

    ...
}
```

Finally, getting an account’s balance is done through the `handle_get_balance` handler which searches the last block’s balances in case there are no balances
stored for the pending transactions. If the balance for the specific account is found, it’ll be printed in standard output, otherwise there will be a log telling
the user that the given account wasn't found:

![user_session_6](https://raw.githubusercontent.com/sebashack/sebashack.github.io/master/_custom_img/2021-01-31-rust-block-chain-simulation/user_session_6.png){: .mx-auto.d-block :}


```rust
impl Node {
    ...

    async fn handle_get_balance(&self, account_id: AccountId) {
        let balances = if self.blockchain.pending.current_balances.is_empty() {
            &self.blockchain.last_block().payload.balances
        } else {
            &self.blockchain.pending.current_balances
        };

        match balances.get(&account_id) {
            Some(b) => {
                println!("+>> Balance: {}", b);
            }
            None => {
                println!("+>> Couldn't find account with id `{}`", account_id.0);
            }
        }
    }

    ...
}
```

<br/>

***A naive consensus implementation***

So far we have implemented a simple networking mechanism that allows each node to synchronize with other nodes and a user can perform some operations on the
blockchain. Nevertheless, if a peer in the network has been appending blocks to its chain, the other members will be unaware of this and won’t have a way to
synchronize its local Blockchain against the most up-to-date copy. In order to solve this, we need to implement some sort of consensus between the nodes so that
each one agrees upon which remote peer has the most up-to-date chain and requests a copy for synchronization.

Our strategy will be simple: for all the peers known by a node, send a request asking for the length of their blockchain:

```rust
impl Node {
    ...

    pub async fn run_consensus_process(
        self_node_id: NodeId,
        connections: Arc<Mutex<Connections>>,
        mut sender: Sender<Message>,
    ) {
        use tokio::time::{sleep, Duration};

        loop {
            let connections_guard: MutexGuard<Connections> = connections.lock().await;

            Node::sync_longest_peer_chain(self_node_id, connections_guard, &mut sender).await;
            sleep(Duration::from_millis(POLL_DELAY)).await;
        }
    }

    async fn sync_longest_peer_chain<'a>(
        self_node_id: NodeId,
        connections: MutexGuard<'a, Connections>,
        sender: &mut Sender<Message>,
    ) {
        use Message::NCommand;
        use NetCommand::ChainLengthReq;

        for peer_id in connections.0.keys() {
            let request = NCommand(ChainLengthReq {
                from: self_node_id,
                to: *peer_id,
            });

            sender.send(request).await.unwrap();
        }
    }

    ...
}
```

`sync_longest_peer_chain` is the method that iterates over all the known peers. Notice that it's permanently called in an infinite loop with a delay between each
call.

On receiving this request, the remote peer just queries its chain’s size and sends a response back to the requester:


```rust
impl Node {
    ...
    
    async fn handle_chain_length_req(&self, peer_id: NodeId) {
        use NetCommand::ChainLengthRes;

        let chain_length = self.blockchain.chain().len();
        let response = ChainLengthRes {
            from: self.id,
            to: peer_id,
            chain_length,
        };

        self.outbound_sender.send(response).await.unwrap();
    }

    ...
}
```

On the other side, when receiving the response, the requester checks if the remote chain is longer than its local copy and, if so, it’ll perform an update of the
`longest_peer_chain` node’s field:

```rust
type ChainLength = usize;

pub struct Node {
    ...

    longest_peer_chain: (NodeId, ChainLength),

    ...
}

impl Node {
    ...

    async fn handle_chain_length_res(&mut self, peer_id: NodeId, chain_length: usize) {
        if chain_length > self.longest_peer_chain.1 {
            println!(
                "+>> Longer chain detected in node `{}`. Length: {}",
                peer_id.0, chain_length
            );

            self.longest_peer_chain.0 = peer_id;
            self.longest_peer_chain.1 = chain_length;
        }
    }

    ... 
}
```
As we saw above `run_consensus_process` is a process that constantly queries remote peers. Thus it has to be executed in its own task:

```rust
#[tokio::main]
async fn main() {

    ...

    let consensus_connections = Arc::clone(&connections);
    tokio::spawn(async move {
        Node::run_consensus_process(node_id, consensus_connections, consensus_sender).await;
    });

    ...
}
```

Now we are just missing the procedure of actually requesting the remote copy of the blockchain and updating the local state. For that we just need to add some
extra code on the node’s main process:

```rust
impl Node {
    ...

    pub async fn run_main_process(&mut self) {
        use Message::*;
        use NetCommand::*;
        use UserCommand::*;

        while let Some(cmd) = self.inbound_receiver.recv().await {
            ...

            if self.longest_peer_chain.1 > self.blockchain.chain().len() {
                let peer_id = self.longest_peer_chain.0;
                let request = SyncWithReq {
                    from: self.id,
                    to: peer_id,
                };

                self.outbound_sender.send(request).await.unwrap();
            }
        }
    }

    ...
}
```

If the `longest_peer_chain` field has information about a peer whose chain is bigger than the local one, then a `SyncWithReq` will be sent to that peer and we
have already explained how the synchronization process happens.

<br/>

***Final remarks***

This is it for our simulation of a blockchain. We dealt with a number of topics that are usually involved when implementing networking asynchronous programs,
namely, socket endpoints, communication formats, serialization/deserialization of binary streams of data, mpsc channels, concurrent tasks with tokio, etc.
Nevertheless, this is by no means a thorough implementation of a blockchain distributed system: on the one hand, our proof of work is a simplified version of
the [Hashcash](https://en.wikipedia.org/wiki/Hashcash) algorithm used in Bitcoin where the number of zeroes specified in the cryptographic constraint determines
the amount of computational work to be exerted. On the other hand, our consensus strategy is really susceptible to run into data inconsistencies, e.g, it might
happen that users issue commands to make and mine transactions which are queued before a command to update the local chain. This would lead to the deletion of
those transactions that were recently appended. Safe manipulation of shared state in a distributed system is beyond the scope of this article, but I hope that
after reading this, you’ll have a taste of what it's like doing asynchronous programming in Rust.

You can scour the whole source code [here](https://gitlab.com/sebashack/rusty_chain/-/tree/master).
