//! A private, local DHT for testing FilePigeon's DHT discovery without touching
//! the public network. Prints a bootstrap list for `FILEPIGEON_DHT_BOOTSTRAP`.
//!
//!     cargo run --example dht_testnet

fn main() -> std::io::Result<()> {
    let testnet = mainline::Testnet::builder(8).build()?;
    println!("FILEPIGEON_DHT_BOOTSTRAP={}", testnet.bootstrap.join(","));
    println!("Local DHT with {} nodes running. Ctrl+C to stop.", testnet.nodes.len());
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
