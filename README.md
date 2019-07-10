First, install rust via:

```
# only needed if you haven't installed rust
curl https://sh.rustup.rs -sSf | sh
rustup install nightly
```

After that, use `cargo`, the standard Rust build tool, to build and run the examples:

```
git clone https://github.com/Pratyush/snark-tutorial.git
cd snark-tutorial
rustup override set nightly
cargo run
```
