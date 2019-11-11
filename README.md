First, install Rust via the instructions from [rustup.rs](https://rustup.rs).
For MacOS and Linux users, this amounts to running the following commands:
```
# only needed if you haven't installed rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install stable
```
If you're uncomfortable with running an arbitrary script off the internet, you could use the (possibly older) version of rust packaged in your package manager, but I can't guarantee that this tutorial will compile and run on older versions of rust.

After that, use `cargo`, the standard Rust build tool, to build and run the code:
```
git clone https://github.com/Pratyush/snark-tutorial.git
cd snark-tutorial
cargo run
```
