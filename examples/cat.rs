extern crate memmap;

use std::env;
use std::io::{self, Write};
use std::fs::File;

/// Output a file's contents to stdout. The file path must be provided as the first process
/// argument.
fn main() {
    let path = env::args().nth(1).expect("supply a single path as the program argument");

    let file = File::open(path).expect("failed to open the file");

    let mmap = unsafe { memmap::file(&file) }
            .map().expect("failed to map the file");

    io::stdout().write_all(&mmap[..]).expect("failed to output the file contents");
}
