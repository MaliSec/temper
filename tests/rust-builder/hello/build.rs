// Compiles src/add.c with the image's C toolchain, as crates with C code do.
use std::{env, path::PathBuf, process::Command};

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("start");
    assert!(status.success(), "{cmd:?} failed");
}

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    run(Command::new("cc").args(["-c", "-fPIC", "src/add.c", "-o"]).arg(out.join("add.o")));
    run(Command::new("ar").arg("crs").arg(out.join("libadd.a")).arg(out.join("add.o")));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=add");
    println!("cargo:rerun-if-changed=src/add.c");
}
