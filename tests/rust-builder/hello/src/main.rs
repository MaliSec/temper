extern "C" {
    fn add(a: i32, b: i32) -> i32;
}

fn main() {
    println!("{} {}", std::env::consts::ARCH, unsafe { add(40, 2) });
}
