use perfect_rand::PerfectRng;

fn main() {
    // Run registered benchmarks.
    divan::main();
}

// Register a `fibonacci` function and benchmark it over multiple cases.
#[divan::bench(args = [256, 65_536, 4_294_967_296, 65_536/3, 4_294_967_296/3])]
fn encrypt(range: u64) {
    let randomizer = PerfectRng::new(range, rand::random(), 4);

    for i in 0..256 {
        let shuffled_i = randomizer.shuffle(i);
        divan::black_box(shuffled_i);
    }
}
