use perfect_rand::{PerfectRng, PerfectRng32};

fn main() {
    divan::main();
}

#[divan::bench(args = [256, 65_536, 4_294_967_296, 65_536/3, 4_294_967_296/3])]
fn encrypt(range: u64) {
    let randomizer = PerfectRng::new(range, 0, 4);

    for i in 0..256 {
        let shuffled_i = randomizer.shuffle(i);
        divan::black_box(shuffled_i);
    }
}

#[divan::bench(args = [256, 65_536, 4_294_967_295, 65_536/3, 4_294_967_295/3])]
fn encrypt32(range: u32) {
    let randomizer = PerfectRng32::new(range, 0, 4);

    for i in 0..256 {
        let shuffled_i = randomizer.shuffle(i);
        divan::black_box(shuffled_i);
    }
}
