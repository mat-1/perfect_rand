//! A port of the Blackrock cipher used in masscan to Rust.
//!
//! It's primarily meant for efficiently randomizing the order of port scans,
//! without having to put every possible target in memory and shuffling.
//!
//! Original code: https://github.com/robertdavidgraham/masscan/blob/master/src/crypto-blackrock2.c
//!
//! # Example
//!
//! ```
//! //! Print 10 random Ipv4 addresses.
//!
//! # use std::net::Ipv4Addr;
//! # use perfect_rand::PerfectRng;
//!
//! let randomizer = PerfectRng::from_range(2u64.pow(32));
//! for i in 0..10 {
//!     let randomized_ip = Ipv4Addr::from(randomizer.shuffle(i) as u32);
//!     println!("{randomized_ip:?}");
//! }
//! ```

// Expanded DES S-boxes
#[rustfmt::skip]
const SB1: [u32; 64] = [
    0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400,
    0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400,
    0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004,
    0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000,
    0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004,
    0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404,
    0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000,
    0x00010004, 0x00010400, 0x00000000, 0x01010004
];
#[rustfmt::skip]
const SB2: [u32; 64] = [
    0x80108020, 0x80008000, 0x00008000, 0x00108020,
    0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000,
    0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000,
    0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000,
    0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020,
    0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020,
    0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020,
    0x80000000, 0x80100020, 0x80108020, 0x00108000
];
#[rustfmt::skip]
const SB3: [u32; 64] = [
    0x00000208, 0x08020200, 0x00000000, 0x08020008,
    0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000,
    0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200,
    0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208,
    0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208,
    0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200,
    0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208,
    0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000,
    0x00020208, 0x00000008, 0x08020008, 0x00020200
];

#[rustfmt::skip]
const SB4: [u32; 64] = [
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080,
    0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001,
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000,
    0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002000, 0x00802080
];

#[rustfmt::skip]
const SB5: [u32; 64] = [
    0x00000100, 0x02080100, 0x02080000, 0x42000100,
    0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100,
    0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000,
    0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000,
    0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000,
    0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100,
    0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100,
    0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000,
    0x00000000, 0x40080000, 0x02080100, 0x40000100
];
#[rustfmt::skip]
const SB6: [u32; 64] = [
    0x20000010, 0x20400000, 0x00004000, 0x20404010,
    0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010,
    0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000,
    0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000,
    0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000,
    0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010,
    0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010,
    0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000,
    0x20404000, 0x20000000, 0x00400010, 0x20004010
];

const SB7: [u32; 64] = [
    0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002, 0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802, 0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800, 0x04000002, 0x04000800, 0x00000800, 0x00200002,
];

const SB8: [u32; 64] = [
    0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000, 0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000, 0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040, 0x00001040, 0x00040040, 0x10000000, 0x10041000,
];

#[derive(Default, Debug)]
pub struct PerfectRng {
    range: u64,
    // a: u64,
    // b: u64,
    seed: u64,
    rounds: usize,
    a_bits: u32,
    a_mask: u64,
    // b_bits: u32,
    b_mask: u64,
}

fn count_bits(num: u64) -> u32 {
    let mut bits = 0;
    while (num >> bits) > 1 {
        bits += 1;
    }
    bits
}

impl PerfectRng {
    /// Create a new perfect cipher with a specific range, seed, and rounds.
    /// Use [`PerfectRng::from_range`] to use the default seed and rounds.
    ///
    /// - `range`: The highest value you will try to shuffle. For example, this
    /// would be 2**32 for an IPv4 address.
    /// - `seed`: The seed used for randomization.
    /// - `rounds`: The amount of times the randomization is done, to make it more random.
    #[must_use]
    pub fn new(range: u64, seed: u64, rounds: usize) -> Self {
        let a = ((range as f64).sqrt() as u64).next_power_of_two();
        let b = (range / a).next_power_of_two();

        PerfectRng {
            range,
            // a,
            // b,
            seed,
            rounds,
            a_bits: count_bits(a),
            a_mask: a - 1,
            // b_bits: count_bits(b),
            b_mask: b - 1,
        }
    }

    /// Create a new `PerfectRng` with a random seed and default rounds.
    ///
    /// ```
    /// # use perfect_rand::PerfectRng;
    /// let perfect_rng = PerfectRng::from_range(2u64.pow(32));
    /// ```
    #[must_use]
    pub fn from_range(range: u64) -> Self {
        Self::new(range, rand::random(), 3)
    }

    #[inline]
    fn round(&self, j: usize, right: u64) -> u64 {
        let t = right ^ ((self.seed >> j) | (self.seed << (64 - j)));

        if j % 2 != 0 {
            (SB8[(t & 0x3F) as usize] as u64)
                ^ (SB6[((t >> 8) & 0x3F) as usize] as u64)
                ^ (SB4[((t >> 16) & 0x3F) as usize] as u64)
                ^ (SB2[((t >> 24) & 0x3F) as usize] as u64)
        } else {
            (SB7[(t & 0x3F) as usize] as u64)
                ^ (SB5[((t >> 8) & 0x3F) as usize] as u64)
                ^ (SB3[((t >> 16) & 0x3F) as usize] as u64)
                ^ (SB1[((t >> 24) & 0x3F) as usize] as u64)
        }
    }

    #[inline]
    fn encrypt(&self, m: u64) -> u64 {
        let mut left = m & self.a_mask;
        let mut right = m >> self.a_bits;

        let mut j = 1;
        while j <= self.rounds {
            let tmp = (left + self.round(j, right)) & self.a_mask;
            left = right;
            right = tmp;
            j += 1;

            let tmp = (left + self.round(j, right)) & self.b_mask;
            left = right;
            right = tmp;
            j += 1;
        }

        if self.rounds % 2 != 0 {
            (left << self.a_bits) + right
        } else {
            (right << self.a_bits) + left
        }
    }

    // fn decrypt(&self, m: u64) -> u64 {
    //     let mut right;
    //     let mut left;
    //     let mut tmp;

    //     if self.rounds % 2 != 0 {
    //         right = m % self.a;
    //         left = m / self.a;
    //     } else {
    //         left = m % self.a;
    //         right = m / self.a;
    //     }

    //     for j in (1..=self.rounds).rev() {
    //         if j & 1 != 0 {
    //             tmp = self.round(j, left);
    //             if tmp > right {
    //                 tmp = tmp - right;
    //                 tmp = self.a - (tmp % self.a);
    //                 if tmp == self.a {
    //                     tmp = 0;
    //                 }
    //             } else {
    //                 tmp = right - tmp;
    //                 tmp %= self.a;
    //             }
    //         } else {
    //             tmp = self.round(j, left);
    //             if tmp > right {
    //                 tmp = tmp - right;
    //                 tmp = self.b - (tmp % self.b);
    //                 if tmp == self.b {
    //                     tmp = 0;
    //                 }
    //             } else {
    //                 tmp = right - tmp;
    //                 tmp %= self.b;
    //             }
    //         }
    //         right = left;
    //         left = tmp;
    //     }

    //     self.a * right + left
    // }

    /// Randomize your input.
    ///
    /// ```
    /// # use perfect_rand::PerfectRng;
    ///
    /// let randomizer = PerfectRng::from_range(100);
    /// for i in 0..100 {
    ///     let shuffled_i = randomizer.shuffle(i);
    ///     assert!(shuffled_i <= 100);
    /// }
    /// ```
    #[must_use]
    pub fn shuffle(&self, m: u64) -> u64 {
        let mut c = self.encrypt(m);
        while c >= self.range {
            c = self.encrypt(c);
        }
        c
    }

    // pub fn unshuffle(&self, m: u64) -> u64 {
    //     let mut c = self.decrypt(m);
    //     while c >= self.range {
    //         c = self.decrypt(c);
    //     }
    //     c
    // }
}

#[cfg(test)]
mod tests {
    use super::PerfectRng;

    #[test]
    fn verify() {
        let mut range = 3015 * 3;

        for i in 0..5 {
            range += 11 + i;
            range *= 1 + i;

            let randomizer = PerfectRng::new(range, 0, 6);
            println!("randomizer: {randomizer:?}");

            // make sure every number gets added exactly once
            let mut list = vec![0; range as usize];
            for i in 0..range {
                let x = randomizer.shuffle(i) as usize;
                list[x] += 1;
            }

            for (i, number) in list.into_iter().enumerate() {
                assert_eq!(number, 1, "Index: {i}, range: {range:?}");
            }
        }
    }
}
