//! A port of the Blackrock cipher used in [Masscan](https://github.com/robertdavidgraham/masscan) to Rust.
//!
//! Its original purpose is efficiently randomizing the order of port scans
//! without having to put every possible target in memory and shuffling.
//!
//! [Original code](https://github.com/robertdavidgraham/masscan/blob/master/src/crypto-blackrock2.c).
//!
//! The DES S-boxes have been replaced with the SipHash round function.
//!
//! # Example
//!
//! ```
//! //! Print 10 random IPv4 addresses.
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
    /// - `rounds`: The amount of times the randomization is done, to make it more random. Default is 3.
    ///
    /// ```
    /// # use perfect_rand::PerfectRng;
    /// let perfect_rng = PerfectRng::new(10, rand::random(), 3);
    /// ```
    #[must_use]
    pub fn new(range: u64, seed: u64, rounds: usize) -> Self {
        let a = ((range as f64).sqrt() as u64 + 1).next_power_of_two();
        let b = (range / a + 1).next_power_of_two();

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
    fn sipround(&self, mut v0: u64, mut v1: u64, mut v2: u64, mut v3: u64) -> (u64, u64, u64, u64) {
        v0 = v0.wrapping_add(v1);
        v2 = v2.wrapping_add(v3);
        v1 = v1.rotate_left(13) ^ v0;
        v3 = v3.rotate_left(16) ^ v2;
        v0 = v0.rotate_left(32);
    
        v2 = v2.wrapping_add(v1);
        v0 = v0.wrapping_add(v3);
        v1 = v1.rotate_left(17) ^ v2;
        v3 = v3.rotate_left(21) ^ v0;
        v2 = v2.rotate_left(32);

        (v0, v1, v2, v3)
    }

    #[inline]
    fn round(&self, j: usize, right: u64) -> u64 {
        let mut v0 = j as u64;
        let mut v1 = right;
        let mut v2 = self.seed;
        // all zeroes will lead to an all-zero output,
        // this adds some randomness for that case.
        let mut v3: u64 = 0xf3016d19bc9ad940;
        
        (v0, v1, v2, v3) = self.sipround(v0, v1, v2, v3);
        (v0, v1, v2, v3) = self.sipround(v0, v1, v2, v3);
        (v0, v1, v2, v3) = self.sipround(v0, v1, v2, v3);
        (v0, _, _, _) = self.sipround(v0, v1, v2, v3);

        return v0
    }

    #[inline]
    fn encrypt(&self, m: u64) -> u64 {
        let mut left = m & self.a_mask;
        let mut right = m >> self.a_bits;

        let mut j = 1;
        while j <= self.rounds {
            if j & 1 == 1 {
                let tmp = (left + self.round(j, right)) & self.a_mask;
                left = right;
                right = tmp;
                j += 1;
            } else {
                let tmp = (left + self.round(j, right)) & self.b_mask;
                left = right;
                right = tmp;
                j += 1;
            }
        }

        if j % 2 == 0 {
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
    use ntest::timeout;

    use super::PerfectRng;

    fn verify(range: u64, seed: u64, rounds: usize) {
        let randomizer = PerfectRng::new(range, seed, rounds);
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

    #[test]
    #[timeout(1250)]
    fn verify_ranges() {
        let mut range = 3015 * 3;

        for i in 0..5 {
            range += 11 + i;
            range *= 1 + i;

            verify(range, 0, 6);
        }

        verify(10, 0, 3);
        verify(100, 0, 3);
    }

    #[test]
    #[timeout(100)]
    fn dont_get_stuck() {
        for range in [10, 100] {
            for seed in 0..100 {
                let randomizer = PerfectRng::new(range, seed, 3);

                for i in 0..range {
                    let _ = randomizer.shuffle(i);
                }
            }
        }
    }
}
