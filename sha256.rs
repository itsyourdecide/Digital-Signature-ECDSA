pub struct Sha256 {
    h: [u32; 8],
    w: [u32; 64],
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    const INITIAL_H: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    pub fn new() -> Self {
        Self {
            h: Self::INITIAL_H,
            w: [0u32; 64],
        }
    }

    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn sigma_upper_0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn sigma_upper_1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn sigma_lower_0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn sigma_lower_1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn pad(input: &[u8]) -> Vec<u8> {
        let mut data = input.to_vec();
        let bit_len = (data.len() as u64).wrapping_mul(8);

        data.push(0x80);
        while data.len() % 64 != 56 {
            data.push(0x00);
        }
        data.extend_from_slice(&bit_len.to_be_bytes());
        data
    }

    fn process_block(&mut self, chunk: &[u8]) {
        for (i, c) in chunk.chunks_exact(4).enumerate() {
            self.w[i] = u32::from_be_bytes(c.try_into().expect("chunk size must be 4"));
        }

        for i in 16..64 {
            self.w[i] = Self::sigma_lower_1(self.w[i - 2])
                .wrapping_add(self.w[i - 7])
                .wrapping_add(Self::sigma_lower_0(self.w[i - 15]))
                .wrapping_add(self.w[i - 16]);
        }

        let mut vars = self.h;

        for i in 0..64 {
            let t1 = vars[7]
                .wrapping_add(Self::sigma_upper_1(vars[4]))
                .wrapping_add(Self::ch(vars[4], vars[5], vars[6]))
                .wrapping_add(Self::K[i])
                .wrapping_add(self.w[i]);

            let t2 =
                Self::sigma_upper_0(vars[0]).wrapping_add(Self::maj(vars[0], vars[1], vars[2]));

            vars[7] = vars[6];
            vars[6] = vars[5];
            vars[5] = vars[4];
            vars[4] = vars[3].wrapping_add(t1);
            vars[3] = vars[2];
            vars[2] = vars[1];
            vars[1] = vars[0];
            vars[0] = t1.wrapping_add(t2);
        }

        for (h_i, v_i) in self.h.iter_mut().zip(vars.iter()) {
            *h_i = h_i.wrapping_add(*v_i);
        }
    }
    
    pub fn finalize(mut self, input: &[u8]) -> [u8; 32] {
        let padded = Self::pad(input);
        
        for chunk in padded.chunks(64) {
            self.process_block(chunk);
        }

        let mut out = [0u8; 32];
        for (i, &val) in self.h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }
}

