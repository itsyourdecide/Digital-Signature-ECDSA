#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const P: Self = Self([
        0xFFFF_FFFE_FFFF_FC2F,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ]);

    pub const N: Self = Self([
        0xBFD2_5E8C_D036_4141, 
        0xBAAE_DCE6_AF48_A03B, 
        0xFFFF_FFFF_FFFF_FFFE, 
        0xFFFF_FFFF_FFFF_FFFF
    ]);

    const C_VALUE: u64 = 0x1_0000_03D1;

    pub const ONE: Self = Self([1, 0, 0, 0]);
    pub const P_MINUS_2: Self = Self([0xFFFF_FFFE_FFFF_FC2D, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF]);
    pub const N_MINUS_2: Self = Self([0xBFD2_5E8C_D036_413F, 0xBAAE_DCE6_AF48_A03B, 0xFFFF_FFFF_FFFF_FFFE, 0xFFFF_FFFF_FFFF_FFFF]);


    pub fn is_greater_or_equal(&self, other: &U256) -> bool {
        for i in (0..4).rev() {
            if self.0[i] > other.0[i] {
                return true;
            } else if self.0[i] < other.0[i] {
                return false;
            }
        }
        true
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    pub fn add_mod(a: &U256, b: &U256, modulus: &U256) -> U256 {
        let mut carry: u128 = 0;
        let mut res_array = [0u64; 4];
        for i in 0..4 {
            let sum = a.0[i] as u128 + b.0[i] as u128 + carry;
            res_array[i] = sum as u64;
            carry = sum >> 64;
        }

        let mut result = U256(res_array);

        if carry > 0 || result.is_greater_or_equal(modulus) {
            result = Self::sup_row(&result, modulus);
        }
        result
    }

    pub fn sup_row(a: &U256, b: &U256) -> U256 {
        let mut borrow: i128 = 0;
        let mut res_array = [0u64; 4];
        for i in 0..4 {
            let mut diff = a.0[i] as i128 - b.0[i] as i128 - borrow;
            if diff < 0 {
                diff += 1 << 64;
                borrow = 1;
            } else {
                borrow = 0;
            }
            res_array[i] = diff as u64;
        }
        U256(res_array)
    }

    pub fn sup_mod(a: &U256, b: &U256) -> U256 {
        if a.is_greater_or_equal(b) {
            Self::sup_row(a, b)
        } else {
            Self::sup_row(&Self::P, &Self::sup_row(b, a))
        }
    }

    pub fn reduce(input: &U512) -> U256 {
        let low = U256([input.0[0], input.0[1], input.0[2], input.0[3]]);
        let high = U256([input.0[4], input.0[5], input.0[6], input.0[7]]);

        let mut res = [0u64; 4];
        let mut carry: u128 = 0;

        for i in 0..4 {
            let mul = (high.0[i] as u128 * Self::C_VALUE as u128) + carry;
            res[i] = mul as u64;
            carry = mul >> 64; 
        }

        let mut result = Self::add_mod(&low, &U256(res), &Self::P);

        if carry > 0 {
            let extra = carry * Self::C_VALUE as u128;
            let extra_u256 = U256([extra as u64, (extra >> 64) as u64, 0, 0]);
            result = Self::add_mod(&result, &extra_u256, &Self::P);
        }
    result
    }

    pub fn mul_mod(a: &U256, b: &U256, modulus: &U256) -> U256 {
        if *modulus == Self::P {
            let product = U512::mul_full(a, b);
            return Self::reduce(&product);
        }

        let mut result = U256([0; 4]);
        let mut temp = *a;
        for i in 0..4 {
            let limb = b.0[i];
            for j in 0..64 {
                if (limb >> j) & 1 == 1 {
                    result = Self::add_mod(&result, &temp, modulus);
                }
                temp = Self::add_mod(&temp, &temp, modulus);
            }
        }
        result
    }

    pub fn pow_mod(base: &U256, exp: &U256, modulus: &U256) -> U256 {
        let mut res = Self::ONE;
        let mut current_base = *base;

        for i in 0..4 {
            let limb = exp.0[i];
            
            for j in 0..64 {
                let bit = (limb >> j) & 1;

                if bit == 1 {
                    res = Self::mul_mod(&res, &current_base, modulus);
                }

                current_base = Self::mul_mod(&current_base, &current_base, modulus);
            }
        }
        res
    }

    pub fn invert(a: &U256, modulus: &U256) -> U256 {
        let exp = if *modulus == Self::P {
            Self::P_MINUS_2
        } else if *modulus == Self::N {
            Self::N_MINUS_2
        } else {
            Self::sup_row(modulus, &U256([2, 0, 0, 0]))
        };
        Self::pow_mod(a, &exp, modulus)
    }

    pub fn is_valid_privkey(&self) -> bool {
        let is_zero = self.0 == [0, 0, 0, 0];
        let is_less_than_n = !self.is_greater_or_equal(&Self::N);
        !is_zero && is_less_than_n
    }

    pub fn from_hex(hex: &str) -> Self {
        let mut res = [0u64; 4];
        let clean_hex = hex.trim_start_matches("0x");
        for i in 0..4 {
            let start = clean_hex.len().saturating_sub((i + 1) * 16);
            let end = clean_hex.len().saturating_sub(i * 16);
            if end > 0 {
                let part = &clean_hex[start..end];
                res[i] = u64::from_str_radix(part, 16).unwrap_or(0);
            }
        }
        U256(res)
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let start = (3 - i) * 8;
            limbs[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
        }
        U256(limbs)
    }

    pub fn to_hex(&self) -> String {
        format!("{:016x}{:016x}{:016x}{:016x}", self.0[3], self.0[2], self.0[1], self.0[0])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U512(pub [u64; 8]);

impl U512 {
    pub fn mul_full(a: &U256, b: &U256) -> U512 {
        let mut res = [0u64; 8];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 {
                let mul = a.0[i] as u128 * b.0[j] as u128 + res[i + j] as u128 + carry;
                res[i + j] = mul as u64;
                carry = mul >> 64;
            }
            res[i + 4] = carry as u64;
        }
    U512(res)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub x: U256,
    pub y: U256,
}

impl Point {

    pub const G: Point = Point {
        x: U256([
            0x59F2_815B_16F8_1798, 
            0x029B_FCDB_2DCE_28D9, 
            0x55A0_6295_CE87_0B07, 
            0x79BE_667E_F9DC_BBAC  
        ]),
        y: U256([
            0x9C47_D08F_FB10_D4B8, 
            0xFD17_B448_A685_5419, 
            0x5DA4_FBFC_0E11_08A8, 
            0x483A_DA77_26A3_C465
        ]),
    };

    pub fn is_infinity(&self) -> bool {
        self.x.0 == [0, 0, 0, 0] && self.y.0 == [0, 0, 0, 0]
    }

    pub fn add(&self, other: &Point) -> Point {
        if self.is_infinity() { return *other; }
        if other.is_infinity() { return *self; }

        if self.x == other.x {
            if self.y == other.y {
                return self.double();
            }
            return Point { x: U256([0; 4]), y: U256([0; 4]) };
        }
        // lambda = (y2 - y1) * (x2 - x1)^(-1)
        let dy = U256::sup_mod(&other.y, &self.y);
        let dx = U256::sup_mod(&other.x, &self.x);
        let dx_inv = U256::invert(&dx, &U256::P);
        let lambda = U256::mul_mod(&dy, &dx_inv, &U256::P);
        // x3 = lambda^2 - x1 - x2
        let lambda_sq = U256::mul_mod(&lambda, &lambda, &U256::P);
        let x3_part1 = U256::sup_mod(&lambda_sq, &self.x);
        let x3 = U256::sup_mod(&x3_part1, &other.x);
        // y3 = lambda * (x1 - x3) - y1
        let dx_for_y = U256::sup_mod(&self.x, &x3);
        let lambda_dx = U256::mul_mod(&lambda, &dx_for_y, &U256::P);
        let y3 = U256::sup_mod(&lambda_dx, &self.y);

        Point { x: x3, y: y3 }
    }

    pub fn double(&self) -> Point {
        if self.is_infinity() { return *self; }

        if self.y.0 == [0, 0, 0, 0] {
            return Point { x: U256([0; 4]), y: U256([0; 4]) };
        }
        
        // lambda = (3 * x^2) / (2 * y)
        let x_sq = U256::mul_mod(&self.x, &self.x, &U256::P);
        let two_x_sq = U256::add_mod(&x_sq, &x_sq, &U256::P);
        let three_x_sq = U256::add_mod(&two_x_sq, &x_sq, &U256::P);

        let two_y = U256::add_mod(&self.y, &self.y, &U256::P);
        let two_y_inv = U256::invert(&two_y, &U256::P);
        
        let lambda = U256::mul_mod(&three_x_sq, &two_y_inv, &U256::P);

        // x3 = lambda^2 - 2x
        let lambda_sq = U256::mul_mod(&lambda, &lambda, &U256::P);
        let two_x = U256::add_mod(&self.x, &self.x, &U256::P);
        let x3 = U256::sup_mod(&lambda_sq, &two_x);

        // y3 = lambda * (x - x3) - y
        let dx = U256::sup_mod(&self.x, &x3);
        let lambda_dx = U256::mul_mod(&lambda, &dx, &U256::P);
        let y3 = U256::sup_mod(&lambda_dx, &self.y);

        Point { x: x3, y: y3 }
    }

    /// P = k * G
    pub fn mul_scalar(&self, scalar: &U256) -> Point {
        let mut result = Point { 
            x: U256([0; 4]), 
            y: U256([0; 4]) 
        };
        
        let mut current_point = *self;

        for i in 0..4 {
            let limb = scalar.0[i];
            
            for j in 0..64 {
                let bit = (limb >> j) & 1;
                if bit == 1 {
                    result = result.add(&current_point);
                }
                current_point = current_point.double();
            }
        }
        result
    }
}