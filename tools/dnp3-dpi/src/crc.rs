//! CRC-16/DNP as used by the DNP3 link layer.
//!
//! Parameters: polynomial `0x3D65`, reflected input and output, initial value
//! `0x0000`, final XOR `0xFFFF`. The reflected polynomial is `0xA6BC`.
//! Check value: `crc16(b"123456789") == 0xEA82`.

const POLYNOMIAL_REFLECTED: u16 = 0xA6BC;

/// Compute the CRC-16/DNP of `data`.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLYNOMIAL_REFLECTED;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::crc16;

    #[test]
    fn matches_the_standard_check_value() {
        assert_eq!(crc16(b"123456789"), 0xEA82);
    }
}
