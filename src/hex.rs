use std::str::FromStr;

use liblisa_libcli::hex_str_to_bytes;

#[derive(Clone, Debug)]
pub struct HexData(Vec<u8>);

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("Invalid hexadecimal string")]
pub struct InvalidHexStr;

impl FromStr for HexData {
    type Err = InvalidHexStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HexData(hex_str_to_bytes(s)))
    }
}

impl From<HexData> for Vec<u8> {
    fn from(data: HexData) -> Self {
        data.0
    }
}
