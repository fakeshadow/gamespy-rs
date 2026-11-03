//! Master-server shard selection; applications supply hostname formatting.
pub const MASTER_SERVER_COUNT: u32 = 20;
pub fn master_server_index(game_name: &str) -> u32 {
    game_name.bytes().fold(0u32, |hash, byte| {
        hash.wrapping_mul(0x9CCF_9319)
            .wrapping_add(u32::from(byte.to_ascii_lowercase()))
    }) % MASTER_SERVER_COUNT
}
