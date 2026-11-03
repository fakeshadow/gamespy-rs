use super::*;

/// The host's own give-up rule, pinned so a service cannot be written
/// against a silent master by accident.
#[test]
fn a_master_has_four_heartbeats_and_ten_seconds_each_to_answer() {
    assert_eq!(HEARTBEAT_RETRY_MS, 10_000, "0x2710 at 0x00ae7c00");
    assert_eq!(MAX_UNANSWERED_HEARTBEATS, 4, "compared at 0x00ae7bf0");
    // Roughly how long a host keeps trying before the console shows "No
    // challenge value was received from the master server."
    assert_eq!(
        HEARTBEAT_RETRY_MS * MAX_UNANSWERED_HEARTBEATS,
        40_000,
        "the budget a master has to say anything at all"
    );
}

/// A retry is distinguishable from an exit, which matters because both
/// carry a `statechanged` value and only one means "remove me".
#[test]
fn the_retry_state_is_not_the_exit_state() {
    assert_ne!(STATE_RETRY, STATE_EXITING);
    let mut packet = vec![packet_type::HEARTBEAT, 1, 2, 3, 4];
    packet.extend_from_slice(b"statechanged\0");
    packet.extend_from_slice(STATE_RETRY.as_bytes());
    packet.extend_from_slice(b"\0\0");
    let HostPacket::Heartbeat { keys, .. } = parse_host_packet(&packet).unwrap() else {
        panic!()
    };
    assert_eq!(keys.get("statechanged"), Some(STATE_RETRY));
    assert!(
        !keys.is_exiting(),
        "a re-send after our silence must never be read as the host leaving"
    );
}
