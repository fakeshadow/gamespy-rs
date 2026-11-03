use super::*;

#[test]
fn a_query_carries_three_length_prefixed_lists() {
    let packet = query([1, 2, 3, 4], &[10, 11], &[20], &[]);
    let payload = &packet[MASTER_HEADER_LEN..];
    assert_eq!(payload, &[2, 10, 11, 1, 20, 0]);
    assert!(
        payload.len() >= 3,
        "the host discards a query shorter than three payload bytes"
    );
}

#[test]
fn an_empty_query_is_still_long_enough_to_be_read() {
    let packet = query([1, 2, 3, 4], &[], &[], &[]);
    assert_eq!(&packet[MASTER_HEADER_LEN..], &[0, 0, 0]);
}

#[test]
fn an_over_long_list_is_sent_as_empty_rather_than_wrapping() {
    let huge = vec![7u8; 300];
    let packet = query([1, 2, 3, 4], &huge, &[], &[]);
    assert_eq!(
        &packet[MASTER_HEADER_LEN..],
        &[0, 0, 0],
        "a count byte cannot describe 300 ids, so nothing is claimed"
    );
}

#[test]
fn a_reserved_count_does_not_shift_the_following_lists() {
    let reserved = [7; 255];
    for (lists, expected) in [
        (
            [reserved.as_slice(), &[20, 21], &[30]],
            vec![0, 2, 20, 21, 1, 30],
        ),
        ([&[10], reserved.as_slice(), &[30]], vec![1, 10, 0, 1, 30]),
        (
            [&[10], &[20, 21], reserved.as_slice()],
            vec![1, 10, 2, 20, 21, 0],
        ),
    ] {
        let packet = query([1, 2, 3, 4], lists[0], lists[1], lists[2]);
        assert_eq!(&packet[MASTER_HEADER_LEN..], expected);
    }
}

#[test]
fn the_largest_explicit_key_list_is_preserved() {
    let keys = [7; 254];
    let packet = query([1, 2, 3, 4], &keys, &[20], &[30]);
    let payload = &packet[MASTER_HEADER_LEN..];
    assert_eq!(payload[0], 254);
    assert_eq!(&payload[1..255], &keys);
    assert_eq!(&payload[255..], &[1, 20, 1, 30]);
}
