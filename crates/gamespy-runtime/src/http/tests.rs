use super::*;
#[test]
fn preserves_coalesced_requests_and_binary_bodies() {
    let first = b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n\x00\xff";
    let second = b"GET / HTTP/1.1\r\n\r\n";
    let bytes = [first.as_slice(), second.as_slice()].concat();
    let mut stream = bytes.as_slice();
    let mut buffered = Vec::new();
    assert_eq!(read_raw(&mut stream, &mut buffered, 1024).unwrap(), first);
    assert_eq!(read_raw(&mut stream, &mut buffered, 1024).unwrap(), second);
    assert!(read_raw(&mut stream, &mut buffered, 1024).is_none());
}
#[test]
fn rejects_oversized_and_overflowing_lengths_before_reading_body() {
    for length in ["1000", "18446744073709551615"] {
        let input = format!("POST / HTTP/1.1\r\nContent-Length: {length}\r\n\r\n");
        assert!(read_raw(&mut input.as_bytes(), &mut Vec::new(), 128).is_none());
    }
}
#[test]
fn soap_handler_controls_keepalive_without_owning_transport() {
    struct Stream {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Stream {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Stream {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut stream = Stream {
        input: std::io::Cursor::new(b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec()),
        output: Vec::new(),
    };
    serve_soap(&mut stream, 128, |_| Some(("<ok/>".into(), false)));
    assert!(stream.output.ends_with(b"<ok/>"));
}
