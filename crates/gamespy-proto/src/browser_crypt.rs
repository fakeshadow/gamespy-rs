//! Browser crypt.

/// Length of the derived key, from `li r5, 8` at the schedule call site
/// (`0x00aebecc`).
pub const KEY_LEN: usize = 8;

/// `len1 = (byte ^ 0xEC) + 2` — `0x00aebdec`, `0x00aebdf0`.
pub const LEN1_XOR: u8 = 0xEC;
/// `len2 = byte ^ 0xEA` — `0x00aebe0c`.
pub const LEN2_XOR: u8 = 0xEA;

/// Fold the second header block into the key, as the loop at
/// `0x00aebe44`-`0x00aebeb4` does.
///
/// Per byte `i` of `block2`:
///
/// - `a = i % 8` (`srawi`/`addze`/`sldi`/`subfc` at
///   `0x00aebe4c`-`0x00aebe60`),
/// - `b = (i * secret[i % secret.len()]) % 8`, with the secret byte
///   **sign-extended** (`extsb`, `0x00aebe70`) before the multiply
///   (`0x00aebe74`) and the same truncating `% 8` (`0x00aebe78`-`0x00aebe84`),
/// - `key[b] ^= key[a] ^ block2[i]` (`0x00aebe9c`-`0x00aebeb0`).
///
/// `seed` is the key buffer's initial contents; see the module's open point.
/// An empty `secret` would divide by zero in the client, so it is refused here.
pub fn derive_key(seed: [u8; KEY_LEN], secret: &[u8], block2: &[u8]) -> Option<[u8; KEY_LEN]> {
    if secret.is_empty() {
        return None;
    }
    let mut key = seed;
    for (index, byte) in block2.iter().enumerate() {
        let index = index as i32;
        let a = (index % KEY_LEN as i32) as usize;
        // The client sign-extends the secret byte, so a secret with a byte
        // above 0x7F would make the product negative and the truncating
        // remainder negative with it — which would index before the buffer.
        // Printable secrets cannot reach that, and the caller validates for
        // printable ASCII, but refuse rather than wrap if it ever happens.
        let secret_byte = secret[(index as usize) % secret.len()] as i8 as i32;
        let b = index.checked_mul(secret_byte)? % KEY_LEN as i32;
        if b < 0 {
            return None;
        }
        key[b as usize] ^= key[a] ^ *byte;
    }
    Some(key)
}

/// The cipher state: a 256-byte table plus the five index bytes the client
/// keeps at `+0x100`-`+0x104`.
#[derive(Clone)]
pub struct Cipher {
    table: [u8; 256],
    /// `+0x100`-`+0x104` in the client's layout.
    index: [u8; 5],
}

impl std::fmt::Debug for Cipher {
    /// Deliberately opaque: the state is key material.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Cipher(..)")
    }
}

impl Cipher {
    /// The key schedule at `0x00afc43c`.
    ///
    /// The prologue branches on the key length (`0x00afc44c`-`0x00afc460`):
    /// with a key of one byte or more it goes to `0x00afc4b4`, which seeds the
    /// table **ascending**, `table[i] = i` (`0x00afc4b8`-`0x00afc4c8`). The
    /// descending seed `table[i] = 255 - i` at `0x00afc48c`-`0x00afc4a0`,
    /// together with the fixed indices `1, 3, 5, 7, 0x0b`, is only the
    /// `keylen == 0` fallback and is **not** what a real key takes. Getting
    /// this backwards produces a cipher that is self-consistent and wrong.
    ///
    /// The accumulator update is `acc = table[acc] + key[index]`, **not**
    /// `acc += table[acc] + key[index]`; the decompiler at
    /// `DEC-S8-20261030-01` renders it as
    /// `uVar7 = table[uVar7] + key[uVar5] & 0xff`.
    ///
    /// The table is then shuffled from `i = 255` down to `0`
    /// (`0x00afc4d8`-`0x00afc580`): a partner index `j` is accumulated from
    /// the key bytes, masked with the smallest `2^k - 1` that covers `i`
    /// (`0x00afc4fc`-`0x00afc508`, `and` at `0x00afc540`), and **resampled**
    /// while `j > i` (`0x00afc558`); after 11 attempts it falls back to
    /// `j % i` (`0x00afc544`-`0x00afc554`). `table[i]` and `table[j]` are then
    /// swapped (`0x00afc564`-`0x00afc578`).
    ///
    /// The key index wraps at the key length, and on wrapping the accumulator
    /// gains the key length (`0x00afc51c`-`0x00afc534`).
    ///
    /// Finally the five indices are seeded from the shuffled table:
    /// `table[1]`, `table[3]`, `table[5]`, `table[7]` and
    /// `table[accumulator]` (`0x00afc584`-`0x00afc5a8`).
    pub fn new(key: &[u8]) -> Option<Self> {
        if key.is_empty() {
            return None;
        }
        let mut table = [0u8; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            *slot = i as u8;
        }

        let mut key_index: usize = 0;
        let mut accumulator: u8 = 0;
        let mut i: i32 = 255;
        while i > 0 {
            // Smallest 2^k - 1 that is >= i, built the way the client builds
            // it: double and add one until it covers i.
            let mut mask: u32 = 0;
            while mask < i as u32 {
                mask = mask * 2 + 1;
            }

            let mut attempts: u32 = 0;
            let j = loop {
                // table[acc] REPLACES acc; it is not added to it. The
                // instruction is `lbzx r10, r4, r10`, which overwrites the
                // accumulator register with the table entry it indexes.
                // Reading it as an accumulate is the bug that made five
                // console attempts fail.
                accumulator = table[accumulator as usize].wrapping_add(key[key_index]);
                key_index += 1;
                if key_index >= key.len() {
                    key_index = 0;
                    accumulator = accumulator.wrapping_add(key.len() as u8);
                }

                attempts += 1;
                let mut candidate = mask & u32::from(accumulator);
                if attempts > 11 {
                    candidate %= i as u32;
                }
                if candidate <= i as u32 {
                    break candidate as usize;
                }
            };

            table.swap(i as usize, j);
            i -= 1;
        }

        let index = [
            table[1],
            table[3],
            table[5],
            table[7],
            table[accumulator as usize],
        ];
        Some(Self { table, index })
    }

    /// The data-independent half of `0x00afc5b0`: advance the state and
    /// return the byte the client XORs with.
    ///
    /// Reading the five indices as `a`, `b`, `c`, `d`, `e`:
    /// `a` is incremented and `b += table[a_old]` (`0x00afc5bc`-`0x00afc5d4`);
    /// then four table entries are rotated through `e`, `b`, `d` and `a`
    /// (`0x00afc5e8`-`0x00afc608`); `c += table[table[e_old]]`
    /// (`0x00afc60c`-`0x00afc620`); and the keystream byte is two table
    /// lookups XORed together, one of them doubly indirect
    /// (`0x00afc648`-`0x00afc658`).
    ///
    /// Everything here is computed from the state the previous byte left, so
    /// it is identical for encryption and decryption. The data byte enters
    /// the state only through [`Cipher::feed`], which is where the two
    /// directions have to agree and where they previously did not. Because
    /// the feedback is data-dependent, applying the same keystream twice does
    /// **not** return the original buffer: decryption is
    /// [`Cipher::apply_decrypt`], not a second [`Cipher::apply`].
    fn keystream_byte(&mut self) -> u8 {
        let [a, b, c, d, e] = self.index;

        let a_new = a.wrapping_add(1);
        let b_new = b.wrapping_add(self.table[a as usize]);

        let table_e = self.table[e as usize];
        self.table[e as usize] = self.table[b_new as usize];
        self.table[b_new as usize] = self.table[d as usize];
        self.table[d as usize] = self.table[a_new as usize];
        self.table[a_new as usize] = table_e;

        let c_new = c.wrapping_add(self.table[table_e as usize]);

        let first = self.table[c_new as usize].wrapping_add(self.table[a_new as usize]);
        let second = self.table[d as usize]
            .wrapping_add(self.table[e as usize])
            .wrapping_add(self.table[b_new as usize]);

        // a, b and c are consumed here; d and e are written by the caller,
        // which is the only place the data byte enters the state.
        self.index = [a_new, b_new, c_new, d, e];

        self.table[first as usize] ^ self.table[self.table[second as usize] as usize]
    }

    /// Write the data feedback the client's two stores perform.
    ///
    /// `0x00afc65c` stores into `+0x103` (`d`) the byte the function
    /// **produced**, and `0x00afc618` stores into `+0x104` (`e`) the byte it
    /// was **given**. The client only ever decrypts, so it is given
    /// ciphertext and produces plaintext: `d` holds the plaintext byte and
    /// `e` the ciphertext byte.
    ///
    /// That is the invariant, and it is stated in terms of plaintext and
    /// ciphertext rather than input and output **on purpose**. Transcribing
    /// the client verbatim and then running it in the encrypt direction swaps
    /// the two stores, because an encoder's input is the plaintext. The
    /// keystream for byte *n* is computed from the state left by byte *n-1*,
    /// so swapping them leaves byte 1 correct and every later byte wrong —
    /// the console symptom in attempt 4: the client read a plausible first
    /// octet, then garbage, so the port was never `0xFFFF`, the record and
    /// key-name counts were nonsense, and its state machine waited on the
    /// open socket for bytes that were never coming.
    fn feed(&mut self, plaintext: u8, ciphertext: u8) {
        self.index[3] = plaintext;
        self.index[4] = ciphertext;
    }

    /// Decrypt one byte: the client's own direction, `0x00afc5b0` verbatim.
    pub fn decrypt_byte(&mut self, ciphertext: u8) -> u8 {
        let plaintext = ciphertext ^ self.keystream_byte();
        self.feed(plaintext, ciphertext);
        plaintext
    }

    /// Encrypt one byte, keeping the state evolution the client will have.
    pub fn encrypt_byte(&mut self, plaintext: u8) -> u8 {
        let ciphertext = plaintext ^ self.keystream_byte();
        self.feed(plaintext, ciphertext);
        ciphertext
    }

    /// Encrypt a buffer in place, byte by byte, as the loop at `0x00afc668`
    /// drives the per-byte transform.
    pub fn apply(&mut self, buffer: &mut [u8]) {
        for byte in buffer.iter_mut() {
            *byte = self.encrypt_byte(*byte);
        }
    }

    /// Decrypt a buffer in place: what the client does to our reply.
    ///
    /// This exists so tests can check the encoder against the client's
    /// direction instead of against a second encoder, which is the check that
    /// was missing while two console attempts failed.
    pub fn apply_decrypt(&mut self, buffer: &mut [u8]) {
        for byte in buffer.iter_mut() {
            *byte = self.decrypt_byte(*byte);
        }
    }
}

/// Build the two length bytes a response header needs, inverting the client's
/// `xori` so it recovers the lengths this encoder intends.
pub fn header_length_bytes(len1: u8, len2: u8) -> (u8, u8) {
    (len1.wrapping_sub(2) ^ LEN1_XOR, len2 ^ LEN2_XOR)
}

#[cfg(test)]
mod tests;
