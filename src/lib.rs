//! This crate implements a wrapper around a secret that is stored in memory.
//!
//! `Protected` allows a program to store a encrypted secret in memory. The secret
//! is encrypted using XChaChaPoly1305. The encryption keys are large enough to mitigate
//! memory side channel attacks like Spectre, Meltdown, Rowhammer, and RamBleed.
//!
//! There is a pre_key and a nonce each large enough to limit these attacks.
//! The pre_key and nonce are feed into a merlin transcript to mix with other data
//! and derive the actual encryption key. This value is wiped from memory when the dropped
//! or decrypted.
#![deny(warnings, missing_docs, dead_code)]

use chacha20poly1305::{aead::AeadInPlace, Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroize;

/// The default BUFFER size for the prekey and nonce in memory.
/// This is large enough to inhibit speculation and side-channel attacks.
/// Consumers should not go much smaller than this.
pub const DEFAULT_BUF_SIZE: usize = 16 * 1024;

/// A protected region of memory.
/// The pre key is large to inhibit speculation and side-channel attacks
/// like Spectre, Meltdown, Rowhammer, and RamBleed. Uses
/// XChacha20Poly1305 to encrypt/decrypt the data in memory in place.
///
/// The prekey random nonce are hashed using merlin transcripts to construct the
/// sealing key and encryption nonce.
/// Standard traits are intentionally not implemented to avoid memory copies like
/// [`Copy`], [`Clone`], [`Debug`], [`ToString`].
pub struct Protected<const B: usize = DEFAULT_BUF_SIZE> {
    /// The key for protecting the value
    pre_key: [u8; B],
    /// The current nonce
    nonce: [u8; B],
    /// The encrypted value
    value: Vec<u8>,
}

impl<const B: usize> Default for Protected<B> {
    fn default() -> Self {
        Self {
            pre_key: [0u8; B],
            nonce: [0u8; B],
            value: Vec::new(),
        }
    }
}

impl<const B: usize> Protected<B> {
    /// Create a new protected memory value
    pub fn new<A: AsRef<[u8]>>(secret: A) -> Self {
        let mut protected = Self {
            pre_key: [0u8; B],
            nonce: [0u8; B],
            value: secret.as_ref().to_vec(),
        };
        protected.protect();
        protected
    }

    /// Create a new protected memory value from a string slice
    pub fn str_into<A: AsRef<str>>(secret: A) -> Self {
        Self::new(secret.as_ref().as_bytes())
    }

    #[cfg(feature = "serde")]
    /// Serialize a secret into protected memory
    pub fn serde_into<T: serde::Serialize>(secret: &T) -> Result<Self, Box<dyn std::error::Error>> {
        let s = serde_bare::to_vec(secret).map_err(|e| Box::new(e))?;
        Ok(Self::new(s.as_slice()))
    }

    fn protect(&mut self) {
        let mut rng = rand::rngs::OsRng {};
        rng.fill_bytes(&mut self.pre_key);
        rng.fill_bytes(&mut self.nonce);
        let mut transcript = merlin::Transcript::new(b"protect memory region");
        transcript.append_message(b"pre_key", &self.pre_key);
        transcript.append_message(b"nonce", &self.nonce);
        let mut output = [0u8; 64];
        transcript.challenge_bytes(b"seal_data", &mut output);
        let seal_key = Key::from_slice(&output[..32]);
        let nonce = XNonce::from_slice(&output[32..56]);
        let cipher = XChaCha20Poly1305::new(seal_key);
        let mut aad = Vec::with_capacity(2 * B);
        aad.extend_from_slice(&self.pre_key);
        aad.extend_from_slice(&self.nonce);
        cipher
            .encrypt_in_place(nonce, &aad, &mut self.value)
            .unwrap();
        output.zeroize();
    }

    /// Unprotect memory value
    pub fn unprotect(&mut self) -> Option<Unprotected<'_, B>> {
        let mut transcript = merlin::Transcript::new(b"protect memory region");
        transcript.append_message(b"pre_key", &self.pre_key);
        transcript.append_message(b"nonce", &self.nonce);
        let mut output = [0u8; 64];
        transcript.challenge_bytes(b"seal_data", &mut output);
        let seal_key = Key::from_slice(&output[..32]);
        let nonce = XNonce::from_slice(&output[32..56]);
        let cipher = XChaCha20Poly1305::new(seal_key);
        let mut aad = Vec::with_capacity(2 * B);
        aad.extend_from_slice(&self.pre_key);
        aad.extend_from_slice(&self.nonce);
        match cipher.decrypt_in_place(nonce, &aad, &mut self.value) {
            Err(_) => None,
            Ok(_) => {
                self.pre_key.zeroize();
                self.nonce.zeroize();
                aad.zeroize();
                Some(Unprotected { protected: self })
            }
        }
    }
}

impl<const B: usize> Drop for Protected<B> {
    fn drop(&mut self) {
        self.pre_key.zeroize();
        self.nonce.zeroize();
    }
}

/// Unprotected contains the decrypted value.
/// After Unprotected is dropped, the `Protected` is reengaged
/// with new cryptographic material and the value is encrypted again
pub struct Unprotected<'a, const B: usize = DEFAULT_BUF_SIZE> {
    protected: &'a mut Protected<B>,
}

macro_rules! int_impl {
    ($($name_be:ident:$name_le:ident => $type:tt:$size:expr),+$(,)*) => {
        $(
            /// Return the protected secret as a $type from big endian bytes
            pub fn $name_be(&self) -> $type {
                $type::from_be_bytes(<[u8; $size]>::try_from(self.as_ref()).unwrap())
            }

            /// Return the protected secret as a $type from little endian bytes
            pub fn $name_le(&self) -> $type {
                $type::from_le_bytes(<[u8; $size]>::try_from(self.as_ref()).unwrap())
            }
        )+
    };
}

impl<'a, const B: usize> Unprotected<'a, B> {
    #[cfg(feature = "serde")]
    /// Deserialize a secret
    pub fn deserialize_from<T: serde::de::DeserializeOwned>(
        &self,
    ) -> Result<T, Box<dyn std::error::Error>> {
        Ok(serde_bare::from_slice::<T>(self.as_ref()).map_err(|e| Box::new(e))?)
    }

    /// Return the protected secret as a string slice
    pub fn str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(self.as_ref()) }
    }

    /// Return the protected secret as a single byte
    pub fn u8(&self) -> u8 {
        self.as_ref()[0]
    }

    int_impl!(
        u16_be:u16_le => u16:2,
        i16_be:i16_le => i16:2,
        u32_be:u32_le => u32:4,
        i32_be:i32_le => i32:4,
        u64_be:u64_le => u64:8,
        i64_be:i64_le => i64:8,
    );

    #[cfg(target_pointer_width = "64")]
    /// Return the protected secret as a 128-bit unsigned integer from little endian bytes
    pub fn u128_be(&self) -> u128 {
        u128::from_be_bytes(<[u8; 16]>::try_from(self.as_ref()).unwrap())
    }

    #[cfg(target_pointer_width = "64")]
    /// Return the protected secret as a 128-bit unsigned integer from little endian bytes
    pub fn u128_le(&self) -> u128 {
        u128::from_le_bytes(<[u8; 16]>::try_from(self.as_ref()).unwrap())
    }

    #[cfg(target_pointer_width = "64")]
    /// Return the protected secret as a 128-bit unsigned integer from little endian bytes
    pub fn i128_be(&self) -> i128 {
        i128::from_be_bytes(<[u8; 16]>::try_from(self.as_ref()).unwrap())
    }

    #[cfg(target_pointer_width = "64")]
    /// Return the protected secret as a 128-bit unsigned integer from little endian bytes
    pub fn i128_le(&self) -> i128 {
        i128::from_le_bytes(<[u8; 16]>::try_from(self.as_ref()).unwrap())
    }
}

impl<'a, const B: usize> AsRef<[u8]> for Unprotected<'a, B> {
    fn as_ref(&self) -> &[u8] {
        self.protected.value.as_slice()
    }
}

impl<'a, const B: usize> AsMut<[u8]> for Unprotected<'a, B> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.protected.value.as_mut()
    }
}

impl<'a, const B: usize> Drop for Unprotected<'a, B> {
    fn drop(&mut self) {
        self.protected.protect();
    }
}

#[test]
fn protect_test() {
    let password = b"letmeinplease!";
    let mut p = Protected::new(&password[..]);
    assert_ne!(p.value, password);
    assert_eq!(p.value.len(), password.len() + 16);
    assert_ne!(p.pre_key, [0u8; DEFAULT_BUF_SIZE]);
    assert_ne!(p.nonce, [0u8; DEFAULT_BUF_SIZE]);

    let password2 = p.unprotect();
    assert!(password2.is_some());
    assert_eq!(password2.unwrap().as_ref(), password.as_slice());
}
