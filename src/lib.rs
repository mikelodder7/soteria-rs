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
/// Standard traits are intentionally not implemented or
/// minimally implemented to avoid memory copies like
/// [`Copy`], [`Clone`], [`Debug`], [`ToString`].
///
/// Serialization is not implemented via `serde`
/// and be warned, serialization takes the value out of protected
/// memory. Serialization is usually meant for persistence and thus
/// memory protections do not apply. Other options like disk encryption
/// or file encryption should be used.
/// This is done deliberately to limit accidental exfiltration of secrets
/// with `serde`.
///
/// If serialization is still desirable, please use the
/// [`serialize_with`][1] attribute to specify a serializer.
///
/// The easiest method for this is to call `unprotect`().as_ref(). However
/// since `unprotect` requires `self` to be mutable, [`RefCell`] will probably
/// need to be used.
///
/// [1]: https://serde.rs/field-attrs.html#serialize_with
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

impl<const B: usize> Drop for Protected<B> {
    fn drop(&mut self) {
        self.pre_key.zeroize();
        self.nonce.zeroize();
    }
}

impl<const B: usize> std::fmt::Debug for Protected<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Protected<{}>", B)
    }
}

impl<const B: usize> std::fmt::Display for Protected<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Protected<{}>", B)
    }
}

impl<const B: usize> From<&[u8]> for Protected<B> {
    fn from(value: &[u8]) -> Self {
        Protected::new(value)
    }
}

impl<const B: usize> From<Vec<u8>> for Protected<B> {
    fn from(value: Vec<u8>) -> Self {
        Protected::new(value.as_slice())
    }
}

impl<const B: usize> From<&str> for Protected<B> {
    fn from(value: &str) -> Self {
        Protected::str(value)
    }
}

impl<const B: usize> From<String> for Protected<B> {
    fn from(value: String) -> Self {
        Protected::str(value.as_str())
    }
}

macro_rules! from_type_to_protected {
    ($($type:tt),+$(,)*) => {
        $(
            impl<const B: usize> From<$type> for Protected<B> {
                fn from(value: $type) -> Self {
                    Protected::$type(value)
                }
            }
        )+
    };
}

from_type_to_protected!(u8, i8, u16, i16, u32, i32, u64, i64);

#[cfg(target_pointer_width = "64")]
from_type_to_protected!(u128, i128);

#[cfg(feature = "secret-key")]
#[cfg_attr(docrs, doc(cfg(feature = "secret-key")))]
impl<C: elliptic_curve::Curve, const B: usize> From<elliptic_curve::SecretKey<C>> for Protected<B> {
    fn from(value: elliptic_curve::SecretKey<C>) -> Protected<B> {
        Protected::from(&value)
    }
}

#[cfg(feature = "secret-key")]
#[cfg_attr(docrs, doc(cfg(feature = "secret-key")))]
impl<C: elliptic_curve::Curve, const B: usize> From<&elliptic_curve::SecretKey<C>>
    for Protected<B>
{
    fn from(value: &elliptic_curve::SecretKey<C>) -> Protected<B> {
        Protected::secret_key(value)
    }
}

#[cfg(feature = "signing")]
#[cfg_attr(docrs, doc(cfg(feature = "signing")))]
impl<C, const B: usize> From<ecdsa::SigningKey<C>> for Protected<B>
where
    C: ecdsa::PrimeCurve + elliptic_curve::CurveArithmetic,
    elliptic_curve::Scalar<C>: elliptic_curve::ops::Invert<Output = subtle::CtOption<elliptic_curve::Scalar<C>>>
        + ecdsa::hazmat::SignPrimitive<C>,
    ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
{
    fn from(value: ecdsa::SigningKey<C>) -> Protected<B> {
        Protected::from(&value)
    }
}

#[cfg(feature = "signing")]
#[cfg_attr(docrs, doc(cfg(feature = "signing")))]
impl<C, const B: usize> From<&ecdsa::SigningKey<C>> for Protected<B>
where
    C: ecdsa::PrimeCurve + elliptic_curve::CurveArithmetic,
    elliptic_curve::Scalar<C>: elliptic_curve::ops::Invert<Output = subtle::CtOption<elliptic_curve::Scalar<C>>>
        + ecdsa::hazmat::SignPrimitive<C>,
    ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
{
    fn from(value: &ecdsa::SigningKey<C>) -> Protected<B> {
        Protected::signing_key(value)
    }
}

#[cfg(feature = "bls")]
#[cfg_attr(docrs, doc(cfg(feature = "bls")))]
impl<S: blsful::BlsSignatureImpl, const B: usize> From<blsful::SecretKey<S>> for Protected<B> {
    fn from(value: blsful::SecretKey<S>) -> Protected<B> {
        Protected::from(&value)
    }
}

#[cfg(feature = "bls")]
#[cfg_attr(docrs, doc(cfg(feature = "bls")))]
impl<S: blsful::BlsSignatureImpl, const B: usize> From<&blsful::SecretKey<S>> for Protected<B> {
    fn from(value: &blsful::SecretKey<S>) -> Protected<B> {
        Protected::bls_secret_key(value)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docrs, doc(cfg(feature = "ed25519")))]
impl<const B: usize> From<ed25519_dalek::SigningKey> for Protected<B> {
    fn from(value: ed25519_dalek::SigningKey) -> Protected<B> {
        Protected::from(&value)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docrs, doc(cfg(feature = "ed25519")))]
impl<const B: usize> From<&ed25519_dalek::SigningKey> for Protected<B> {
    fn from(value: &ed25519_dalek::SigningKey) -> Protected<B> {
        Protected::ed25519(value)
    }
}

#[cfg(feature = "x25519")]
#[cfg_attr(docrs, doc(cfg(feature = "x25519")))]
impl<const B: usize> From<x25519_dalek::StaticSecret> for Protected<B> {
    fn from(value: x25519_dalek::StaticSecret) -> Protected<B> {
        Protected::from(&value)
    }
}

#[cfg(feature = "x25519")]
#[cfg_attr(docrs, doc(cfg(feature = "x25519")))]
impl<const B: usize> From<&x25519_dalek::StaticSecret> for Protected<B> {
    fn from(value: &x25519_dalek::StaticSecret) -> Protected<B> {
        Protected::x25519(value)
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

    #[cfg(feature = "elements")]
    #[cfg_attr(docrs, doc(cfg(feature = "elements")))]
    /// Create a new protected memory value from a field element
    pub fn field_element<F: group::ff::PrimeField>(secret: F) -> Self {
        Self::new(secret.to_repr().as_ref())
    }

    #[cfg(feature = "elements")]
    #[cfg_attr(docrs, doc(cfg(feature = "elements")))]
    /// Create a new protected memory value from a group element
    pub fn group_element<G: group::GroupEncoding>(secret: G) -> Self {
        Self::new(secret.to_bytes().as_ref())
    }

    #[cfg(feature = "secret-key")]
    #[cfg_attr(docrs, doc(cfg(feature = "secret-key")))]
    /// Create a new protected memory value from a secret key
    pub fn secret_key<C: elliptic_curve::Curve>(key: &elliptic_curve::SecretKey<C>) -> Self {
        Self::new(key.to_bytes())
    }

    #[cfg(feature = "signing")]
    #[cfg_attr(docrs, doc(cfg(feature = "signing")))]
    /// Create a new protected memory value from a signing key
    pub fn signing_key<C>(key: &ecdsa::SigningKey<C>) -> Self
    where
        C: ecdsa::PrimeCurve + elliptic_curve::CurveArithmetic,
        elliptic_curve::Scalar<C>: elliptic_curve::ops::Invert<Output = subtle::CtOption<elliptic_curve::Scalar<C>>>
            + ecdsa::hazmat::SignPrimitive<C>,
        ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    {
        Self::new(key.to_bytes())
    }

    #[cfg(feature = "bls")]
    #[cfg_attr(docrs, doc(cfg(feature = "bls")))]
    /// Create a new protected memory value from a bls secret key
    pub fn bls_secret_key<C: blsful::BlsSignatureImpl>(key: &blsful::SecretKey<C>) -> Self {
        Self::new(key.to_be_bytes())
    }

    #[cfg(feature = "ed25519")]
    #[cfg_attr(docrs, doc(cfg(feature = "ed25519")))]
    /// Create a new protected memory value from a ed25519 signing key
    pub fn ed25519(key: &ed25519_dalek::SigningKey) -> Self {
        Self::new(key.to_bytes())
    }

    #[cfg(feature = "x25519")]
    #[cfg_attr(docrs, doc(cfg(feature = "x25519")))]
    /// Create a new protected memory value from a x25519 key
    pub fn x25519(key: &x25519_dalek::StaticSecret) -> Self {
        Self::new(key.to_bytes())
    }

    /// Create a new protected memory value from a string slice
    pub fn str<A: AsRef<str>>(secret: A) -> Self {
        Self::new(secret.as_ref().as_bytes())
    }

    /// Create a new protected memory value from a u8
    pub fn u8(input: u8) -> Self {
        Self::new([input])
    }

    /// Create a new protected memory value from a i8
    pub fn i8(input: i8) -> Self {
        Self::new([input as u8])
    }

    /// Create a new protected memory value from a u16
    pub fn u16(input: u16) -> Self {
        Self::new(input.to_be_bytes())
    }

    /// Create a new protected memory value from a i16
    pub fn i16(input: i16) -> Self {
        Self::new(input.to_be_bytes())
    }

    /// Create a new protected memory value from a u32
    pub fn u32(input: u32) -> Self {
        Self::new(input.to_be_bytes())
    }

    /// Create a new protected memory value from a i32
    pub fn i32(input: i32) -> Self {
        Self::new(input.to_be_bytes())
    }

    /// Create a new protected memory value from a u64
    pub fn u64(input: u64) -> Self {
        Self::new(input.to_be_bytes())
    }

    /// Create a new protected memory value from a i64
    pub fn i64(input: i64) -> Self {
        Self::new(input.to_be_bytes())
    }

    #[cfg(target_pointer_width = "64")]
    /// Create a new protected memory value from a u128
    pub fn u128(input: u128) -> Self {
        Self::new(input.to_be_bytes())
    }

    #[cfg(target_pointer_width = "64")]
    /// Create a new protected memory value from a i128
    pub fn i128(input: i128) -> Self {
        Self::new(input.to_be_bytes())
    }

    #[cfg(feature = "serde")]
    #[cfg_attr(docrs, doc(cfg(feature = "serde")))]
    /// Serialize a secret into protected memory
    pub fn serde<T: serde::Serialize>(secret: &T) -> Result<Self, Box<dyn std::error::Error>> {
        let s = serde_bare::to_vec(secret).map_err(|e| string_error::into_err(e.to_string()))?;
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

    /// Unprotect memory value. If the value has been tampered, [`None`] is returned.
    /// Otherwise the value is decrypted and return via [`Some`]
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

/// Unprotected contains the decrypted value.
/// After Unprotected is dropped, the `Protected` is reengaged
/// with new cryptographic material and the value is encrypted again
pub struct Unprotected<'a, const B: usize = DEFAULT_BUF_SIZE> {
    protected: &'a mut Protected<B>,
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

impl<'a, const B: usize> Unprotected<'a, B> {
    #[cfg(feature = "serde")]
    #[cfg_attr(docrs, doc(cfg(feature = "serde")))]
    /// Deserialize a secret
    pub fn serde<T: serde::de::DeserializeOwned>(&self) -> Result<T, Box<dyn std::error::Error>> {
        Ok(serde_bare::from_slice::<T>(self.as_ref()).map_err(Box::new)?)
    }

    #[cfg(feature = "elements")]
    #[cfg_attr(docrs, doc(cfg(feature = "elements")))]
    /// Convert the secret into a field element
    pub fn field_element<F: group::ff::PrimeField>(&self) -> Result<F, Box<dyn std::error::Error>> {
        let mut repr = F::Repr::default();
        repr.as_mut().copy_from_slice(self.as_ref());
        Option::<F>::from(F::from_repr(repr))
            .ok_or(string_error::static_err("invalid field element"))
    }

    #[cfg(feature = "elements")]
    #[cfg_attr(docrs, doc(cfg(feature = "elements")))]
    /// Convert the secret into a group element
    pub fn group_element<G: group::GroupEncoding>(&self) -> Result<G, Box<dyn std::error::Error>> {
        let mut repr = G::Repr::default();
        repr.as_mut().copy_from_slice(self.as_ref());
        Option::<G>::from(G::from_bytes(&repr))
            .ok_or(string_error::static_err("invalid group element"))
    }

    #[cfg(feature = "secret-key")]
    #[cfg_attr(docrs, doc(cfg(feature = "secret-key")))]
    /// Convert the secret to a secret key
    pub fn secret_key<C: elliptic_curve::Curve>(
        &self,
    ) -> Result<elliptic_curve::SecretKey<C>, Box<dyn std::error::Error>> {
        elliptic_curve::SecretKey::from_slice(self.as_ref())
            .map_err(|e| string_error::into_err(e.to_string()))
    }

    #[cfg(feature = "signing")]
    #[cfg_attr(docrs, doc(cfg(feature = "signing")))]
    /// Convert the secret to a signing key
    pub fn signing_key<C>(&self) -> Result<ecdsa::SigningKey<C>, Box<dyn std::error::Error>>
    where
        C: ecdsa::PrimeCurve + elliptic_curve::CurveArithmetic,
        elliptic_curve::Scalar<C>: elliptic_curve::ops::Invert<Output = subtle::CtOption<elliptic_curve::Scalar<C>>>
            + ecdsa::hazmat::SignPrimitive<C>,
        ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    {
        ecdsa::SigningKey::from_slice(self.as_ref())
            .map_err(|e| string_error::into_err(e.to_string()))
    }

    #[cfg(feature = "bls")]
    #[cfg_attr(docrs, doc(cfg(feature = "bls")))]
    /// Convert the secret to a bls secret key
    pub fn bls_secret_key<C: blsful::BlsSignatureImpl>(
        &self,
    ) -> Result<blsful::SecretKey<C>, Box<dyn std::error::Error>> {
        Option::from(blsful::SecretKey::<C>::from_be_bytes(
            &<[u8; 32]>::try_from(self.as_ref())
                .map_err(|_| string_error::static_err("invalid bls secret key"))?,
        ))
        .ok_or_else(|| string_error::static_err("invalid bls secret key"))
    }

    #[cfg(feature = "ed25519")]
    #[cfg_attr(docrs, doc(cfg(feature = "ed25519")))]
    /// Convert the secret to an ed25519 signing key
    pub fn ed25519(&self) -> Result<ed25519_dalek::SigningKey, Box<dyn std::error::Error>> {
        Ok(ed25519_dalek::SigningKey::from_bytes(
            &<[u8; 32]>::try_from(self.as_ref())
                .map_err(|_| string_error::static_err("invalid ed25519 signing key"))?,
        ))
    }

    #[cfg(feature = "x25519")]
    #[cfg_attr(docrs, doc(cfg(feature = "x25519")))]
    /// Convert the secret to a x25519 key
    pub fn x25519(&self) -> Result<x25519_dalek::StaticSecret, Box<dyn std::error::Error>> {
        Ok(x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(self.as_ref())
                .map_err(|_| string_error::static_err("invalid x25519 key"))?,
        ))
    }

    /// Return the protected secret as a string slice
    pub fn str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.as_ref()) }
    }

    /// Return the protected secret as a single byte
    pub fn u8(&self) -> u8 {
        self.as_ref()[0]
    }

    /// Return the protected secret as a single byte
    pub fn i8(&self) -> i8 {
        self.as_ref()[0] as i8
    }

    /// Return the protected secret as a single byte
    pub fn u16(&self) -> u16 {
        u16::from_be_bytes(<[u8; 2]>::try_from(self.as_ref()).unwrap())
    }

    /// Return the protected secret as a single byte
    pub fn i16(&self) -> i16 {
        i16::from_be_bytes(<[u8; 2]>::try_from(self.as_ref()).unwrap())
    }

    /// Return the protected secret as a single byte
    pub fn u32(&self) -> u32 {
        u32::from_be_bytes(<[u8; 4]>::try_from(self.as_ref()).unwrap())
    }

    /// Return the protected secret as a single byte
    pub fn i32(&self) -> i32 {
        i32::from_be_bytes(<[u8; 4]>::try_from(self.as_ref()).unwrap())
    }

    /// Return the protected secret as a single byte
    pub fn u64(&self) -> u64 {
        u64::from_be_bytes(<[u8; 8]>::try_from(self.as_ref()).unwrap())
    }

    /// Return the protected secret as a single byte
    pub fn i64(&self) -> i64 {
        i64::from_be_bytes(<[u8; 8]>::try_from(self.as_ref()).unwrap())
    }

    #[cfg(target_pointer_width = "64")]
    /// Return the protected secret as a 128-bit unsigned integer from little endian bytes
    pub fn u128(&self) -> u128 {
        u128::from_be_bytes(<[u8; 16]>::try_from(self.as_ref()).unwrap())
    }

    #[cfg(target_pointer_width = "64")]
    /// Return the protected secret as a 128-bit unsigned integer from little endian bytes
    pub fn i128(&self) -> i128 {
        i128::from_be_bytes(<[u8; 16]>::try_from(self.as_ref()).unwrap())
    }
}

#[test]
fn protect_slice() {
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

#[test]
fn protected_integers() {
    let mut p: Protected<256> = 8u8.into();
    assert_eq!(p.unprotect().unwrap().u8(), 8);
    p = 9i8.into();
    assert_eq!(p.unprotect().unwrap().i8(), 9);
    p = 80u16.into();
    assert_eq!(p.unprotect().unwrap().u16(), 80);
    p = 90i16.into();
    assert_eq!(p.unprotect().unwrap().i16(), 90);
    p = 800u32.into();
    assert_eq!(p.unprotect().unwrap().u32(), 800);
    p = 900i32.into();
    assert_eq!(p.unprotect().unwrap().i32(), 900);
    p = 8000u64.into();
    assert_eq!(p.unprotect().unwrap().u64(), 8000);
    p = 9000i64.into();
    assert_eq!(p.unprotect().unwrap().i64(), 9000);
    p = 80000u128.into();
    assert_eq!(p.unprotect().unwrap().u128(), 80000);
    p = 90000i128.into();
    assert_eq!(p.unprotect().unwrap().i128(), 90000);
}

#[cfg(feature = "serde")]
#[test]
fn protect_serde() {
    #[derive(Debug, Eq, PartialEq)]
    struct Data {
        one: Vec<u8>,
        two: Vec<u8>,
    }

    impl serde::Serialize for Data {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut output = Vec::with_capacity(self.one.len() + self.two.len() + 8);
            output.extend_from_slice(&(self.one.len() as u32).to_be_bytes());
            output.extend_from_slice(self.one.as_slice());
            output.extend_from_slice(&(self.two.len() as u32).to_be_bytes());
            output.extend_from_slice(self.two.as_slice());
            output.serialize(s)
        }
    }

    impl<'de> serde::Deserialize<'de> for Data {
        fn deserialize<D>(d: D) -> Result<Self, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            struct DataVisitor;

            impl<'de> serde::de::Visitor<'de> for DataVisitor {
                type Value = Data;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(formatter, "a byte sequence")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    let mut len = [0u8; 4];
                    len[0] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                    len[1] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                    len[2] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                    len[3] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                    let mut arr_len = u32::from_be_bytes(len) as usize;
                    let mut one = Vec::with_capacity(arr_len);
                    for i in 0..arr_len {
                        one.push(
                            seq.next_element()?
                                .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?,
                        );
                    }

                    len[0] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(arr_len + 4, &self))?;
                    len[1] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(arr_len + 5, &self))?;
                    len[2] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(arr_len + 6, &self))?;
                    len[3] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(arr_len + 7, &self))?;
                    arr_len = u32::from_be_bytes(len) as usize;
                    let mut two = Vec::with_capacity(arr_len);
                    for i in 0..arr_len {
                        two.push(
                            seq.next_element()?
                                .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?,
                        );
                    }

                    Ok(Data { one, two })
                }
            }

            d.deserialize_seq(DataVisitor)
        }
    }

    let tt = Data {
        one: vec![1u8; 16],
        two: vec![2u8; 32],
    };

    let p = Protected::<DEFAULT_BUF_SIZE>::serde(&tt);
    assert!(p.is_ok());
    let mut p = p.unwrap();
    let u = p.unprotect().unwrap();
    let dd = u.serde::<Data>();
    assert!(dd.is_ok());
    let dd = dd.unwrap();
    assert_eq!(dd, tt);
}

#[test]
fn protect_str() {
    let mut p = Protected::<DEFAULT_BUF_SIZE>::str("letmeinplease");
    let u = p.unprotect().unwrap();
    assert_eq!(u.str(), "letmeinplease");
}

#[cfg(feature = "elements")]
#[test]
fn protect_elements() {
    use group::ff::Field;

    let sk = k256::Scalar::random(&mut rand::rngs::OsRng);
    let pk = k256::ProjectivePoint::GENERATOR * sk;

    let mut p = Protected::<DEFAULT_BUF_SIZE>::field_element(sk);
    {
        let u = p.unprotect().unwrap();
        let ss = u.field_element::<k256::Scalar>();
        assert!(ss.is_ok());
        let ss = ss.unwrap();
        assert_eq!(ss, sk);
    }

    p = Protected::group_element(pk);
    let u = p.unprotect().unwrap();
    let gg = u.group_element::<k256::ProjectivePoint>();
    assert!(gg.is_ok());
    let gg = gg.unwrap();
    assert_eq!(gg, pk);
}

#[cfg(feature = "secret-key")]
#[test]
fn protect_secret_key() {
    let sk = k256::SecretKey::random(&mut rand::rngs::OsRng);
    let mut p: Protected<DEFAULT_BUF_SIZE> = (&sk).into();
    let u = p.unprotect().unwrap();
    let r = u.secret_key::<k256::Secp256k1>();
    assert!(r.is_ok());
    assert_eq!(r.unwrap(), sk);
}

#[cfg(feature = "signing")]
#[test]
fn protect_signing_key() {
    let sk = ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let mut p: Protected<DEFAULT_BUF_SIZE> = (&sk).into();
    let u = p.unprotect().unwrap();
    let r = u.signing_key::<k256::Secp256k1>();
    assert!(r.is_ok());
    assert_eq!(r.unwrap(), sk);
}

#[cfg(feature = "bls")]
#[test]
fn protect_bls_secret_key() {
    let sk = blsful::Bls12381G1::new_secret_key();
    let mut p: Protected<DEFAULT_BUF_SIZE> = (&sk).into();
    let u = p.unprotect().unwrap();
    let r = u.bls_secret_key::<blsful::Bls12381G1Impl>();
    assert!(r.is_ok());
    assert_eq!(r.unwrap(), sk);
}

#[cfg(feature = "ed25519")]
#[test]
fn protect_ed25519() {
    use rand::Rng;

    let sk = ed25519_dalek::SigningKey::from_bytes(&rand::rngs::OsRng.gen::<[u8; 32]>());
    let mut p: Protected<DEFAULT_BUF_SIZE> = (&sk).into();
    let u = p.unprotect().unwrap();
    let r = u.ed25519();
    assert!(r.is_ok());
    assert_eq!(r.unwrap().to_bytes(), sk.to_bytes());
}

#[cfg(feature = "x25519")]
#[test]
fn protect_x25519() {
    let sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let mut p: Protected<DEFAULT_BUF_SIZE> = (&sk).into();
    let u = p.unprotect().unwrap();
    let r = u.x25519();
    assert!(r.is_ok());
    assert_eq!(r.unwrap().to_bytes(), sk.to_bytes());
}
