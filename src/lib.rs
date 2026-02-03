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
/// since `unprotect` requires `self` to be mutable, `RefCell` will probably
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

impl<const B: usize, const N: usize> From<[u8; N]> for Protected<B> {
    fn from(value: [u8; N]) -> Self {
        Protected::new(value.as_slice())
    }
}

impl<const B: usize> From<Box<[u8]>> for Protected<B> {
    fn from(value: Box<[u8]>) -> Self {
        Protected::new(value.as_ref())
    }
}

impl<const B: usize> From<std::borrow::Cow<'_, [u8]>> for Protected<B> {
    fn from(value: std::borrow::Cow<'_, [u8]>) -> Self {
        Protected::new(value.as_ref())
    }
}

impl<const B: usize> From<std::borrow::Cow<'_, str>> for Protected<B> {
    fn from(value: std::borrow::Cow<'_, str>) -> Self {
        Protected::str(value.as_ref())
    }
}

impl<const B: usize> From<&std::ffi::OsStr> for Protected<B> {
    fn from(value: &std::ffi::OsStr) -> Self {
        Protected::new(value.as_encoded_bytes())
    }
}

impl<const B: usize> From<std::ffi::OsString> for Protected<B> {
    fn from(value: std::ffi::OsString) -> Self {
        Protected::new(value.into_encoded_bytes().as_slice())
    }
}

impl<const B: usize> From<bool> for Protected<B> {
    fn from(value: bool) -> Self {
        Protected::bool(value)
    }
}

#[cfg(feature = "generic-array-014")]
#[cfg_attr(docsrs, doc(cfg(feature = "generic-array-014")))]
impl<const B: usize, N: generic_array_014::ArrayLength<u8>>
    From<generic_array_014::GenericArray<u8, N>> for Protected<B>
{
    fn from(value: generic_array_014::GenericArray<u8, N>) -> Self {
        Protected::new(value.as_slice())
    }
}

#[cfg(feature = "generic-array")]
#[cfg_attr(docsrs, doc(cfg(feature = "generic-array")))]
impl<const B: usize, N: generic_array::ArrayLength> From<generic_array::GenericArray<u8, N>>
    for Protected<B>
{
    fn from(value: generic_array::GenericArray<u8, N>) -> Self {
        Protected::new(value.as_slice())
    }
}

#[cfg(feature = "hybrid-array")]
#[cfg_attr(docsrs, doc(cfg(feature = "hybrid-array")))]
impl<const B: usize, N: hybrid_array::ArraySize> From<hybrid_array::Array<u8, N>> for Protected<B> {
    fn from(value: hybrid_array::Array<u8, N>) -> Self {
        Protected::new(value.as_slice())
    }
}

#[cfg(feature = "crypto-bigint-05")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint-05")))]
impl<const B: usize, const N: usize> From<crypto_bigint_05::Uint<N>> for Protected<B>
where
    crypto_bigint_05::Uint<N>: crypto_bigint_05::ArrayEncoding,
{
    fn from(value: crypto_bigint_05::Uint<N>) -> Self {
        use crypto_bigint_05::ArrayEncoding;
        Protected::new(value.to_be_byte_array().as_slice())
    }
}

#[cfg(feature = "crypto-bigint")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint")))]
impl<const B: usize, const N: usize> From<crypto_bigint::Uint<N>> for Protected<B>
where
    crypto_bigint::Uint<N>: crypto_bigint::ArrayEncoding,
{
    fn from(value: crypto_bigint::Uint<N>) -> Self {
        use crypto_bigint::ArrayEncoding;
        Protected::new(value.to_be_byte_array().as_slice())
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

from_type_to_protected!(u8, i8, u16, i16, u32, i32, u64, i64, usize, isize);

#[cfg(target_pointer_width = "64")]
from_type_to_protected!(u128, i128);

#[cfg(feature = "secret-key")]
#[cfg_attr(docsrs, doc(cfg(feature = "secret-key")))]
impl<C: elliptic_curve::Curve, const B: usize> From<elliptic_curve::SecretKey<C>> for Protected<B> {
    fn from(value: elliptic_curve::SecretKey<C>) -> Protected<B> {
        Protected::from(&value)
    }
}

#[cfg(feature = "secret-key")]
#[cfg_attr(docsrs, doc(cfg(feature = "secret-key")))]
impl<C: elliptic_curve::Curve, const B: usize> From<&elliptic_curve::SecretKey<C>>
    for Protected<B>
{
    fn from(value: &elliptic_curve::SecretKey<C>) -> Protected<B> {
        Protected::secret_key(value)
    }
}

#[cfg(feature = "signing")]
#[cfg_attr(docsrs, doc(cfg(feature = "signing")))]
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
#[cfg_attr(docsrs, doc(cfg(feature = "signing")))]
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
#[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
impl<S: blsful::BlsSignatureImpl, const B: usize> From<blsful::SecretKey<S>> for Protected<B> {
    fn from(value: blsful::SecretKey<S>) -> Protected<B> {
        Protected::from(&value)
    }
}

#[cfg(feature = "bls")]
#[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
impl<S: blsful::BlsSignatureImpl, const B: usize> From<&blsful::SecretKey<S>> for Protected<B> {
    fn from(value: &blsful::SecretKey<S>) -> Protected<B> {
        Protected::bls_secret_key(value)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl<const B: usize> From<ed25519_dalek::SigningKey> for Protected<B> {
    fn from(value: ed25519_dalek::SigningKey) -> Protected<B> {
        Protected::from(&value)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl<const B: usize> From<&ed25519_dalek::SigningKey> for Protected<B> {
    fn from(value: &ed25519_dalek::SigningKey) -> Protected<B> {
        Protected::ed25519(value)
    }
}

#[cfg(feature = "x25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "x25519")))]
impl<const B: usize> From<x25519_dalek::StaticSecret> for Protected<B> {
    fn from(value: x25519_dalek::StaticSecret) -> Protected<B> {
        Protected::from(&value)
    }
}

#[cfg(feature = "x25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "x25519")))]
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
    #[cfg_attr(docsrs, doc(cfg(feature = "elements")))]
    /// Create a new protected memory value from a field element
    pub fn field_element<F: group::ff::PrimeField>(secret: F) -> Self {
        Self::new(secret.to_repr().as_ref())
    }

    #[cfg(feature = "elements")]
    #[cfg_attr(docsrs, doc(cfg(feature = "elements")))]
    /// Create a new protected memory value from a group element
    pub fn group_element<G: group::GroupEncoding>(secret: G) -> Self {
        Self::new(secret.to_bytes().as_ref())
    }

    #[cfg(feature = "secret-key")]
    #[cfg_attr(docsrs, doc(cfg(feature = "secret-key")))]
    /// Create a new protected memory value from a secret key
    pub fn secret_key<C: elliptic_curve::Curve>(key: &elliptic_curve::SecretKey<C>) -> Self {
        Self::new(key.to_bytes())
    }

    #[cfg(feature = "signing")]
    #[cfg_attr(docsrs, doc(cfg(feature = "signing")))]
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
    #[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
    /// Create a new protected memory value from a bls secret key
    pub fn bls_secret_key<C: blsful::BlsSignatureImpl>(key: &blsful::SecretKey<C>) -> Self {
        Self::new(key.to_be_bytes())
    }

    #[cfg(feature = "ed25519")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
    /// Create a new protected memory value from a ed25519 signing key
    pub fn ed25519(key: &ed25519_dalek::SigningKey) -> Self {
        Self::new(key.to_bytes())
    }

    #[cfg(feature = "x25519")]
    #[cfg_attr(docsrs, doc(cfg(feature = "x25519")))]
    /// Create a new protected memory value from a x25519 key
    pub fn x25519(key: &x25519_dalek::StaticSecret) -> Self {
        Self::new(key.to_bytes())
    }

    /// Create a new protected memory value from a fixed-length byte array
    pub fn array<const N: usize>(value: [u8; N]) -> Self {
        Self::new(value.as_slice())
    }

    /// Create a new protected memory value from a boxed byte slice
    pub fn boxed(value: Box<[u8]>) -> Self {
        Self::new(value.as_ref())
    }

    #[cfg(feature = "generic-array-014")]
    #[cfg_attr(docsrs, doc(cfg(feature = "generic-array-014")))]
    /// Create a new protected memory value from a [`generic_array_014::GenericArray`]
    pub fn generic_array_014<N: generic_array_014::ArrayLength<u8>>(
        value: generic_array_014::GenericArray<u8, N>,
    ) -> Self {
        Self::new(value.as_slice())
    }

    #[cfg(feature = "generic-array")]
    #[cfg_attr(docsrs, doc(cfg(feature = "generic-array")))]
    /// Create a new protected memory value from a [`generic_array::GenericArray`]
    pub fn generic_array<N: generic_array::ArrayLength>(
        value: generic_array::GenericArray<u8, N>,
    ) -> Self {
        Self::new(value.as_slice())
    }

    #[cfg(feature = "hybrid-array")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hybrid-array")))]
    /// Create a new protected memory value from a [`hybrid_array::Array`]
    pub fn hybrid_array<N: hybrid_array::ArraySize>(value: hybrid_array::Array<u8, N>) -> Self {
        Self::new(value.as_slice())
    }

    #[cfg(feature = "crypto-bigint-05")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint-05")))]
    /// Create a new protected memory value from a [`crypto_bigint_05::Uint`] (crypto-bigint 0.5).
    pub fn crypto_bigint_05<T: crypto_bigint_05::ArrayEncoding>(value: T) -> Self {
        Self::new(value.to_be_byte_array().as_slice())
    }

    #[cfg(feature = "crypto-bigint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint")))]
    /// Create a new protected memory value from a [`crypto_bigint::Uint`] (crypto-bigint 0.6).
    pub fn crypto_bigint<T: crypto_bigint::ArrayEncoding>(value: T) -> Self {
        Self::new(value.to_be_byte_array().as_slice())
    }

    /// Create a new protected memory value from a string slice
    pub fn str<A: AsRef<str>>(secret: A) -> Self {
        Self::new(secret.as_ref().as_bytes())
    }

    /// Create a new protected memory value from a bool
    pub fn bool(input: bool) -> Self {
        Self::new([input as u8])
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

    /// Create a new protected memory value from a usize
    pub fn usize(input: usize) -> Self {
        Self::new(input.to_be_bytes())
    }

    /// Create a new protected memory value from a isize
    pub fn isize(input: isize) -> Self {
        Self::new(input.to_be_bytes())
    }

    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    /// Serialize a secret into protected memory
    pub fn serde<T: serde::Serialize>(secret: &T) -> Result<Self, Box<dyn std::error::Error>> {
        let s = postcard::to_stdvec(secret).map_err(|e| string_error::into_err(e.to_string()))?;
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
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    /// Deserialize a secret
    pub fn serde<T: serde::de::DeserializeOwned>(&self) -> Result<T, Box<dyn std::error::Error>> {
        Ok(postcard::from_bytes::<T>(self.as_ref()).map_err(Box::new)?)
    }

    #[cfg(feature = "elements")]
    #[cfg_attr(docsrs, doc(cfg(feature = "elements")))]
    /// Convert the secret into a field element
    pub fn field_element<F: group::ff::PrimeField>(&self) -> Result<F, Box<dyn std::error::Error>> {
        let mut repr = F::Repr::default();
        repr.as_mut().copy_from_slice(self.as_ref());
        Option::<F>::from(F::from_repr(repr))
            .ok_or(string_error::static_err("invalid field element"))
    }

    #[cfg(feature = "elements")]
    #[cfg_attr(docsrs, doc(cfg(feature = "elements")))]
    /// Convert the secret into a group element
    pub fn group_element<G: group::GroupEncoding>(&self) -> Result<G, Box<dyn std::error::Error>> {
        let mut repr = G::Repr::default();
        repr.as_mut().copy_from_slice(self.as_ref());
        Option::<G>::from(G::from_bytes(&repr))
            .ok_or(string_error::static_err("invalid group element"))
    }

    #[cfg(feature = "secret-key")]
    #[cfg_attr(docsrs, doc(cfg(feature = "secret-key")))]
    /// Convert the secret to a secret key
    pub fn secret_key<C: elliptic_curve::Curve>(
        &self,
    ) -> Result<elliptic_curve::SecretKey<C>, Box<dyn std::error::Error>> {
        elliptic_curve::SecretKey::from_slice(self.as_ref())
            .map_err(|e| string_error::into_err(e.to_string()))
    }

    #[cfg(feature = "signing")]
    #[cfg_attr(docsrs, doc(cfg(feature = "signing")))]
    /// Convert the secret to a signing key
    pub fn signing_key<C>(&self) -> Result<ecdsa::SigningKey<C>, Box<dyn std::error::Error>>
    where
        C: ecdsa::PrimeCurve + elliptic_curve::CurveArithmetic,
        elliptic_curve::Scalar<C>: elliptic_curve::ops::Invert<Output = subtle::CtOption<elliptic_curve::Scalar<C>>>
            + ecdsa::hazmat::SignPrimitive<C>,
        ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    {
        ecdsa::SigningKey::from_slice(self.as_ref())
            .map_err(|e: ecdsa::Error| string_error::into_err(e.to_string()))
    }

    #[cfg(feature = "bls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
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
    #[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
    /// Convert the secret to an ed25519 signing key
    pub fn ed25519(&self) -> Result<ed25519_dalek::SigningKey, Box<dyn std::error::Error>> {
        Ok(ed25519_dalek::SigningKey::from_bytes(
            &<[u8; 32]>::try_from(self.as_ref())
                .map_err(|_| string_error::static_err("invalid ed25519 signing key"))?,
        ))
    }

    #[cfg(feature = "x25519")]
    #[cfg_attr(docsrs, doc(cfg(feature = "x25519")))]
    /// Convert the secret to a x25519 key
    pub fn x25519(&self) -> Result<x25519_dalek::StaticSecret, Box<dyn std::error::Error>> {
        Ok(x25519_dalek::StaticSecret::from(
            <[u8; 32]>::try_from(self.as_ref())
                .map_err(|_| string_error::static_err("invalid x25519 key"))?,
        ))
    }

    /// Return the protected secret as a fixed-length byte array.
    /// Panics if the secret length is not exactly `N` bytes.
    pub fn array<const N: usize>(&self) -> [u8; N] {
        <[u8; N]>::try_from(self.as_ref())
            .expect("protected value length does not match array size")
    }

    /// Return the protected secret as a fixed-length byte array, or an error if the length does not match.
    pub fn try_array<const N: usize>(&self) -> Result<[u8; N], Box<dyn std::error::Error>> {
        <[u8; N]>::try_from(self.as_ref()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "length mismatch").into()
        })
    }

    #[cfg(feature = "generic-array-014")]
    #[cfg_attr(docsrs, doc(cfg(feature = "generic-array-014")))]
    /// Return the protected secret as a [`generic_array_014::GenericArray`].
    /// Panics if the secret length does not match the array size.
    pub fn generic_array_014<N: generic_array_014::ArrayLength<u8>>(
        &self,
    ) -> generic_array_014::GenericArray<u8, N> {
        generic_array_014::GenericArray::from_exact_iter(self.as_ref().iter().cloned())
            .expect("protected value length does not match GenericArray size")
    }

    #[cfg(feature = "generic-array-014")]
    #[cfg_attr(docsrs, doc(cfg(feature = "generic-array-014")))]
    /// Return the protected secret as a [`generic_array_014::GenericArray`], or an error if the length does not match.
    pub fn try_generic_array_014<N: generic_array_014::ArrayLength<u8>>(
        &self,
    ) -> Result<generic_array_014::GenericArray<u8, N>, Box<dyn std::error::Error>> {
        generic_array_014::GenericArray::from_exact_iter(self.as_ref().iter().cloned()).ok_or_else(
            || std::io::Error::new(std::io::ErrorKind::InvalidInput, "length mismatch").into(),
        )
    }

    #[cfg(feature = "generic-array")]
    #[cfg_attr(docsrs, doc(cfg(feature = "generic-array")))]
    /// Return the protected secret as a [`generic_array::GenericArray`].
    /// Panics if the secret length does not match the array size.
    pub fn generic_array<N: generic_array::ArrayLength>(
        &self,
    ) -> generic_array::GenericArray<u8, N> {
        generic_array::GenericArray::try_from_iter(self.as_ref().iter().cloned())
            .expect("protected value length does not match GenericArray size")
    }

    #[cfg(feature = "generic-array")]
    #[cfg_attr(docsrs, doc(cfg(feature = "generic-array")))]
    /// Return the protected secret as a [`generic_array::GenericArray`], or an error if the length does not match.
    pub fn try_generic_array<N: generic_array::ArrayLength>(
        &self,
    ) -> Result<generic_array::GenericArray<u8, N>, Box<dyn std::error::Error>> {
        generic_array::GenericArray::try_from_iter(self.as_ref().iter().cloned()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "length mismatch").into()
        })
    }

    #[cfg(feature = "hybrid-array")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hybrid-array")))]
    /// Return the protected secret as a [`hybrid_array::Array`].
    /// Panics if the secret length does not match the array size.
    pub fn hybrid_array<N: hybrid_array::ArraySize>(&self) -> hybrid_array::Array<u8, N> {
        hybrid_array::Array::try_from_iter(self.as_ref().iter().cloned())
            .expect("protected value length does not match Array size")
    }

    #[cfg(feature = "hybrid-array")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hybrid-array")))]
    /// Return the protected secret as a [`hybrid_array::Array`], or an error if the length does not match.
    pub fn try_hybrid_array<N: hybrid_array::ArraySize>(
        &self,
    ) -> Result<hybrid_array::Array<u8, N>, Box<dyn std::error::Error>> {
        hybrid_array::Array::try_from_iter(self.as_ref().iter().cloned()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "length mismatch").into()
        })
    }

    #[cfg(feature = "crypto-bigint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint")))]
    /// Return the protected secret as a [`crypto_bigint::Uint`] (crypto-bigint 0.6).
    /// Panics if the secret length does not match the type's byte size.
    pub fn crypto_bigint<T: crypto_bigint::ArrayEncoding>(&self) -> T
    where
        crypto_bigint::ByteArray<T>: for<'b> TryFrom<&'b [u8]>,
        for<'b> <crypto_bigint::ByteArray<T> as TryFrom<&'b [u8]>>::Error:
            std::error::Error + 'static,
    {
        self.try_crypto_bigint()
            .expect("protected value length does not match Uint byte size")
    }

    #[cfg(feature = "crypto-bigint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint")))]
    /// Return the protected secret as a [`crypto_bigint::Uint`], or an error if the length does not match.
    pub fn try_crypto_bigint<T: crypto_bigint::ArrayEncoding>(
        &self,
    ) -> Result<T, Box<dyn std::error::Error>>
    where
        crypto_bigint::ByteArray<T>: for<'b> TryFrom<&'b [u8]>,
        for<'b> <crypto_bigint::ByteArray<T> as TryFrom<&'b [u8]>>::Error:
            std::error::Error + 'static,
    {
        let arr = crypto_bigint::ByteArray::<T>::try_from(self.as_ref())
            .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
        Ok(T::from_be_byte_array(arr))
    }

    #[cfg(feature = "crypto-bigint-05")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint-05")))]
    /// Return the protected secret as a [`crypto_bigint_05::Uint`] (crypto-bigint 0.5).
    /// Panics if the secret length does not match the type's byte size.
    pub fn crypto_bigint_05<const LIMBS: usize>(&self) -> crypto_bigint_05::Uint<LIMBS>
    where
        crypto_bigint_05::Uint<LIMBS>: crypto_bigint_05::ArrayEncoding,
    {
        self.try_crypto_bigint_05()
            .expect("protected value length does not match Uint byte size")
    }

    #[cfg(feature = "crypto-bigint-05")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint-05")))]
    /// Return the protected secret as a [`crypto_bigint_05::Uint`], or an error if the length does not match.
    pub fn try_crypto_bigint_05<const LIMBS: usize>(
        &self,
    ) -> Result<crypto_bigint_05::Uint<LIMBS>, Box<dyn std::error::Error>> {
        let bytes = self.as_ref();
        let expected = LIMBS * std::mem::size_of::<crypto_bigint_05::Limb>();
        if bytes.len() != expected {
            return Err(
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "length mismatch").into(),
            );
        }
        Ok(crypto_bigint_05::Uint::from_be_slice(bytes))
    }

    /// Return the protected secret as an owned boxed byte slice
    pub fn boxed(&self) -> Box<[u8]> {
        self.as_ref().into()
    }

    /// Return the protected secret as a string slice
    pub fn str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.as_ref()) }
    }

    /// Return the protected secret as a bool
    pub fn bool(&self) -> bool {
        self.as_ref()[0] != 0
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

    /// Return the protected secret as a usize
    pub fn usize(&self) -> usize {
        let bytes = <[u8; std::mem::size_of::<usize>()]>::try_from(self.as_ref()).unwrap();
        usize::from_be_bytes(bytes)
    }

    /// Return the protected secret as a isize
    pub fn isize(&self) -> isize {
        let bytes = <[u8; std::mem::size_of::<isize>()]>::try_from(self.as_ref()).unwrap();
        isize::from_be_bytes(bytes)
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

#[test]
fn protected_no_deps_conversions() {
    use std::borrow::Cow;
    use std::ffi::OsStr;

    let mut p: Protected<256> = true.into();
    assert_eq!(p.unprotect().unwrap().bool(), true);
    p = false.into();
    assert_eq!(p.unprotect().unwrap().bool(), false);

    let arr: [u8; 4] = [1, 2, 3, 4];
    p = arr.into();
    assert_eq!(p.unprotect().unwrap().as_ref(), &[1, 2, 3, 4]);

    p = Protected::array([10, 20, 30, 40]);
    {
        let u = p.unprotect().unwrap();
        assert_eq!(u.array::<4>(), [10, 20, 30, 40]);
        assert_eq!(u.try_array::<4>().unwrap(), [10, 20, 30, 40]);
        assert!(u.try_array::<8>().is_err());
    }

    let boxed: Box<[u8]> = vec![5, 6, 7].into_boxed_slice();
    p = boxed.into();
    assert_eq!(p.unprotect().unwrap().as_ref(), &[5, 6, 7]);

    p = Protected::boxed(vec![11, 22, 33].into_boxed_slice());
    assert_eq!(p.unprotect().unwrap().boxed().as_ref(), &[11u8, 22, 33]);

    let cow_bytes: Cow<'_, [u8]> = Cow::Borrowed(&[8, 9]);
    p = cow_bytes.into();
    assert_eq!(p.unprotect().unwrap().as_ref(), &[8, 9]);

    let cow_str: Cow<'_, str> = Cow::Borrowed("secret");
    p = cow_str.into();
    assert_eq!(p.unprotect().unwrap().str(), "secret");

    p = 42usize.into();
    assert_eq!(p.unprotect().unwrap().usize(), 42usize);
    p = (-1i32 as isize).into();
    assert_eq!(p.unprotect().unwrap().isize(), -1i32 as isize);

    let os_str = OsStr::new("path_secret");
    p = os_str.into();
    assert_eq!(p.unprotect().unwrap().as_ref(), os_str.as_encoded_bytes());

    let os_string = std::ffi::OsString::from("path_secret_owned");
    p = os_string.into();
    assert_eq!(
        p.unprotect().unwrap().as_ref(),
        std::ffi::OsStr::new("path_secret_owned").as_encoded_bytes()
    );
}

#[cfg(feature = "serde")]
#[test]
fn protect_serde() {
    #[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Data {
        one: Vec<u8>,
        two: Vec<u8>,
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

#[cfg(feature = "generic-array-014")]
#[test]
fn protect_generic_array_014() {
    use generic_array_014::{typenum::U4, GenericArray};

    let arr: GenericArray<u8, U4> = [1, 2, 3, 4].into();
    let mut p: Protected<256> = arr.into();
    {
        let u = p.unprotect().unwrap();
        assert_eq!(u.generic_array_014::<U4>().as_slice(), &[1, 2, 3, 4]);
        assert_eq!(
            u.try_generic_array_014::<U4>().unwrap().as_slice(),
            &[1, 2, 3, 4]
        );
        assert!(u
            .try_generic_array_014::<generic_array_014::typenum::U8>()
            .is_err());
    }
    p = Protected::generic_array_014(GenericArray::<u8, U4>::clone_from_slice(&[5, 6, 7, 8]));
    let u = p.unprotect().unwrap();
    assert_eq!(u.generic_array_014::<U4>().as_slice(), &[5, 6, 7, 8]);
}

#[cfg(feature = "generic-array")]
#[test]
fn protect_generic_array() {
    use generic_array::{typenum::U4, GenericArray};

    let arr: GenericArray<u8, U4> = [1, 2, 3, 4].into();
    let mut p: Protected<256> = arr.into();
    {
        let u = p.unprotect().unwrap();
        assert_eq!(u.generic_array::<U4>().as_slice(), &[1, 2, 3, 4]);
        assert_eq!(
            u.try_generic_array::<U4>().unwrap().as_slice(),
            &[1, 2, 3, 4]
        );
        assert!(u.try_generic_array::<generic_array::typenum::U8>().is_err());
    }
    p = Protected::generic_array(GenericArray::from_array([5, 6, 7, 8]));
    let u = p.unprotect().unwrap();
    assert_eq!(u.generic_array::<U4>().as_slice(), &[5, 6, 7, 8]);
}

#[cfg(feature = "hybrid-array")]
#[test]
fn protect_hybrid_array() {
    use hybrid_array::{sizes::U4, Array};

    let arr: Array<u8, U4> = Array([10, 20, 30, 40]);
    let mut p: Protected<256> = arr.into();
    {
        let u = p.unprotect().unwrap();
        assert_eq!(u.hybrid_array::<U4>().as_slice(), &[10, 20, 30, 40]);
        assert_eq!(
            u.try_hybrid_array::<U4>().unwrap().as_slice(),
            &[10, 20, 30, 40]
        );
        assert!(u.try_hybrid_array::<hybrid_array::sizes::U8>().is_err());
    }
    p = Protected::hybrid_array(Array::<u8, U4>([50, 60, 70, 80]));
    let u = p.unprotect().unwrap();
    assert_eq!(u.hybrid_array::<U4>().as_slice(), &[50, 60, 70, 80]);
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

    let sk = ed25519_dalek::SigningKey::from_bytes(&rand::rngs::OsRng.r#gen::<[u8; 32]>());
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

#[cfg(feature = "crypto-bigint-05")]
#[test]
fn protect_crypto_bigint_05() {
    use crypto_bigint_05::{U128, U256};

    let n = U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000001");
    let mut p: Protected<256> = n.into();
    {
        let u = p.unprotect().unwrap();
        let r: U256 = u.crypto_bigint_05();
        assert_eq!(r, n);
        assert!(u.try_crypto_bigint_05::<{ U256::LIMBS }>().unwrap() == n);
        assert!(u.try_crypto_bigint_05::<{ U128::LIMBS }>().is_err());
    }
    p = Protected::crypto_bigint_05(U256::from_be_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ));
    let u = p.unprotect().unwrap();
    let r: U256 = u.crypto_bigint_05();
    assert_eq!(r, U256::MAX);
}

#[cfg(feature = "crypto-bigint")]
#[test]
fn protect_crypto_bigint() {
    use crypto_bigint::U256;

    let n = U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000001");
    let mut p: Protected<256> = n.into();
    {
        let u = p.unprotect().unwrap();
        let r: U256 = u.crypto_bigint();
        assert_eq!(r, n);
        assert!(u.try_crypto_bigint::<U256>().unwrap() == n);
        assert!(u.try_crypto_bigint::<crypto_bigint::U128>().is_err());
    }
    p = Protected::crypto_bigint(U256::from_be_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ));
    let u = p.unprotect().unwrap();
    let r: U256 = u.crypto_bigint();
    assert_eq!(r, U256::MAX);
}
