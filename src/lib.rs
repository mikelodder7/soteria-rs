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
//!
//! On Unix, the secret's heap buffer is locked via `mlock(2)` to prevent it from
//! being written to swap. On Linux, `madvise(MADV_DONTDUMP)` is also applied so
//! the buffer is excluded from core dumps. On Windows, `VirtualLock` is used.
//! Locking is best-effort: failures (e.g. due to `RLIMIT_MEMLOCK`) are silently ignored.
//!
//! On Linux, the default `kernel-keyring` feature also stores a random
//! per-process key in the kernel's process keyring and mixes it into every seal
//! key, so a dump of process memory alone cannot unseal a secret. If the keyring
//! is unavailable (e.g. `keyctl` blocked with an error by seccomp), sealing falls
//! back to the in-memory keys only. Disable the feature under seccomp filters that
//! kill on unknown syscalls.
#![deny(warnings, missing_docs, dead_code)]

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInOut};
use zeroize::Zeroize;

/// Platform OS memory-locking helpers.
///
/// Uses `mlock`/`munlock` (Unix) or `VirtualLock`/`VirtualUnlock` (Windows) via
/// `extern` declarations — no extra crate dependencies required. Failures are
/// silently ignored so that callers without elevated privileges continue to work.
mod mem_lock {
    #[cfg(any(unix, windows))]
    use core::ffi::c_void;

    #[cfg(unix)]
    unsafe extern "C" {
        fn mlock(addr: *const c_void, len: usize) -> i32;
        fn munlock(addr: *const c_void, len: usize) -> i32;
    }

    #[cfg(all(unix, target_os = "linux"))]
    unsafe extern "C" {
        fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;
    }

    /// `MADV_DONTDUMP` — exclude region from core dumps (Linux only).
    #[cfg(all(unix, target_os = "linux"))]
    const MADV_DONTDUMP: i32 = 16;

    #[cfg(windows)]
    unsafe extern "system" {
        fn VirtualLock(lpAddress: *const c_void, dwSize: usize) -> i32;
        fn VirtualUnlock(lpAddress: *const c_void, dwSize: usize) -> i32;
    }

    /// Lock `len` bytes starting at `ptr` into physical RAM and, on Linux,
    /// exclude them from core dumps. No-op if `len` is zero or on unsupported platforms.
    pub(super) fn lock(ptr: *const u8, len: usize) {
        if len == 0 {
            return;
        }
        #[cfg(unix)]
        // SAFETY: ptr is valid for `len` bytes (callers guarantee this).
        unsafe {
            let _ = mlock(ptr.cast(), len);
            #[cfg(target_os = "linux")]
            let _ = madvise(ptr as *mut c_void, len, MADV_DONTDUMP);
        }
        #[cfg(windows)]
        // SAFETY: ptr is valid for `len` bytes (callers guarantee this).
        unsafe {
            let _ = VirtualLock(ptr.cast(), len);
        }
    }

    /// Unlock memory previously locked by [`lock`]. No-op if `len` is zero or on unsupported platforms.
    pub(super) fn unlock(ptr: *const u8, len: usize) {
        if len == 0 {
            return;
        }
        #[cfg(unix)]
        // SAFETY: ptr is valid for `len` bytes (callers guarantee this).
        unsafe {
            let _ = munlock(ptr.cast(), len);
        }
        #[cfg(windows)]
        // SAFETY: ptr is valid for `len` bytes (callers guarantee this).
        unsafe {
            let _ = VirtualUnlock(ptr.cast(), len);
        }
    }
}

/// Linux kernel keyring helper.
///
/// Holds one random per-process key in the kernel's process keyring
/// (`add_key(2)`/`keyctl(2)`), which is mixed into every seal key so the
/// material needed to decrypt a [`Protected`] never lives entirely in process
/// memory. Syscalls are only issued on architectures whose syscall numbers
/// are known. Any failure (e.g. a seccomp profile that blocks `keyctl`)
/// disables the kernel key for the life of the process. A parked
/// `soteria-keyring` thread anchors the key for the life of the process.
#[cfg(all(
    feature = "kernel-keyring",
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    )
))]
mod kernel_keyring {
    use core::ffi::{c_long, c_void};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{OnceLock, mpsc};
    use std::thread;
    use zeroize::Zeroize;

    unsafe extern "C" {
        fn syscall(num: c_long, ...) -> c_long;
    }

    #[cfg(target_arch = "x86_64")]
    const SYS_ADD_KEY: c_long = 248;
    #[cfg(target_arch = "x86_64")]
    const SYS_KEYCTL: c_long = 250;
    #[cfg(target_arch = "x86")]
    const SYS_ADD_KEY: c_long = 286;
    #[cfg(target_arch = "x86")]
    const SYS_KEYCTL: c_long = 288;
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    ))]
    const SYS_ADD_KEY: c_long = 217;
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    ))]
    const SYS_KEYCTL: c_long = 219;

    const KEY_SPEC_PROCESS_KEYRING: c_long = -2;
    const KEYCTL_SETPERM: c_long = 5;
    const KEYCTL_LINK: c_long = 8;
    const KEYCTL_READ: c_long = 11;
    /// Possessor: all. User: view, read, link. Read and link let a forked
    /// child re-attach the key; the key alone cannot unseal anything.
    const KEY_PERM: c_long = 0x3f00_0000 | 0x0001_0000 | 0x0002_0000 | 0x0010_0000;

    /// Length of the kernel-held key in bytes.
    pub(super) const KEY_LEN: usize = 64;

    struct KernelKey {
        serial: c_long,
        pid: AtomicU32,
    }

    static KEY: OnceLock<Option<KernelKey>> = OnceLock::new();

    /// Run `op` on a new thread that then parks for the life of the process.
    ///
    /// The kernel attaches a process keyring to the credentials of the thread
    /// that creates it, so a key linked there is freed when that thread exits.
    /// A parked thread keeps the link alive until the process exits.
    fn anchored(op: fn() -> Option<c_long>) -> Option<c_long> {
        let (tx, rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("soteria-keyring".into())
            .spawn(move || {
                let serial = op();
                let _ = tx.send(serial);
                while serial.is_some() {
                    thread::park();
                }
            })
            .ok()?;
        rx.recv().ok()?
    }

    fn add_key() -> Option<c_long> {
        let mut payload = [0u8; KEY_LEN];
        getrandom::fill(&mut payload).ok()?;
        // SAFETY: all pointers are valid NUL-terminated strings or a buffer of
        // `KEY_LEN` bytes for the duration of the call; every variadic argument
        // is passed as a long or pointer, matching what `syscall(2)` reads.
        let serial = unsafe {
            syscall(
                SYS_ADD_KEY,
                c"user".as_ptr(),
                c"soteria-rs".as_ptr(),
                payload.as_ptr().cast::<c_void>(),
                KEY_LEN as c_long,
                KEY_SPEC_PROCESS_KEYRING,
            )
        };
        payload.zeroize();
        if serial <= 0 {
            return None;
        }
        // SAFETY: integer-only arguments, passed as longs.
        let rc = unsafe { syscall(SYS_KEYCTL, KEYCTL_SETPERM, serial, KEY_PERM) };
        (rc == 0).then_some(serial)
    }

    fn link_key() -> Option<c_long> {
        let serial = KEY.get()?.as_ref()?.serial;
        // SAFETY: integer-only arguments, passed as longs.
        let rc = unsafe { syscall(SYS_KEYCTL, KEYCTL_LINK, serial, KEY_SPEC_PROCESS_KEYRING) };
        (rc == 0).then_some(serial)
    }

    fn init() -> Option<KernelKey> {
        Some(KernelKey {
            serial: anchored(add_key)?,
            pid: AtomicU32::new(std::process::id()),
        })
    }

    /// Fill `out` with the per-process kernel key. Returns `false` when the
    /// kernel keyring is unavailable, in which case `out` may be clobbered.
    pub(super) fn read(out: &mut [u8; KEY_LEN]) -> bool {
        let Some(key) = KEY.get_or_init(init) else {
            return false;
        };
        let pid = std::process::id();
        if key.pid.swap(pid, Ordering::AcqRel) != pid {
            // A forked child has no anchor thread; give it one so the key
            // outlives the parent.
            let _ = anchored(link_key);
        }
        // SAFETY: `out` is a valid, writable buffer of `KEY_LEN` bytes.
        let n = unsafe {
            syscall(
                SYS_KEYCTL,
                KEYCTL_READ,
                key.serial,
                out.as_mut_ptr().cast::<c_void>(),
                KEY_LEN as c_long,
            )
        };
        n == KEY_LEN as c_long
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn read_is_stable_or_consistently_unavailable() {
            let mut a = [0u8; KEY_LEN];
            let mut b = [0u8; KEY_LEN];
            let first = read(&mut a);
            assert_eq!(first, read(&mut b));
            assert_eq!(a, b);
            if first {
                assert_ne!(a, [0u8; KEY_LEN]);
            }
        }

        #[test]
        fn survives_exit_of_first_reader_thread() {
            let first = thread::spawn(|| {
                let mut a = [0u8; KEY_LEN];
                read(&mut a).then_some(a)
            })
            .join()
            .ok()
            .flatten();
            let Some(a) = first else {
                return;
            };
            let mut b = [0u8; KEY_LEN];
            assert!(read(&mut b));
            assert_eq!(a, b);
        }

        #[test]
        fn relinks_after_pid_change() {
            let mut a = [0u8; KEY_LEN];
            if !read(&mut a) {
                return;
            }
            if let Some(Some(key)) = KEY.get() {
                key.pid.store(0, Ordering::Release);
            }
            let mut b = [0u8; KEY_LEN];
            assert!(read(&mut b));
            assert_eq!(a, b);
        }
    }
}

/// Fallback when the kernel keyring is not available on this target.
#[cfg(not(all(
    feature = "kernel-keyring",
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    )
)))]
mod kernel_keyring {
    /// Length of the kernel-held key in bytes.
    pub(super) const KEY_LEN: usize = 64;

    /// The kernel keyring is never available on this target.
    pub(super) fn read(_out: &mut [u8; KEY_LEN]) -> bool {
        false
    }
}

/// The default BUFFER size for the prekey and nonce in memory.
/// This is large enough to inhibit speculation and side-channel attacks.
/// Consumers should not go much smaller than this.
pub const DEFAULT_BUF_SIZE: usize = 16 * 1024;

/// Length of the XChaCha20Poly1305 tag appended to every sealed value.
const TAG_LEN: usize = 16;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The OS random number generator failed.
    #[error("OS random number generator failed")]
    Rng,
    /// The value could not be sealed.
    #[error("failed to seal protected value")]
    Seal,
    /// The secret's length does not match the requested type.
    #[error("protected value is {actual} bytes, expected {expected}")]
    Length {
        /// Length the requested type needs.
        expected: usize,
        /// Length of the protected secret.
        actual: usize,
    },
    /// The secret is not valid UTF-8.
    #[error("protected value is not valid UTF-8")]
    Utf8(#[from] core::str::Utf8Error),
    /// The secret's bytes do not encode a valid value of the requested type.
    #[error("protected value is not a valid {0}")]
    Invalid(&'static str),
    /// Serialization or deserialization failed.
    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    #[error(transparent)]
    Serde(#[from] postcard::Error),
}

/// Result type for this crate.
pub type Result<T> = core::result::Result<T, Error>;

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
        mem_lock::unlock(self.value.as_ptr(), self.value.capacity());
        self.pre_key.zeroize();
        self.nonce.zeroize();
        self.value.zeroize();
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

macro_rules! impl_try_from {
    ($($type:ty => $ctor:expr),+ $(,)?) => {
        $(
            impl<const B: usize> TryFrom<$type> for Protected<B> {
                type Error = Error;

                fn try_from(value: $type) -> Result<Self> {
                    $ctor(value)
                }
            }
        )+
    };
}

impl_try_from!(
    &[u8] => Self::new,
    Vec<u8> => Self::seal,
    &str => Self::str,
    String => |v: String| Self::seal(v.into_bytes()),
    Box<[u8]> => Self::boxed,
    std::borrow::Cow<'_, [u8]> => |v: std::borrow::Cow<'_, [u8]>| Self::seal(v.into_owned()),
    std::borrow::Cow<'_, str> => |v: std::borrow::Cow<'_, str>| Self::seal(v.into_owned().into_bytes()),
    &std::ffi::OsStr => |v: &std::ffi::OsStr| Self::new(v.as_encoded_bytes()),
    std::ffi::OsString => |v: std::ffi::OsString| Self::seal(v.into_encoded_bytes()),
    bool => Self::bool,
    u8 => Self::u8,
    i8 => Self::i8,
    u16 => Self::u16,
    i16 => Self::i16,
    u32 => Self::u32,
    i32 => Self::i32,
    u64 => Self::u64,
    i64 => Self::i64,
    usize => Self::usize,
    isize => Self::isize,
);

#[cfg(target_pointer_width = "64")]
impl_try_from!(u128 => Self::u128, i128 => Self::i128);

impl<const B: usize, const N: usize> TryFrom<[u8; N]> for Protected<B> {
    type Error = Error;

    fn try_from(value: [u8; N]) -> Result<Self> {
        Self::new(value)
    }
}

#[cfg(feature = "hybrid-array")]
#[cfg_attr(docsrs, doc(cfg(feature = "hybrid-array")))]
impl<const B: usize, N: hybrid_array::ArraySize> TryFrom<hybrid_array::Array<u8, N>>
    for Protected<B>
{
    type Error = Error;

    fn try_from(value: hybrid_array::Array<u8, N>) -> Result<Self> {
        Self::hybrid_array(value)
    }
}

#[cfg(feature = "crypto-bigint")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint")))]
impl<const B: usize, const N: usize> TryFrom<crypto_bigint::Uint<N>> for Protected<B>
where
    crypto_bigint::Uint<N>: crypto_bigint::ArrayEncoding,
{
    type Error = Error;

    fn try_from(value: crypto_bigint::Uint<N>) -> Result<Self> {
        Self::crypto_bigint(value)
    }
}

#[cfg(feature = "secret-key")]
#[cfg_attr(docsrs, doc(cfg(feature = "secret-key")))]
impl<C: elliptic_curve::Curve, const B: usize> TryFrom<elliptic_curve::SecretKey<C>>
    for Protected<B>
{
    type Error = Error;

    fn try_from(value: elliptic_curve::SecretKey<C>) -> Result<Self> {
        Self::secret_key(&value)
    }
}

#[cfg(feature = "secret-key")]
#[cfg_attr(docsrs, doc(cfg(feature = "secret-key")))]
impl<C: elliptic_curve::Curve, const B: usize> TryFrom<&elliptic_curve::SecretKey<C>>
    for Protected<B>
{
    type Error = Error;

    fn try_from(value: &elliptic_curve::SecretKey<C>) -> Result<Self> {
        Self::secret_key(value)
    }
}

#[cfg(feature = "signing")]
#[cfg_attr(docsrs, doc(cfg(feature = "signing")))]
impl<C, const B: usize> TryFrom<ecdsa::SigningKey<C>> for Protected<B>
where
    C: ecdsa::EcdsaCurve + elliptic_curve::CurveArithmetic,
{
    type Error = Error;

    fn try_from(value: ecdsa::SigningKey<C>) -> Result<Self> {
        Self::signing_key(&value)
    }
}

#[cfg(feature = "signing")]
#[cfg_attr(docsrs, doc(cfg(feature = "signing")))]
impl<C, const B: usize> TryFrom<&ecdsa::SigningKey<C>> for Protected<B>
where
    C: ecdsa::EcdsaCurve + elliptic_curve::CurveArithmetic,
{
    type Error = Error;

    fn try_from(value: &ecdsa::SigningKey<C>) -> Result<Self> {
        Self::signing_key(value)
    }
}

#[cfg(feature = "bls")]
#[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
impl<S: blsful::BlsSignatureImpl, const B: usize> TryFrom<blsful::SecretKey<S>> for Protected<B> {
    type Error = Error;

    fn try_from(value: blsful::SecretKey<S>) -> Result<Self> {
        Self::bls_secret_key(&value)
    }
}

#[cfg(feature = "bls")]
#[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
impl<S: blsful::BlsSignatureImpl, const B: usize> TryFrom<&blsful::SecretKey<S>> for Protected<B> {
    type Error = Error;

    fn try_from(value: &blsful::SecretKey<S>) -> Result<Self> {
        Self::bls_secret_key(value)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl<const B: usize> TryFrom<ed25519_dalek::SigningKey> for Protected<B> {
    type Error = Error;

    fn try_from(value: ed25519_dalek::SigningKey) -> Result<Self> {
        Self::ed25519(&value)
    }
}

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
impl<const B: usize> TryFrom<&ed25519_dalek::SigningKey> for Protected<B> {
    type Error = Error;

    fn try_from(value: &ed25519_dalek::SigningKey) -> Result<Self> {
        Self::ed25519(value)
    }
}

#[cfg(feature = "x25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "x25519")))]
impl<const B: usize> TryFrom<x25519_dalek::StaticSecret> for Protected<B> {
    type Error = Error;

    fn try_from(value: x25519_dalek::StaticSecret) -> Result<Self> {
        Self::x25519(&value)
    }
}

#[cfg(feature = "x25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "x25519")))]
impl<const B: usize> TryFrom<&x25519_dalek::StaticSecret> for Protected<B> {
    type Error = Error;

    fn try_from(value: &x25519_dalek::StaticSecret) -> Result<Self> {
        Self::x25519(value)
    }
}

/// Cipher state derived from a [`Protected`]'s key material. The associated
/// data is wiped on drop.
struct Sealer {
    cipher: XChaCha20Poly1305,
    nonce: XNonce,
    aad: Vec<u8>,
}

impl Drop for Sealer {
    fn drop(&mut self) {
        self.aad.zeroize();
    }
}

macro_rules! int_constructors {
    ($($type:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Create a new protected memory value from a `", stringify!($type), "`")]
            pub fn $type(input: $type) -> Result<Self> {
                Self::new(input.to_be_bytes())
            }
        )+
    };
}

impl<const B: usize> Protected<B> {
    /// Create a new protected memory value
    pub fn new<A: AsRef<[u8]>>(secret: A) -> Result<Self> {
        let secret = secret.as_ref();
        let mut value = Vec::with_capacity(secret.len() + TAG_LEN);
        value.extend_from_slice(secret);
        Self::seal(value)
    }

    /// Seal an owned buffer without copying it, unless it lacks room for the
    /// tag. Growing in place would reallocate and leave the plaintext behind
    /// in freed memory, so a short buffer is copied and then wiped instead.
    fn seal(mut value: Vec<u8>) -> Result<Self> {
        if value.capacity() - value.len() < TAG_LEN {
            let mut sized = Vec::with_capacity(value.len() + TAG_LEN);
            sized.extend_from_slice(&value);
            value.zeroize();
            value = sized;
        }
        let mut protected = Self {
            pre_key: [0u8; B],
            nonce: [0u8; B],
            value,
        };
        protected.protect()?;
        Ok(protected)
    }

    #[cfg(feature = "elements")]
    #[cfg_attr(docsrs, doc(cfg(feature = "elements")))]
    /// Create a new protected memory value from a field element
    pub fn field_element<F: group::ff::PrimeField>(secret: F) -> Result<Self> {
        Self::new(secret.to_repr())
    }

    #[cfg(feature = "elements")]
    #[cfg_attr(docsrs, doc(cfg(feature = "elements")))]
    /// Create a new protected memory value from a group element
    pub fn group_element<G: group::GroupEncoding>(secret: G) -> Result<Self> {
        Self::new(secret.to_bytes())
    }

    #[cfg(feature = "secret-key")]
    #[cfg_attr(docsrs, doc(cfg(feature = "secret-key")))]
    /// Create a new protected memory value from a secret key
    pub fn secret_key<C: elliptic_curve::Curve>(
        key: &elliptic_curve::SecretKey<C>,
    ) -> Result<Self> {
        Self::new(key.to_bytes())
    }

    #[cfg(feature = "signing")]
    #[cfg_attr(docsrs, doc(cfg(feature = "signing")))]
    /// Create a new protected memory value from a signing key
    pub fn signing_key<C>(key: &ecdsa::SigningKey<C>) -> Result<Self>
    where
        C: ecdsa::EcdsaCurve + elliptic_curve::CurveArithmetic,
    {
        Self::new(key.to_bytes())
    }

    #[cfg(feature = "bls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
    /// Create a new protected memory value from a bls secret key
    pub fn bls_secret_key<C: blsful::BlsSignatureImpl>(key: &blsful::SecretKey<C>) -> Result<Self> {
        Self::new(key.to_be_bytes())
    }

    #[cfg(feature = "ed25519")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
    /// Create a new protected memory value from a ed25519 signing key
    pub fn ed25519(key: &ed25519_dalek::SigningKey) -> Result<Self> {
        Self::new(key.to_bytes())
    }

    #[cfg(feature = "x25519")]
    #[cfg_attr(docsrs, doc(cfg(feature = "x25519")))]
    /// Create a new protected memory value from a x25519 key
    pub fn x25519(key: &x25519_dalek::StaticSecret) -> Result<Self> {
        Self::new(key.to_bytes())
    }

    /// Create a new protected memory value from a fixed-length byte array
    pub fn array<const N: usize>(value: [u8; N]) -> Result<Self> {
        Self::new(value)
    }

    /// Create a new protected memory value from a boxed byte slice
    pub fn boxed(value: Box<[u8]>) -> Result<Self> {
        Self::seal(value.into_vec())
    }

    #[cfg(feature = "hybrid-array")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hybrid-array")))]
    /// Create a new protected memory value from a [`hybrid_array::Array`]
    pub fn hybrid_array<N: hybrid_array::ArraySize>(
        value: hybrid_array::Array<u8, N>,
    ) -> Result<Self> {
        Self::new(value)
    }

    #[cfg(feature = "crypto-bigint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint")))]
    /// Create a new protected memory value from a [`crypto_bigint::Uint`].
    pub fn crypto_bigint<T: crypto_bigint::ArrayEncoding>(value: T) -> Result<Self> {
        Self::new(value.to_be_byte_array())
    }

    /// Create a new protected memory value from a string slice
    pub fn str<A: AsRef<str>>(secret: A) -> Result<Self> {
        Self::new(secret.as_ref().as_bytes())
    }

    /// Create a new protected memory value from a bool
    pub fn bool(input: bool) -> Result<Self> {
        Self::new([u8::from(input)])
    }

    int_constructors!(u8, i8, u16, i16, u32, i32, u64, i64, usize, isize);

    #[cfg(target_pointer_width = "64")]
    int_constructors!(u128, i128);

    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    /// Serialize a secret into protected memory
    pub fn serde<T: serde::Serialize>(secret: &T) -> Result<Self> {
        Self::seal(postcard::to_stdvec(secret)?)
    }

    fn derive_seal_key(&self) -> [u8; 64] {
        let mut transcript = merlin::Transcript::new(b"protect memory region");
        transcript.append_message(b"pre_key", &self.pre_key);
        transcript.append_message(b"nonce", &self.nonce);
        let mut kernel_key = [0u8; kernel_keyring::KEY_LEN];
        if kernel_keyring::read(&mut kernel_key) {
            transcript.append_message(b"kernel_key", &kernel_key);
        }
        kernel_key.zeroize();
        let mut output = [0u8; 64];
        transcript.challenge_bytes(b"seal_data", &mut output);
        output
    }

    fn sealer(&self) -> Result<Sealer> {
        let mut output = self.derive_seal_key();
        let cipher = XChaCha20Poly1305::new_from_slice(&output[..32]);
        let nonce = XNonce::try_from(&output[32..56]);
        output.zeroize();
        let (Ok(cipher), Ok(nonce)) = (cipher, nonce) else {
            return Err(Error::Seal);
        };
        let mut aad = Vec::with_capacity(2 * B);
        aad.extend_from_slice(&self.pre_key);
        aad.extend_from_slice(&self.nonce);
        Ok(Sealer { cipher, nonce, aad })
    }

    fn protect(&mut self) -> Result<()> {
        getrandom::fill(&mut self.pre_key).map_err(|_| Error::Rng)?;
        getrandom::fill(&mut self.nonce).map_err(|_| Error::Rng)?;
        let sealer = self.sealer()?;
        sealer
            .cipher
            .encrypt_in_place(&sealer.nonce, &sealer.aad, &mut self.value)
            .map_err(|_| Error::Seal)?;
        // Lock the ciphertext buffer into RAM after every (re-)encryption.
        // mlock is idempotent on already-locked pages, so repeated calls are safe.
        mem_lock::lock(self.value.as_ptr(), self.value.capacity());
        Ok(())
    }

    /// Unprotect memory value. If the value has been tampered, [`None`] is returned.
    /// Otherwise the value is decrypted and return via [`Some`]
    pub fn unprotect(&mut self) -> Option<Unprotected<'_, B>> {
        let sealer = self.sealer().ok()?;
        sealer
            .cipher
            .decrypt_in_place(&sealer.nonce, &sealer.aad, &mut self.value)
            .ok()?;
        self.pre_key.zeroize();
        self.nonce.zeroize();
        Some(Unprotected { protected: self })
    }
}

/// Unprotected contains the decrypted value.
/// After Unprotected is dropped, the `Protected` is reengaged
/// with new cryptographic material and the value is encrypted again.
/// If re-sealing fails, the value is wiped rather than left in plaintext,
/// and every later [`Protected::unprotect`] returns [`None`].
pub struct Unprotected<'a, const B: usize = DEFAULT_BUF_SIZE> {
    protected: &'a mut Protected<B>,
}

impl<const B: usize> AsRef<[u8]> for Unprotected<'_, B> {
    fn as_ref(&self) -> &[u8] {
        self.protected.value.as_slice()
    }
}

impl<const B: usize> AsMut<[u8]> for Unprotected<'_, B> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.protected.value.as_mut()
    }
}

impl<const B: usize> Drop for Unprotected<'_, B> {
    fn drop(&mut self) {
        if self.protected.protect().is_err() {
            self.protected.value.zeroize();
        }
    }
}

macro_rules! int_getters {
    ($($type:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Return the protected secret as a big-endian `", stringify!($type), "`")]
            pub fn $type(&self) -> Result<$type> {
                Ok($type::from_be_bytes(self.array()?))
            }
        )+
    };
}

impl<const B: usize> Unprotected<'_, B> {
    fn length_error(&self, expected: usize) -> Error {
        Error::Length {
            expected,
            actual: self.as_ref().len(),
        }
    }

    #[cfg(feature = "elements")]
    fn copy_exact(&self, out: &mut [u8]) -> Result<()> {
        if out.len() != self.as_ref().len() {
            return Err(self.length_error(out.len()));
        }
        out.copy_from_slice(self.as_ref());
        Ok(())
    }

    #[cfg(feature = "serde")]
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    /// Deserialize a secret
    pub fn serde<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        Ok(postcard::from_bytes::<T>(self.as_ref())?)
    }

    #[cfg(feature = "elements")]
    #[cfg_attr(docsrs, doc(cfg(feature = "elements")))]
    /// Convert the secret into a field element
    pub fn field_element<F: group::ff::PrimeField>(&self) -> Result<F> {
        let mut repr = F::Repr::default();
        self.copy_exact(repr.as_mut())?;
        Option::<F>::from(F::from_repr(repr)).ok_or(Error::Invalid("field element"))
    }

    #[cfg(feature = "elements")]
    #[cfg_attr(docsrs, doc(cfg(feature = "elements")))]
    /// Convert the secret into a group element
    pub fn group_element<G: group::GroupEncoding>(&self) -> Result<G> {
        let mut repr = G::Repr::default();
        self.copy_exact(repr.as_mut())?;
        Option::<G>::from(G::from_bytes(&repr)).ok_or(Error::Invalid("group element"))
    }

    #[cfg(feature = "secret-key")]
    #[cfg_attr(docsrs, doc(cfg(feature = "secret-key")))]
    /// Convert the secret to a secret key
    pub fn secret_key<C: elliptic_curve::Curve>(&self) -> Result<elliptic_curve::SecretKey<C>> {
        elliptic_curve::SecretKey::from_slice(self.as_ref())
            .map_err(|_| Error::Invalid("secret key"))
    }

    #[cfg(feature = "signing")]
    #[cfg_attr(docsrs, doc(cfg(feature = "signing")))]
    /// Convert the secret to a signing key
    pub fn signing_key<C>(&self) -> Result<ecdsa::SigningKey<C>>
    where
        C: ecdsa::EcdsaCurve + elliptic_curve::CurveArithmetic,
    {
        ecdsa::SigningKey::from_slice(self.as_ref()).map_err(|_| Error::Invalid("signing key"))
    }

    #[cfg(feature = "bls")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
    /// Convert the secret to a bls secret key
    pub fn bls_secret_key<C: blsful::BlsSignatureImpl>(&self) -> Result<blsful::SecretKey<C>> {
        let mut bytes = self.array::<32>()?;
        let key = Option::from(blsful::SecretKey::<C>::from_be_bytes(&bytes));
        bytes.zeroize();
        key.ok_or(Error::Invalid("bls secret key"))
    }

    #[cfg(feature = "ed25519")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
    /// Convert the secret to an ed25519 signing key
    pub fn ed25519(&self) -> Result<ed25519_dalek::SigningKey> {
        let mut bytes = self.array::<32>()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        Ok(key)
    }

    #[cfg(feature = "x25519")]
    #[cfg_attr(docsrs, doc(cfg(feature = "x25519")))]
    /// Convert the secret to a x25519 key
    pub fn x25519(&self) -> Result<x25519_dalek::StaticSecret> {
        let mut bytes = self.array::<32>()?;
        let key = x25519_dalek::StaticSecret::from(bytes);
        bytes.zeroize();
        Ok(key)
    }

    /// Return the protected secret as a fixed-length byte array, or an error if the length does not match.
    pub fn array<const N: usize>(&self) -> Result<[u8; N]> {
        <[u8; N]>::try_from(self.as_ref()).map_err(|_| self.length_error(N))
    }

    #[cfg(feature = "hybrid-array")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hybrid-array")))]
    /// Return the protected secret as a [`hybrid_array::Array`], or an error if the length does not match.
    pub fn hybrid_array<N: hybrid_array::ArraySize>(&self) -> Result<hybrid_array::Array<u8, N>> {
        hybrid_array::Array::try_from_iter(self.as_ref().iter().copied())
            .map_err(|_| self.length_error(size_of::<hybrid_array::Array<u8, N>>()))
    }

    #[cfg(feature = "crypto-bigint")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto-bigint")))]
    /// Return the protected secret as a [`crypto_bigint::Uint`], or an error if the length does not match.
    pub fn crypto_bigint<T: crypto_bigint::ArrayEncoding>(&self) -> Result<T>
    where
        crypto_bigint::ByteArray<T>: for<'b> TryFrom<&'b [u8]>,
    {
        let arr = crypto_bigint::ByteArray::<T>::try_from(self.as_ref())
            .map_err(|_| self.length_error(size_of::<crypto_bigint::ByteArray<T>>()))?;
        Ok(T::from_be_byte_array(arr))
    }

    /// Return the protected secret as an owned boxed byte slice
    pub fn boxed(&self) -> Box<[u8]> {
        self.as_ref().into()
    }

    /// Return the protected secret as a string slice, or an error if it is not valid UTF-8.
    pub fn str(&self) -> Result<&str> {
        Ok(core::str::from_utf8(self.as_ref())?)
    }

    /// Return the protected secret as a bool, or an error if it is not exactly one byte.
    pub fn bool(&self) -> Result<bool> {
        let [byte] = self.array::<1>()?;
        Ok(byte != 0)
    }

    int_getters!(u8, i8, u16, i16, u32, i32, u64, i64, usize, isize);

    #[cfg(target_pointer_width = "64")]
    int_getters!(u128, i128);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Data {
        one: Vec<u8>,
        two: Vec<u8>,
    }

    fn data() -> Data {
        Data {
            one: vec![1u8; 16],
            two: vec![2u8; 32],
        }
    }

    #[test]
    fn protect_slice() {
        let password = b"letmeinplease!";
        let mut p = Protected::<DEFAULT_BUF_SIZE>::new(&password[..]).unwrap();
        assert_ne!(p.value, password);
        assert_eq!(p.value.len(), password.len() + TAG_LEN);
        assert_ne!(p.pre_key, [0u8; DEFAULT_BUF_SIZE]);
        assert_ne!(p.nonce, [0u8; DEFAULT_BUF_SIZE]);

        let password2 = p.unprotect();
        assert!(password2.is_some());
        assert_eq!(password2.unwrap().as_ref(), password.as_slice());
    }

    #[test]
    fn tampered_value_does_not_unprotect() {
        let mut p = Protected::<256>::new(b"secret").unwrap();
        p.value[0] ^= 1;
        assert!(p.unprotect().is_none());
    }

    #[test]
    fn exact_capacity_buffer_is_resized_before_sealing() {
        let secret = vec![7u8; 32];
        assert_eq!(secret.capacity(), 32);
        let mut p = Protected::<256>::try_from(secret).unwrap();
        assert!(p.value.capacity() >= 32 + TAG_LEN);
        let ptr = p.value.as_ptr();
        assert_eq!(p.unprotect().unwrap().as_ref(), &[7u8; 32]);
        assert_eq!(p.value.as_ptr(), ptr);
    }

    #[test]
    fn owned_buffer_with_room_is_sealed_in_place() {
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&[1u8; 8]);
        let ptr = secret.as_ptr();
        let p = Protected::<256>::try_from(secret).unwrap();
        assert_eq!(p.value.as_ptr(), ptr);
    }

    #[test]
    fn protected_integers() {
        let mut p: Protected<256> = 8u8.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().u8().unwrap(), 8);
        p = 9i8.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().i8().unwrap(), 9);
        p = 80u16.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().u16().unwrap(), 80);
        p = 90i16.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().i16().unwrap(), 90);
        p = 800u32.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().u32().unwrap(), 800);
        p = 900i32.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().i32().unwrap(), 900);
        p = 8000u64.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().u64().unwrap(), 8000);
        p = 9000i64.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().i64().unwrap(), 9000);
        p = 80000u128.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().u128().unwrap(), 80000);
        p = 90000i128.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().i128().unwrap(), 90000);
    }

    #[test]
    fn integer_length_mismatch_is_an_error() {
        let mut p = Protected::<256>::u8(1).unwrap();
        let u = p.unprotect().unwrap();
        assert!(matches!(
            u.u32(),
            Err(Error::Length {
                expected: 4,
                actual: 1
            })
        ));
        assert!(u.u16().is_err());
        assert!(u.i64().is_err());
    }

    #[test]
    fn empty_secret_is_not_a_bool() {
        let mut p = Protected::<256>::new([0u8; 0]).unwrap();
        assert!(p.unprotect().unwrap().bool().is_err());
    }

    #[test]
    fn str_rejects_invalid_utf8() {
        let mut p = Protected::<256>::new([0xffu8, 0xfe]).unwrap();
        assert!(matches!(p.unprotect().unwrap().str(), Err(Error::Utf8(_))));
    }

    #[test]
    fn protected_no_deps_conversions() {
        use std::borrow::Cow;
        use std::ffi::OsStr;

        let mut p: Protected<256> = true.try_into().unwrap();
        assert!(p.unprotect().unwrap().bool().unwrap());
        p = false.try_into().unwrap();
        assert!(!p.unprotect().unwrap().bool().unwrap());

        let arr: [u8; 4] = [1, 2, 3, 4];
        p = arr.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().as_ref(), &[1, 2, 3, 4]);

        p = Protected::array([10, 20, 30, 40]).unwrap();
        {
            let u = p.unprotect().unwrap();
            assert_eq!(u.array::<4>().unwrap(), [10, 20, 30, 40]);
            assert!(u.array::<8>().is_err());
        }

        let boxed: Box<[u8]> = vec![5, 6, 7].into_boxed_slice();
        p = boxed.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().as_ref(), &[5, 6, 7]);

        p = Protected::boxed(vec![11, 22, 33].into_boxed_slice()).unwrap();
        assert_eq!(p.unprotect().unwrap().boxed().as_ref(), &[11u8, 22, 33]);

        let cow_bytes: Cow<'_, [u8]> = Cow::Borrowed(&[8, 9]);
        p = cow_bytes.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().as_ref(), &[8, 9]);

        let cow_str: Cow<'_, str> = Cow::Borrowed("secret");
        p = cow_str.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().str().unwrap(), "secret");

        p = String::from("owned").try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().str().unwrap(), "owned");

        p = 42usize.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().usize().unwrap(), 42usize);
        p = (-1i32 as isize).try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().isize().unwrap(), -1i32 as isize);

        let os_str = OsStr::new("path_secret");
        p = os_str.try_into().unwrap();
        assert_eq!(p.unprotect().unwrap().as_ref(), os_str.as_encoded_bytes());

        let os_string = std::ffi::OsString::from("path_secret_owned");
        p = os_string.try_into().unwrap();
        assert_eq!(
            p.unprotect().unwrap().as_ref(),
            OsStr::new("path_secret_owned").as_encoded_bytes()
        );
    }

    #[test]
    fn protect_str() {
        let mut p = Protected::<DEFAULT_BUF_SIZE>::str("letmeinplease").unwrap();
        let u = p.unprotect().unwrap();
        assert_eq!(u.str().unwrap(), "letmeinplease");
    }

    fn round_trip_bytes(bytes: Vec<u8>) -> Vec<u8> {
        let mut p = Protected::<256>::try_from(bytes).unwrap();
        p.unprotect().unwrap().as_ref().to_vec()
    }

    fn round_trip_text(text: String) -> String {
        let mut p = Protected::<256>::try_from(text).unwrap();
        p.unprotect().unwrap().str().unwrap().to_owned()
    }

    #[test]
    fn serialized_secrets_round_trip_in_every_format() {
        let expected = data();

        let cbor = round_trip_bytes(serde_cbor_2::to_vec(&expected).unwrap());
        assert_eq!(serde_cbor_2::from_slice::<Data>(&cbor).unwrap(), expected);

        let json = round_trip_bytes(serde_json::to_vec(&expected).unwrap());
        assert_eq!(serde_json::from_slice::<Data>(&json).unwrap(), expected);

        let toml_text = round_trip_text(toml::to_string(&expected).unwrap());
        assert_eq!(toml::from_str::<Data>(&toml_text).unwrap(), expected);

        let yaml = round_trip_text(yaml_serde::to_string(&expected).unwrap());
        assert_eq!(yaml_serde::from_str::<Data>(&yaml).unwrap(), expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn protect_serde_postcard() {
        let expected = data();
        let mut p = Protected::<DEFAULT_BUF_SIZE>::serde(&expected).unwrap();
        assert_eq!(p.unprotect().unwrap().serde::<Data>().unwrap(), expected);

        let raw = round_trip_bytes(postcard::to_stdvec(&expected).unwrap());
        assert_eq!(postcard::from_bytes::<Data>(&raw).unwrap(), expected);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_garbage() {
        let mut p = Protected::<256>::new([0xffu8; 3]).unwrap();
        assert!(matches!(
            p.unprotect().unwrap().serde::<Data>(),
            Err(Error::Serde(_))
        ));
    }

    #[cfg(feature = "hybrid-array")]
    #[test]
    fn protect_hybrid_array() {
        use hybrid_array::{Array, sizes::U4};

        let arr: Array<u8, U4> = Array([10, 20, 30, 40]);
        let mut p: Protected<256> = arr.try_into().unwrap();
        {
            let u = p.unprotect().unwrap();
            assert_eq!(
                u.hybrid_array::<U4>().unwrap().as_slice(),
                &[10, 20, 30, 40]
            );
            assert!(u.hybrid_array::<hybrid_array::sizes::U8>().is_err());
        }
        p = Protected::hybrid_array(Array::<u8, U4>([50, 60, 70, 80])).unwrap();
        let u = p.unprotect().unwrap();
        assert_eq!(
            u.hybrid_array::<U4>().unwrap().as_slice(),
            &[50, 60, 70, 80]
        );
    }

    #[cfg(feature = "elements")]
    #[test]
    fn protect_elements() {
        use group::ff::Field;

        let sk = k256::Scalar::random(&mut rand_core::UnwrapErr(getrandom::SysRng));
        let pk = k256::ProjectivePoint::GENERATOR * sk;

        let mut p = Protected::<DEFAULT_BUF_SIZE>::field_element(sk).unwrap();
        assert_eq!(
            p.unprotect()
                .unwrap()
                .field_element::<k256::Scalar>()
                .unwrap(),
            sk
        );

        p = Protected::group_element(pk).unwrap();
        assert_eq!(
            p.unprotect()
                .unwrap()
                .group_element::<k256::ProjectivePoint>()
                .unwrap(),
            pk
        );
    }

    #[cfg(feature = "elements")]
    #[test]
    fn wrong_length_is_not_an_element() {
        let mut p = Protected::<256>::new([1u8; 5]).unwrap();
        let u = p.unprotect().unwrap();
        assert!(matches!(
            u.field_element::<k256::Scalar>(),
            Err(Error::Length { actual: 5, .. })
        ));
        assert!(u.group_element::<k256::ProjectivePoint>().is_err());
    }

    #[cfg(feature = "secret-key")]
    #[test]
    fn protect_secret_key() {
        let sk = <k256::SecretKey as elliptic_curve::Generate>::generate_from_rng(
            &mut rand_core::UnwrapErr(getrandom::SysRng),
        );
        let mut p: Protected<DEFAULT_BUF_SIZE> = (&sk).try_into().unwrap();
        assert_eq!(
            p.unprotect()
                .unwrap()
                .secret_key::<k256::Secp256k1>()
                .unwrap(),
            sk
        );
    }

    #[cfg(feature = "signing")]
    #[test]
    fn protect_signing_key() {
        let sk =
            <ecdsa::SigningKey<k256::Secp256k1> as elliptic_curve::Generate>::generate_from_rng(
                &mut rand_core::UnwrapErr(getrandom::SysRng),
            );
        let mut p: Protected<DEFAULT_BUF_SIZE> = (&sk).try_into().unwrap();
        assert_eq!(
            p.unprotect()
                .unwrap()
                .signing_key::<k256::Secp256k1>()
                .unwrap(),
            sk
        );
    }

    #[cfg(feature = "bls")]
    #[test]
    fn protect_bls_secret_key() {
        let sk = blsful::Bls12381G1::new_secret_key();
        let mut p: Protected<DEFAULT_BUF_SIZE> = (&sk).try_into().unwrap();
        assert_eq!(
            p.unprotect()
                .unwrap()
                .bls_secret_key::<blsful::Bls12381G1Impl>()
                .unwrap(),
            sk
        );
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn protect_ed25519() {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let mut p: Protected<DEFAULT_BUF_SIZE> = (&sk).try_into().unwrap();
        assert_eq!(
            p.unprotect().unwrap().ed25519().unwrap().to_bytes(),
            sk.to_bytes()
        );
    }

    #[cfg(feature = "x25519")]
    #[test]
    fn protect_x25519() {
        let sk = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::UnwrapErr(
            getrandom::SysRng,
        ));
        let mut p: Protected<DEFAULT_BUF_SIZE> = (&sk).try_into().unwrap();
        assert_eq!(
            p.unprotect().unwrap().x25519().unwrap().to_bytes(),
            sk.to_bytes()
        );
    }

    #[cfg(feature = "crypto-bigint")]
    #[test]
    fn protect_crypto_bigint() {
        use crypto_bigint::U256;

        let n =
            U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000001");
        let mut p: Protected<256> = n.try_into().unwrap();
        {
            let u = p.unprotect().unwrap();
            assert_eq!(u.crypto_bigint::<U256>().unwrap(), n);
            assert!(u.crypto_bigint::<crypto_bigint::U128>().is_err());
        }
        p = Protected::crypto_bigint(U256::MAX).unwrap();
        let r: U256 = p.unprotect().unwrap().crypto_bigint().unwrap();
        assert_eq!(r, U256::MAX);
    }
}
