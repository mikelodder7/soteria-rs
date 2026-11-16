# Soteria

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache 2.0/MIT Licensed][license-image]

This crate implements a wrapper around a secret that is stored in memory.

The library aims to be simple to use (misuse resistant) and easy to understand.

Thus only one struct is provided `Protected`. The struct wraps the secret so it is encrypted
in memory and can be decrypted by the same application that put it there.

`Protected` allows a program to store a encrypted secret in memory. The secret
is encrypted using XChaCha20Poly1305. The encryption keys are large enough to mitigate
memory side channel attacks like Spectre, Meltdown, Rowhammer, and RamBleed.

There is a pre_key and a nonce each large enough to limit these attacks.
The pre_key and nonce are feed into a merlin transcript to mix with other data
and derive the actual encryption key. This value is wiped from memory when the dropped
or decrypted.

## [Documentation](https://docs.rs/soteria-rs)

Secrets can be made using the `Protected` struct

```rust
use soteria_rs::*;

let password = b"top secret";
let mut p = Protected::<DEFAULT_BUF_SIZE>::new(password)?;

let unprotected = p.unprotect().ok_or(Error::Invalid("tampered value"))?;
assert_eq!(unprotected.as_ref(), password.as_slice());
assert_eq!(unprotected.str()?, "top secret");
```

Every constructor and conversion returns `Result<_, soteria_rs::Error>`; nothing in
the library panics.

`Protected` provides convenience methods (and `TryFrom` impls) to wrap many types of secrets from strings, byte slices, integers, keys, and serializable types.

Use the `serde` feature to enable serialization to and from a protected type.

## Linux kernel keyring (on by default)

On Linux (x86_64, x86, aarch64, riscv64, loongarch64), the default `kernel-keyring`
feature stores one random per-process key in the kernel's process keyring and mixes
it into every sealing key. Nothing needs to be called to enable it. With it, reading
the process's memory alone (a core dump, swap, a memory-disclosure bug, Rowhammer or
RAMBleed) is no longer enough to unseal a secret; an attacker also has to run code as
the same user.

It never weakens protection. If the keyring can't be used (for example, `keyctl` is
blocked with an error by a seccomp profile, as Docker's can be), soteria falls back to
the in-memory keys only, which is exactly the behavior without the feature. Other
operating systems never use it.

What it costs:

* One extra background thread per process, named `soteria-keyring`, which keeps the
  key alive for the life of the process.
* One extra syscall each time a value is sealed or unsealed.

**Turn it off if your process runs under a seccomp filter that kills on unknown
syscalls** (for example systemd's `SystemCallFilter=` without `add_key`/`keyctl`
allowed). Such a filter terminates the process with `SIGSYS` instead of letting the
fallback run. To opt out:

```toml
soteria-rs = { version = "0.6", default-features = false }
```

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/soteria-rs.svg
[crate-link]: https://crates.io/crates/soteria-rs
[docs-image]: https://docs.rs/soteria-rs/badge.svg
[docs-link]: https://docs.rs/soteria-rs/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg