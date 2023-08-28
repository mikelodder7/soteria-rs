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

let mut protected = Protected::new(b"top secret");

assert_ne!(p.value, password);
assert_eq!(p.value.len(), password.len() + 16);
assert_ne!(p.pre_key, [0u8; DEFAULT_BUF_SIZE]);
assert_ne!(p.nonce, [0u8; DEFAULT_BUF_SIZE]);

let password2 = p.unprotect();
assert!(password2.is_some());
assert_eq!(password2.unwrap().as_ref(), password.as_slice());

let str_pass = password2.str();
assert_eq!("top secret", str_pass);
```

`Protected` provides convenience methods to wrap many types of secrets from strings, byte slices, and serializable types.

Use the `serde` feature to enable serialization to and from a protected type.

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