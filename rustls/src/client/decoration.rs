//! Decorations for an outgoing `ClientHello`: content that is advertised but
//! can never be negotiated.

use alloc::vec;
use alloc::vec::Vec;

use crate::client::ClientConfig;
use crate::enums::CipherSuite;
use crate::error::Error;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::ClientExtensions;

/// The sixteen GREASE code points reserved by
/// [RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701#section-2).
///
/// These are deliberately meaningless: a peer that acts on one is
/// mis-implementing TLS, and `rustls` treats that as a protocol error.
pub(crate) const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Extensions resolved into the `(type, body)` pairs the encoder takes.
type EncodedExtensions = Vec<(ExtensionType, Vec<u8>)>;

/// Is `value` one of the sixteen GREASE code points?
pub(crate) fn is_grease(value: u16) -> bool {
    // The GREASE values are exactly the `0x?a?a` values with equal halves.
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0x00ff)
}

/// The `index`th GREASE code point for a connection seeded with `seed`.
///
/// Distinct for every `index < 16`, so no two GREASE extensions in one
/// `ClientHello` can collide -- which would be an illegal duplicate
/// extension.  Derived from a seed (rather than drawn afresh) so that the
/// second `ClientHello` of a `HelloRetryRequest` exchange repeats the first
/// one's values, as [RFC 8446 section
/// 4.1.2](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2)
/// requires.
pub(crate) fn grease_value(seed: u16, index: usize) -> u16 {
    // 7 is coprime with 16, so `index` 0..16 selects 16 different slots.
    GREASE_VALUES[(usize::from(seed) + index * 7) % GREASE_VALUES.len()]
}

/// Extra content for the `ClientHello` messages this client sends.
///
/// # Why this exists
///
/// A TLS implementation is identifiable from the *framing* of its
/// `ClientHello` -- which extensions and cipher suite code points appear,
/// and in which order -- separately from what it goes on to negotiate.
/// Fingerprints such as JA3 and JA4 are computed from exactly that framing,
/// and on some networks a fingerprint that belongs to no web browser is
/// itself grounds for the connection being blocked.  Users who need to avoid
/// that today either fork a TLS library (as
/// [uTLS](https://github.com/refraction-networking/utls) does to Go's
/// `crypto/tls`) or hand-roll `CryptoProvider` entries that pretend to
/// implement code points they do not.
///
/// This type lets such a client add content to its `ClientHello` without
/// forking, and without claiming any capability it cannot honour.
///
/// # What it cannot do
///
/// Everything configured here is *decorative*: `rustls` advertises it, and
/// nothing more.  Decorative content is deliberately absent from every set
/// `rustls` matches a server's choices against, so:
///
/// * a server that selects a decorative cipher suite is rejected with
///   [`PeerMisbehaved::SelectedUnofferedCipherSuite`][], and
/// * a server that answers a decorative extension is rejected with
///   [`PeerMisbehaved::UnsolicitedServerHelloExtension`][] (or the TLS 1.3
///   equivalent),
///
/// exactly as if the client had never sent it.  Decorations therefore cannot
/// weaken a connection; the failure mode of asking for too much is a failed
/// handshake, not a downgraded one.
///
/// That also means decorations must only name things the servers you talk to
/// will ignore.  GREASE code points are ignored by every correct
/// implementation and are always safe.  A real extension that a server might
/// answer -- `application_settings`, say -- will break the handshake against
/// a server that supports it.
///
/// Decorations are applied only to the outer `ClientHello`.  They do not
/// affect what is negotiated, so two [`ClientConfig`]s that differ only in
/// their decorations may share a session cache.
///
/// # Example
///
/// Two GREASE extensions and a leading GREASE cipher suite, which is what
/// Chromium-based browsers send:
///
/// ```
/// use rustls::client::{ClientHelloDecorations, DecorativeCipherSuite, DecorativeExtension};
///
/// let decorations = ClientHelloDecorations::new()
///     .with_leading_cipher_suites([DecorativeCipherSuite::Grease])
///     .with_leading_extensions([DecorativeExtension::Grease { body_len: 0 }])
///     .with_trailing_extensions([DecorativeExtension::Grease { body_len: 1 }]);
/// ```
///
/// [`PeerMisbehaved::SelectedUnofferedCipherSuite`]: crate::PeerMisbehaved::SelectedUnofferedCipherSuite
/// [`PeerMisbehaved::UnsolicitedServerHelloExtension`]: crate::PeerMisbehaved::UnsolicitedServerHelloExtension
#[derive(Clone, Debug, Default)]
pub struct ClientHelloDecorations {
    leading_extensions: Vec<DecorativeExtension>,
    trailing_extensions: Vec<DecorativeExtension>,
    leading_cipher_suites: Vec<DecorativeCipherSuite>,
    trailing_cipher_suites: Vec<DecorativeCipherSuite>,
    renegotiation_info_extension: bool,
}

impl ClientHelloDecorations {
    /// No decorations: the `ClientHello` is unaltered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit these extensions, in this order, before all others.
    pub fn with_leading_extensions(
        mut self,
        extensions: impl IntoIterator<Item = DecorativeExtension>,
    ) -> Self {
        self.leading_extensions.extend(
            extensions
                .into_iter()
                .map(canonical_extension),
        );
        self
    }

    /// Emit these extensions, in this order, after all others.
    ///
    /// The `encrypted_client_hello` and `pre_shared_key` extensions are
    /// required by their specifications to be last, so these are emitted
    /// before those two if they are present.
    pub fn with_trailing_extensions(
        mut self,
        extensions: impl IntoIterator<Item = DecorativeExtension>,
    ) -> Self {
        self.trailing_extensions.extend(
            extensions
                .into_iter()
                .map(canonical_extension),
        );
        self
    }

    /// Advertise these cipher suites, in this order, before all others.
    pub fn with_leading_cipher_suites(
        mut self,
        suites: impl IntoIterator<Item = DecorativeCipherSuite>,
    ) -> Self {
        self.leading_cipher_suites.extend(
            suites
                .into_iter()
                .map(canonical_cipher_suite),
        );
        self
    }

    /// Advertise these cipher suites, in this order, after all others.
    pub fn with_trailing_cipher_suites(
        mut self,
        suites: impl IntoIterator<Item = DecorativeCipherSuite>,
    ) -> Self {
        self.trailing_cipher_suites.extend(
            suites
                .into_iter()
                .map(canonical_cipher_suite),
        );
        self
    }

    /// Signal support for secure renegotiation with the `renegotiation_info`
    /// extension rather than `TLS_EMPTY_RENEGOTIATION_INFO_SCSV`.
    ///
    /// [RFC 5746](https://datatracker.ietf.org/doc/html/rfc5746) defines both
    /// forms and they mean the same thing.  `rustls` sends the SCSV by
    /// default; web browsers send the extension.  `rustls` does not implement
    /// renegotiation either way, so this changes nothing but the framing.
    pub fn with_renegotiation_info_extension(mut self) -> Self {
        self.renegotiation_info_extension = true;
        self
    }

    /// Does this configuration replace the renegotiation SCSV with an extension?
    pub(super) fn renegotiation_info_extension(&self) -> bool {
        self.renegotiation_info_extension
    }

    /// Resolve the decorative extensions for a connection seeded with
    /// `grease_seed`, as `(leading, trailing)` lists of encoded extensions.
    ///
    /// GREASE indices are allocated across both lists, so the GREASE
    /// extensions of one `ClientHello` always have different code points.
    pub(super) fn resolve_extensions(
        &self,
        grease_seed: u16,
    ) -> (EncodedExtensions, EncodedExtensions) {
        let mut next_grease = 0;
        let mut resolve = |items: &[DecorativeExtension]| {
            items
                .iter()
                .map(|item| match item {
                    DecorativeExtension::Grease { body_len } => {
                        let value = grease_value(grease_seed, next_grease);
                        next_grease += 1;
                        (
                            ExtensionType::from(value),
                            // RFC 8701 section 3.1 allows any body; Chromium
                            // sends one empty and one single zero byte.
                            vec![0u8; *body_len],
                        )
                    }
                    DecorativeExtension::Opaque { typ, body } => (*typ, body.clone()),
                })
                .collect()
        };

        let leading = resolve(&self.leading_extensions);
        let trailing = resolve(&self.trailing_extensions);
        (leading, trailing)
    }

    /// Place `negotiable` between the decorative cipher suites, resolving
    /// GREASE for a connection seeded with `grease_seed`.
    pub(super) fn decorate_cipher_suites(
        &self,
        negotiable: &[CipherSuite],
        grease_seed: u16,
    ) -> Vec<CipherSuite> {
        // The cipher suite and extension registries are separate, so this
        // GREASE index space is separate too.
        let mut next_grease = 0;
        let mut resolve = |items: &[DecorativeCipherSuite], out: &mut Vec<CipherSuite>| {
            for item in items {
                out.push(match item {
                    DecorativeCipherSuite::Grease => {
                        let value = grease_value(grease_seed, next_grease);
                        next_grease += 1;
                        CipherSuite::from(value)
                    }
                    DecorativeCipherSuite::Opaque(suite) => *suite,
                });
            }
        };

        let mut out = Vec::with_capacity(
            negotiable.len() + self.leading_cipher_suites.len() + self.trailing_cipher_suites.len(),
        );
        resolve(&self.leading_cipher_suites, &mut out);
        out.extend_from_slice(negotiable);
        resolve(&self.trailing_cipher_suites, &mut out);
        out
    }

    /// Check that nothing configured here could be negotiated, or collide.
    ///
    /// This is checked when a connection is created rather than when the
    /// decorations are built, because it depends on the `ClientConfig`'s
    /// [`CryptoProvider`][crate::crypto::CryptoProvider].
    pub(super) fn validate(&self, config: &ClientConfig) -> Result<(), Error> {
        let mut seen = Vec::new();

        for ext in self
            .leading_extensions
            .iter()
            .chain(self.trailing_extensions.iter())
        {
            let DecorativeExtension::Opaque { typ, .. } = ext else {
                continue;
            };

            // A code point rustls models is one it may negotiate, and would
            // then be encoded twice.
            if ClientExtensions::ALL_EXTENSIONS.contains(typ)
                // A GREASE code point must come from `Grease`, so that rustls
                // can keep the values distinct and fresh per connection.
                || is_grease(u16::from(*typ))
                || seen.contains(typ)
            {
                return Err(Error::DecorativeExtensionRejected(*typ));
            }

            seen.push(*typ);
        }

        if self.renegotiation_info_extension && seen.contains(&ExtensionType::RenegotiationInfo) {
            return Err(Error::DecorativeExtensionRejected(
                ExtensionType::RenegotiationInfo,
            ));
        }

        for suite in self
            .leading_cipher_suites
            .iter()
            .chain(self.trailing_cipher_suites.iter())
        {
            let DecorativeCipherSuite::Opaque(suite) = suite else {
                continue;
            };

            if config
                .provider
                .cipher_suites
                .iter()
                .any(|cs| cs.suite() == *suite)
                || is_grease(u16::from(*suite))
                || *suite == CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            {
                return Err(Error::DecorativeCipherSuiteRejected(*suite));
            }
        }

        Ok(())
    }
}

/// Map an `Opaque` extension type onto the spelling `rustls` uses internally.
///
/// `ExtensionType` is an open enum, so the same code point has both a named
/// and an `Unknown` spelling.  Normalising on the way in means validation
/// and encoding always see the named form, and cannot be bypassed by naming
/// a modelled extension as `Unknown`.
fn canonical_extension(ext: DecorativeExtension) -> DecorativeExtension {
    match ext {
        DecorativeExtension::Opaque { typ, body } => DecorativeExtension::Opaque {
            typ: ExtensionType::from(u16::from(typ)),
            body,
        },
        other => other,
    }
}

/// `canonical_extension()`, for cipher suites.
fn canonical_cipher_suite(suite: DecorativeCipherSuite) -> DecorativeCipherSuite {
    match suite {
        DecorativeCipherSuite::Opaque(suite) => {
            DecorativeCipherSuite::Opaque(CipherSuite::from(u16::from(suite)))
        }
        other => other,
    }
}

/// An extension added to a `ClientHello` for its framing alone.
///
/// See [`ClientHelloDecorations`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum DecorativeExtension {
    /// A GREASE extension ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701)).
    ///
    /// `rustls` chooses the code point: one of the sixteen reserved values,
    /// varying per connection, and different for every GREASE extension in
    /// the same `ClientHello`.  The body is `body_len` zero bytes.
    Grease {
        /// How many bytes of body to send.  RFC 8701 section 3.1 permits any
        /// length; Chromium sends one empty GREASE extension and one
        /// one-byte one.
        body_len: usize,
    },

    /// An extension emitted exactly as given.
    ///
    /// `typ` must not be an extension `rustls` itself negotiates, and must
    /// not be a GREASE code point (use [`Self::Grease`] for those);
    /// otherwise connecting fails with
    /// [`Error::DecorativeExtensionRejected`].
    Opaque {
        /// The extension type.
        typ: ExtensionType,
        /// The extension body, encoded by the caller.
        body: Vec<u8>,
    },
}

/// A cipher suite advertised in a `ClientHello` for its framing alone.
///
/// See [`ClientHelloDecorations`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum DecorativeCipherSuite {
    /// A GREASE cipher suite ([RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701)).
    ///
    /// `rustls` chooses the code point, varying per connection.
    Grease,

    /// A cipher suite code point advertised as given.
    ///
    /// It must be one the configured
    /// [`CryptoProvider`][crate::crypto::CryptoProvider] does not support,
    /// and must not be a GREASE code point (use [`Self::Grease`]) or
    /// `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (see
    /// [`ClientHelloDecorations::with_renegotiation_info_extension()`]);
    /// otherwise connecting fails with
    /// [`Error::DecorativeCipherSuiteRejected`].
    Opaque(CipherSuite),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_values_are_recognised() {
        for value in GREASE_VALUES {
            assert!(is_grease(value), "{value:#06x}");
        }
    }

    #[test]
    fn non_grease_values_are_not_recognised() {
        for value in [
            0x0000, 0x0a0b, 0x0b0a, 0x1a0a, 0x0a1a, 0xffff, 0x1301, 0xaaab,
        ] {
            assert!(!is_grease(value), "{value:#06x}");
        }
    }

    #[test]
    fn grease_indices_are_distinct_within_one_hello() {
        for seed in 0..=u16::MAX {
            let values = (0..16)
                .map(|i| grease_value(seed, i))
                .collect::<Vec<_>>();
            for (i, value) in values.iter().enumerate() {
                assert!(is_grease(*value));
                assert!(
                    !values[i + 1..].contains(value),
                    "seed {seed} repeats {value:#06x}"
                );
            }
        }
    }

    #[test]
    fn grease_values_vary_with_the_seed() {
        assert_ne!(grease_value(0, 0), grease_value(1, 0));
    }

    #[test]
    fn decorative_extensions_resolve_in_order() {
        let decorations = ClientHelloDecorations::new()
            .with_leading_extensions([DecorativeExtension::Grease { body_len: 0 }])
            .with_trailing_extensions([
                DecorativeExtension::Opaque {
                    typ: ExtensionType::Padding,
                    body: vec![0u8; 3],
                },
                DecorativeExtension::Grease { body_len: 1 },
            ]);

        let (leading, trailing) = decorations.resolve_extensions(0);
        assert_eq!(
            leading,
            vec![(ExtensionType::from(GREASE_VALUES[0]), vec![])]
        );
        assert_eq!(
            trailing,
            vec![
                (ExtensionType::Padding, vec![0, 0, 0]),
                (ExtensionType::from(GREASE_VALUES[7]), vec![0]),
            ]
        );
    }

    #[test]
    fn decorative_cipher_suites_bracket_the_negotiable_ones() {
        let decorations = ClientHelloDecorations::new()
            .with_leading_cipher_suites([DecorativeCipherSuite::Grease])
            .with_trailing_cipher_suites([DecorativeCipherSuite::Opaque(
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            )]);

        assert_eq!(
            decorations.decorate_cipher_suites(&[CipherSuite::TLS13_AES_128_GCM_SHA256], 0),
            vec![
                CipherSuite::from(GREASE_VALUES[0]),
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            ]
        );
    }

    #[test]
    fn no_decorations_means_no_change() {
        let decorations = ClientHelloDecorations::new();
        assert_eq!(decorations.resolve_extensions(0), (Vec::new(), Vec::new()));
        assert_eq!(
            decorations.decorate_cipher_suites(&[CipherSuite::TLS13_AES_128_GCM_SHA256], 0),
            vec![CipherSuite::TLS13_AES_128_GCM_SHA256]
        );
    }

    #[test]
    fn opaque_code_points_are_canonicalised_on_the_way_in() {
        // `ExtensionType` and `CipherSuite` are open enums: a modelled code
        // point has both a named and an `Unknown` spelling, and validation
        // must not be bypassable by choosing the latter.
        let decorations = ClientHelloDecorations::new()
            .with_leading_extensions([DecorativeExtension::Opaque {
                typ: ExtensionType::Unknown(0x0000),
                body: vec![],
            }])
            .with_leading_cipher_suites([DecorativeCipherSuite::Opaque(CipherSuite::Unknown(
                0x1301,
            ))]);

        let (leading, _) = decorations.resolve_extensions(0);
        assert_eq!(leading, vec![(ExtensionType::ServerName, vec![])]);
        assert_eq!(
            decorations.decorate_cipher_suites(&[], 0),
            vec![CipherSuite::TLS13_AES_128_GCM_SHA256]
        );
    }
}
