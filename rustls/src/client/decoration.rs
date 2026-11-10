//! Decorations for an outgoing `ClientHello`: content that is advertised but
//! can never be negotiated.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::client::ClientConfig;
use crate::crypto::SecureRandom;
use crate::enums::CipherSuite;
use crate::error::Error;
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{ExtensionType, HpkeAead, HpkeKdf};
use crate::msgs::handshake::{
    ClientExtensions, EncryptedClientHello, EncryptedClientHelloOuter, HpkeSymmetricCipherSuite,
};
use crate::sync::Arc;

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

/// How many bytes of HPKE encapsulated key a GREASE `encrypted_client_hello`
/// claims.
///
/// X25519 (`DHKEM(X25519, HKDF-SHA256)`), which is what BoringSSL GREASEs
/// with, so this is the length Chromium-based browsers send.
const ECH_GREASE_ENC_LEN: usize = 32;

/// Build the body of a GREASE `encrypted_client_hello` extension
/// ([draft-ietf-tls-esni section 6.2][grease-ech]).
///
/// `config_id`, the encapsulated key and the payload are random, as they must
/// be: a GREASE `ECHClientHello` that repeated any of them across connections
/// would be a stronger identifier than the extension it is imitating.  They
/// are drawn once per connection and stored, rather than per message, because
/// the second `ClientHello` of a `HelloRetryRequest` exchange has to repeat
/// the first one's extensions.
///
/// The structure is encoded by `rustls`' own `ECHClientHello` codec, so it is
/// a well-formed outer `ECHClientHello` and not merely a blob of the right
/// length.  The named HPKE symmetric suite is `HKDF-SHA256` with
/// `AES-128-GCM`, which is BoringSSL's GREASE choice on hardware with AES
/// acceleration.
///
/// [grease-ech]: https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#name-grease-ech
pub(super) fn ech_grease_body(
    secure_random: &dyn SecureRandom,
    payload_len: usize,
) -> Result<Vec<u8>, Error> {
    // `payload` is `opaque payload<1..2^16-1>`: an empty one would not decode.
    let payload_len = payload_len.max(1);

    // One read for all three fields rather than three.  That is one fewer
    // trip through `SecureRandom` per connection, and it keeps this off the
    // sizes `rustls` itself asks for: a `SecureRandom` implementation is
    // entitled to treat a request of a particular size as significant (one
    // that stages a crafted 32-byte `ClientHello.random` and session ID, for
    // instance), and `ECH_GREASE_ENC_LEN` is 32.
    let mut material = vec![0u8; 1 + ECH_GREASE_ENC_LEN + payload_len];
    secure_random.fill(&mut material)?;
    let (config_id, rest) = material.split_at(1);
    let (enc, payload) = rest.split_at(ECH_GREASE_ENC_LEN);

    let mut body = Vec::new();
    EncryptedClientHello::Outer(EncryptedClientHelloOuter {
        cipher_suite: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_128_GCM,
        },
        config_id: config_id[0],
        enc: PayloadU16::new(enc.to_vec()),
        payload: PayloadU16::new(payload.to_vec()),
    })
    .encode(&mut body);
    Ok(body)
}

/// Supplies the `legacy_session_id` of an outgoing `ClientHello`, after the
/// rest of the message has been serialized.
///
/// # Why this exists
///
/// A protocol layered on top of TLS may want to put a value in
/// `legacy_session_id` that commits to the rest of the `ClientHello` -- a
/// MAC or an AEAD tag over the serialized message, so that an observer who
/// copies the field into a hello of its own cannot have it accepted.  That is
/// impossible from outside the library: the field has to be chosen before
/// `rustls` serializes the message, and the message is what it commits to.
///
/// This hook closes that circle.  `rustls` serializes the `ClientHello` with
/// the session id set to 32 zero bytes, hands those bytes to
/// [`Self::session_id`], and substitutes the 32 bytes it returns.  The
/// substituted value is what goes into the handshake transcript and onto the
/// wire, and it is what the server echoes back, so nothing else in the
/// handshake can disagree about it.
///
/// # When it is called
///
/// Once per connection, for the first `ClientHello` only, and only when that
/// hello carries a 32-byte session id (which is what TLS 1.3 compatibility
/// mode sends).  A `HelloRetryRequest` retry repeats the first hello's
/// session id, as [RFC 8446 section
/// 4.1.2](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2)
/// requires, so the hook is not consulted again -- a second call over the
/// retry's different bytes would produce a different value and break that
/// rule.
///
/// It is called after every other part of the message is final, the
/// `pre_shared_key` binders and any `encrypted_client_hello` included.
pub trait SessionIdFromClientHello: Send + Sync + Debug {
    /// Return the 32 bytes to place in `legacy_session_id`.
    ///
    /// `client_hello` is the serialized `ClientHello` handshake message --
    /// the `client_hello` type byte, its three-byte length and its body --
    /// with the 32 bytes of `legacy_session_id` set to zero.  Substituting
    /// the return value into those 32 bytes yields the message that is sent,
    /// so a value computed over `client_hello` commits to every other byte
    /// of it.
    ///
    /// An error here fails the connection.
    fn session_id(&self, client_hello: &[u8]) -> Result<[u8; 32], Error>;
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
    session_id_source: Option<Arc<dyn SessionIdFromClientHello>>,
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

    /// Fill `legacy_session_id` in from the serialized `ClientHello`.
    ///
    /// See [`SessionIdFromClientHello`] for what is passed, when, and the two
    /// cases in which the hook is not consulted.
    pub fn with_session_id_from_client_hello(
        mut self,
        source: Arc<dyn SessionIdFromClientHello>,
    ) -> Self {
        self.session_id_source = Some(source);
        self
    }

    /// Does this configuration replace the renegotiation SCSV with an extension?
    pub(super) fn renegotiation_info_extension(&self) -> bool {
        self.renegotiation_info_extension
    }

    /// Who supplies `legacy_session_id`, if anyone.
    pub(super) fn session_id_source(&self) -> Option<&Arc<dyn SessionIdFromClientHello>> {
        self.session_id_source.as_ref()
    }

    /// Does this configuration include a GREASE `encrypted_client_hello`?
    pub(super) fn ech_grease_extension(&self) -> Option<usize> {
        self.leading_extensions
            .iter()
            .chain(self.trailing_extensions.iter())
            .find_map(|ext| match ext {
                DecorativeExtension::EchGrease { payload_len } => Some(*payload_len),
                _ => None,
            })
    }

    /// Resolve the decorative extensions for a connection seeded with
    /// `grease_seed`, as `(leading, trailing)` lists of encoded extensions.
    ///
    /// GREASE indices are allocated across both lists, so the GREASE
    /// extensions of one `ClientHello` always have different code points.
    pub(super) fn resolve_extensions(
        &self,
        grease_seed: u16,
        ech_grease_body: Option<&[u8]>,
    ) -> (EncodedExtensions, EncodedExtensions) {
        let mut next_grease = 0;
        let mut resolve = |items: &[DecorativeExtension]| {
            items
                .iter()
                .filter_map(|item| match item {
                    DecorativeExtension::Grease { body_len } => {
                        let value = grease_value(grease_seed, next_grease);
                        next_grease += 1;
                        Some((
                            ExtensionType::from(value),
                            // RFC 8701 section 3.1 allows any body; Chromium
                            // sends one empty and one single zero byte.
                            vec![0u8; *body_len],
                        ))
                    }
                    DecorativeExtension::Opaque { typ, body } => Some((*typ, body.clone())),
                    // The body is drawn once per connection in
                    // `ClientHelloInput::new`, which is also where the
                    // decorations are validated, so `None` here means this
                    // variant is not configured and nothing is emitted.
                    DecorativeExtension::EchGrease { .. } => ech_grease_body
                        .map(|body| (ExtensionType::EncryptedClientHello, body.to_vec())),
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

        let mut ech_greases = 0;

        for ext in self
            .leading_extensions
            .iter()
            .chain(self.trailing_extensions.iter())
        {
            let typ = match ext {
                DecorativeExtension::Grease { .. } => continue,
                DecorativeExtension::EchGrease { .. } => {
                    ech_greases += 1;
                    // A second one would be an illegal duplicate extension,
                    // and a decorative one alongside real ECH would collide
                    // with the extension rustls encodes itself.
                    if ech_greases > 1 || config.ech_mode.is_some() {
                        return Err(Error::DecorativeExtensionRejected(
                            ExtensionType::EncryptedClientHello,
                        ));
                    }
                    continue;
                }
                DecorativeExtension::Opaque { typ, .. } => typ,
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

    /// A GREASE `encrypted_client_hello` extension, as current
    /// Chromium-based browsers send
    /// ([draft-ietf-tls-esni section 6.2][grease-ech]).
    ///
    /// This advertises the `encrypted_client_hello` code point without
    /// offering ECH: no key is encapsulated, nothing is encrypted, and
    /// `rustls`' [`EchStatus`][crate::client::EchStatus] stays
    /// [`NotOffered`][crate::client::EchStatus::NotOffered], so a server that
    /// answers with retry configurations is rejected with
    /// [`PeerMisbehaved::UnsolicitedEchExtension`][] -- the same
    /// fail-rather-than-downgrade behaviour as every other decoration.  Use
    /// [`EchMode::Grease`][crate::client::EchMode::Grease] instead if you
    /// want retry configurations ignored rather than treated as misbehaviour;
    /// that path offers ECH for real and, in this version, is only available
    /// for a TLS-1.3-only client with an HPKE-capable provider.
    ///
    /// `rustls` chooses the `config_id`, the encapsulated key and the
    /// payload, which are fresh per connection and repeated across a
    /// `HelloRetryRequest`, exactly as a real GREASE `ECHClientHello` must
    /// be.  Rejected with [`Error::DecorativeExtensionRejected`] if ECH is
    /// also configured, or if given twice.
    ///
    /// [grease-ech]: https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#name-grease-ech
    /// [`PeerMisbehaved::UnsolicitedEchExtension`]: crate::PeerMisbehaved::UnsolicitedEchExtension
    EchGrease {
        /// How many bytes of encrypted-`ClientHelloInner` payload to claim.
        ///
        /// A browser sizes this from the inner `ClientHello` it would have
        /// encrypted, plus the AEAD tag.  It is not part of any JA3 or JA4
        /// fingerprint, but it does contribute to the `ClientHello`'s length.
        /// Zero is sent as one byte, because the field's encoding is
        /// `opaque payload<1..2^16-1>`.
        payload_len: usize,
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
    use core::sync::atomic::{AtomicUsize, Ordering};

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

        let (leading, trailing) = decorations.resolve_extensions(0, None);
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
        assert_eq!(
            decorations.resolve_extensions(0, None),
            (Vec::new(), Vec::new())
        );
        assert_eq!(
            decorations.decorate_cipher_suites(&[CipherSuite::TLS13_AES_128_GCM_SHA256], 0),
            vec![CipherSuite::TLS13_AES_128_GCM_SHA256]
        );
    }

    #[test]
    fn ech_grease_is_reported_from_either_list() {
        assert_eq!(ClientHelloDecorations::new().ech_grease_extension(), None);
        assert_eq!(
            ClientHelloDecorations::new()
                .with_leading_extensions([DecorativeExtension::EchGrease { payload_len: 7 }])
                .ech_grease_extension(),
            Some(7)
        );
        assert_eq!(
            ClientHelloDecorations::new()
                .with_trailing_extensions([DecorativeExtension::EchGrease { payload_len: 9 }])
                .ech_grease_extension(),
            Some(9)
        );
    }

    #[test]
    fn ech_grease_resolves_to_the_connection_body_in_place() {
        let decorations = ClientHelloDecorations::new().with_trailing_extensions([
            DecorativeExtension::EchGrease { payload_len: 3 },
            DecorativeExtension::Opaque {
                typ: ExtensionType::Padding,
                body: vec![0u8; 2],
            },
        ]);

        let (_, trailing) = decorations.resolve_extensions(0, Some(&[1, 2, 3]));
        assert_eq!(
            trailing,
            vec![
                (ExtensionType::EncryptedClientHello, vec![1, 2, 3]),
                (ExtensionType::Padding, vec![0, 0]),
            ]
        );

        // Without a body there is nothing to emit, and `padding` keeps its
        // place rather than shifting into the gap.
        let (_, trailing) = decorations.resolve_extensions(0, None);
        assert_eq!(trailing, vec![(ExtensionType::Padding, vec![0, 0])]);
    }

    /// Counts up, so every byte of the body is visibly filled, and records
    /// the size of every request.  Avoids needing a `CryptoProvider`, of
    /// which there may be none under `--no-default-features`.
    #[derive(Debug, Default)]
    struct CountingRandom {
        reads: AtomicUsize,
        last_len: AtomicUsize,
    }

    impl SecureRandom for CountingRandom {
        fn fill(&self, buf: &mut [u8]) -> Result<(), crate::crypto::GetRandomFailed> {
            self.reads
                .fetch_add(1, Ordering::Relaxed);
            self.last_len
                .store(buf.len(), Ordering::Relaxed);
            for (i, b) in buf.iter_mut().enumerate() {
                *b = i as u8;
            }
            Ok(())
        }
    }

    #[test]
    fn ech_grease_body_is_drawn_in_one_read() {
        // Three separate reads would be three chances to collide with a size
        // a caller's `SecureRandom` treats as significant -- and the
        // encapsulated key is 32 bytes, the size of `ClientHello.random`.
        for (payload_len, expected) in [(144, 1 + 32 + 144), (0, 1 + 32 + 1)] {
            let random = CountingRandom::default();
            ech_grease_body(&random, payload_len).unwrap();
            assert_eq!(random.reads.load(Ordering::Relaxed), 1);
            assert_eq!(random.last_len.load(Ordering::Relaxed), expected);
        }
    }

    #[test]
    fn ech_grease_body_is_an_outer_ech_client_hello() {
        let random = &CountingRandom::default();
        let body = ech_grease_body(random, 239).unwrap();

        // type(1) + cipher_suite(4) + config_id(1) + enc(2+32) + payload(2+239)
        assert_eq!(body.len(), 1 + 4 + 1 + 2 + 32 + 2 + 239);
        assert_eq!(&body[..5], &[0x00, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(&body[6..8], &[0x00, 0x20]);
        assert_eq!(&body[40..42], &[0x00, 0xef]);
        // It decodes as what it claims to be.
        let mut reader = crate::msgs::codec::Reader::init(&body);
        assert!(matches!(
            EncryptedClientHello::read(&mut reader).unwrap(),
            EncryptedClientHello::Outer(_)
        ));
        assert!(!reader.any_left());

        // `opaque payload<1..2^16-1>`: a zero-length request still sends one
        // byte, because an empty payload would not decode.
        let empty = ech_grease_body(random, 0).unwrap();
        assert_eq!(&empty[empty.len() - 3..empty.len() - 1], &[0x00, 0x01]);
        assert!(EncryptedClientHello::read(&mut crate::msgs::codec::Reader::init(&empty)).is_ok());
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

        let (leading, _) = decorations.resolve_extensions(0, None);
        assert_eq!(leading, vec![(ExtensionType::ServerName, vec![])]);
        assert_eq!(
            decorations.decorate_cipher_suites(&[], 0),
            vec![CipherSuite::TLS13_AES_128_GCM_SHA256]
        );
    }
}
