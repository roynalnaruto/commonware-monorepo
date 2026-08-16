//! The subject validators attest to, and the multi-signature scheme they attest with.

use crate::constants::attest_namespace;
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_coding::Config;
use commonware_consensus::types::View;
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    certificate::{self, Namespace as CertificateNamespace, Subject},
    ed25519,
    transcript::Summary,
};

/// The subject validators attest to.
///
/// Attested tier. Every field is checkable by a validator holding one shard: the commitment binds
/// the encoded batch, the coding configuration says how the shards were cut, and the dispersal
/// view lets an attestor reject a stale or future dispersal. The blob-tree root is deliberately
/// absent, because no validator can derive it from a single shard.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BatchHeader {
    /// Version of the dispersal format.
    pub version: u8,
    /// ZODA transcript summary binding the encoded batch. The identifier of a batch on the rail.
    pub commitment: Summary,
    /// Coding parameters the batch was encoded with.
    pub config: Config,
    /// View the gateway claimed when dispersing.
    pub dispersal_view: View,
}

impl BatchHeader {
    /// Version of the dispersal format this build produces.
    pub const VERSION: u8 = 0x01;

    /// Builds a header at the current format version.
    pub const fn new(commitment: Summary, config: Config, dispersal_view: View) -> Self {
        Self {
            version: Self::VERSION,
            commitment,
            config,
            dispersal_view,
        }
    }
}

impl Write for BatchHeader {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.commitment.write(buf);
        self.config.write(buf);
        self.dispersal_view.write(buf);
    }
}

impl EncodeSize for BatchHeader {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.commitment.encode_size()
            + self.config.encode_size()
            + self.dispersal_view.encode_size()
    }
}

impl Read for BatchHeader {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != Self::VERSION {
            return Err(CodecError::Invalid(
                "blob::BatchHeader",
                "unsupported version",
            ));
        }
        Ok(Self {
            version,
            commitment: Summary::read(buf)?,
            config: Config::read(buf)?,
            dispersal_view: View::read(buf)?,
        })
    }
}

/// Pre-computed namespace for attestations over a [`BatchHeader`].
#[derive(Clone, Debug)]
pub struct Namespace(Vec<u8>);

impl CertificateNamespace for Namespace {
    fn derive(namespace: &[u8]) -> Self {
        Self(attest_namespace(namespace))
    }
}

impl Subject for &BatchHeader {
    type Namespace = Namespace;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        &derived.0
    }

    fn message(&self) -> Bytes {
        self.encode()
    }
}

pub mod scheme {
    //! BLS12-381 multi-signature scheme over [`BatchHeader`].
    //!
    //! Attributable: a certificate names its signers, so a validator that attests to an
    //! unavailable batch can be identified. Shard index `i` is the `i`-th key of the scheme's
    //! ordered `participants()` set, which is ordered by ed25519 identity, so the same ordering
    //! drives p2p addressing and shard assignment.

    use super::{BatchHeader, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_multisig;
    use commonware_utils::N3f1;

    impl_certificate_bls12381_multisig!(&'a BatchHeader, Namespace, N3f1);
}

/// The signing scheme attestors and gateways share.
///
/// `MinSig` keeps signatures small, which matters because certificates ride inside consensus
/// blocks.
pub type Scheme = scheme::Scheme<ed25519::PublicKey, MinSig>;

/// One validator's attestation over a [`BatchHeader`].
pub type Attestation = certificate::Attestation<Scheme>;

/// An aggregated quorum of attestations.
pub type Certificate = certificate::bls12381_multisig::Certificate<MinSig>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::NAMESPACE,
        types::test_util::{PARTICIPANTS, Unused, header_at},
    };
    use commonware_cryptography::{
        bls12381::certificate::multisig::mocks::fixture,
        certificate::{Scheme as _, Verifier as _},
    };
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    #[test]
    fn cert_sign_verify_roundtrip() {
        let mut rng = test_rng();
        let fixture = fixture::<Scheme, MinSig, _>(
            &mut rng,
            NAMESPACE,
            PARTICIPANTS,
            Scheme::signer,
            Scheme::verifier,
        );
        let header = header_at(11);

        // A quorum of 7 of 10 assembles a certificate that verifies.
        let quorum: Vec<Attestation> = fixture.schemes[..7]
            .iter()
            .map(|scheme| scheme.sign::<Unused>(&header).expect("scheme can sign"))
            .collect();
        for attestation in &quorum {
            assert!(fixture.verifier.verify_attestation::<_, Unused>(
                &mut rng,
                &header,
                attestation,
                &Sequential
            ));
        }
        let certificate = fixture
            .verifier
            .assemble(quorum.clone(), &Sequential)
            .expect("quorum assembles");
        assert!(fixture.verifier.verify_certificate::<_, Unused>(
            &mut rng,
            &header,
            &certificate,
            &Sequential
        ));

        // One short of a quorum does not.
        let short: Vec<Attestation> = quorum[..6].to_vec();
        let assembled = fixture.verifier.assemble(short, &Sequential);
        assert!(assembled.is_none_or(|certificate| {
            !fixture.verifier.verify_certificate::<_, Unused>(
                &mut rng,
                &header,
                &certificate,
                &Sequential,
            )
        }));

        // A certificate is bound to its subject: a different dispersal view breaks it.
        assert!(!fixture.verifier.verify_certificate::<_, Unused>(
            &mut rng,
            &header_at(12),
            &certificate,
            &Sequential
        ));
    }
}
