//! The gateway's signed structural claim, and the certificate that carries it into consensus.

use super::{BatchHeader, Certificate};
use crate::{
    constants::gateway_root_namespace,
    poseidon2::{self, FR_SIZE, Fr},
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Signer, Verifier as _, ed25519, transcript::Summary};

/// The gateway's signed claim about a batch's structure.
///
/// Claimed tier, and outside the attested subject on purpose: attestors hold one shard each and
/// cannot recompute a hash tree over the whole batch, so this can only ever be an attributable
/// assertion. A gateway that signs a root that disagrees with the decoded bytes has produced
/// evidence against itself; what it cannot do is fake availability, which the attestations cover.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClaimedRoot {
    /// The blob-tree root the gateway claims for the batch.
    pub root: Fr,
    /// Identity of the gateway making the claim.
    pub gateway: ed25519::PublicKey,
    /// Signature over `(commitment, root)`.
    pub signature: ed25519::Signature,
}

impl ClaimedRoot {
    /// Bytes the gateway signs: the batch commitment followed by the claimed root.
    fn message(commitment: &Summary, root: &Fr) -> Vec<u8> {
        let mut message = Vec::with_capacity(Summary::SIZE + FR_SIZE);
        message.extend_from_slice(commitment.as_ref());
        message.extend_from_slice(&poseidon2::to_bytes(root));
        message
    }

    /// Signs a claim under the base `namespace`.
    pub fn sign(
        namespace: &[u8],
        gateway: &ed25519::PrivateKey,
        commitment: &Summary,
        root: Fr,
    ) -> Self {
        let signature = gateway.sign(
            &gateway_root_namespace(namespace),
            &Self::message(commitment, &root),
        );
        Self {
            root,
            gateway: gateway.public_key(),
            signature,
        }
    }

    /// Checks the claim against the batch it is supposed to describe.
    ///
    /// Verifying this proves who made the claim, not that the claim is true. Truth is settled by
    /// decoding the batch and recomputing the root.
    pub fn verify(&self, namespace: &[u8], commitment: &Summary) -> bool {
        self.gateway.verify(
            &gateway_root_namespace(namespace),
            &Self::message(commitment, &self.root),
            &self.signature,
        )
    }
}

impl Write for ClaimedRoot {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&poseidon2::to_bytes(&self.root));
        self.gateway.write(buf);
        self.signature.write(buf);
    }
}

impl FixedSize for ClaimedRoot {
    const SIZE: usize = FR_SIZE + ed25519::PublicKey::SIZE + ed25519::Signature::SIZE;
}

impl Read for ClaimedRoot {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let encoded: [u8; FR_SIZE] = ReadExt::read(buf)?;
        let root = poseidon2::from_bytes(&encoded).ok_or(CodecError::Invalid(
            "blob::ClaimedRoot",
            "non-canonical root",
        ))?;
        Ok(Self {
            root,
            gateway: ed25519::PublicKey::read(buf)?,
            signature: ed25519::Signature::read(buf)?,
        })
    }
}

/// The availability proof, and the only blob-related object that enters consensus.
///
/// One object, three tiers: an attested [`BatchHeader`], a quorum [`Certificate`] over it, and a
/// gateway-[`ClaimedRoot`]. Holding a valid certificate means at least `2f + 1` validators custody
/// a shard, so at least `f + 1` honest ones do, which is more than the `minimum_shards` needed to
/// reconstruct.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DaCert {
    /// The attested subject.
    pub header: BatchHeader,
    /// Aggregated attestations from a quorum of validators.
    pub certificate: Certificate,
    /// The gateway's claim about the batch's structure.
    pub claimed_root: ClaimedRoot,
}

impl Write for DaCert {
    fn write(&self, buf: &mut impl BufMut) {
        self.header.write(buf);
        self.certificate.write(buf);
        self.claimed_root.write(buf);
    }
}

impl EncodeSize for DaCert {
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.certificate.encode_size() + self.claimed_root.encode_size()
    }
}

impl Read for DaCert {
    /// Number of participants in the signing set, which bounds the certificate's signer bitmap.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, participants: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            header: BatchHeader::read(buf)?,
            certificate: Certificate::read_cfg(buf, participants)?,
            claimed_root: ClaimedRoot::read(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::NAMESPACE,
        types::{
            Attestation, Scheme,
            test_util::{PARTICIPANTS, Unused, header_at},
        },
    };
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_consensus::types::View;
    use commonware_cryptography::{
        bls12381::{certificate::multisig::mocks::fixture, primitives::variant::MinSig},
        certificate::{Scheme as _, Verifier as _},
    };
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    #[test]
    fn p1_codec_rejects_non_canonical_claimed_root() {
        // The field modulus `r`, little-endian, is the smallest non-canonical encoding: it is one
        // past `r - 1`, whose low byte is zero.
        let modulus = {
            let mut encoded = poseidon2::to_bytes(&(Fr::from(0u64) - Fr::from(1u64)));
            assert_eq!(encoded[0], 0);
            encoded[0] = 1;
            encoded
        };

        let signer = ed25519::PrivateKey::from_seed(1);
        let claimed = ClaimedRoot::sign(
            NAMESPACE,
            &signer,
            &Summary::decode([3u8; 32].as_slice()).expect("summary is 32 bytes"),
            Fr::from(9u64),
        );
        let mut encoded = claimed.encode().to_vec();
        encoded[..FR_SIZE].copy_from_slice(&modulus);
        assert!(ClaimedRoot::decode(encoded.as_slice()).is_err());
    }

    #[test]
    fn p1_cert_codec_roundtrip() {
        let mut rng = test_rng();
        let fixture = fixture::<Scheme, MinSig, _>(
            &mut rng,
            NAMESPACE,
            PARTICIPANTS,
            Scheme::signer,
            Scheme::verifier,
        );
        let header = header_at(5);
        let attestations: Vec<Attestation> = fixture.schemes[..7]
            .iter()
            .map(|scheme| scheme.sign::<Unused>(&header).expect("scheme can sign"))
            .collect();
        let certificate = fixture
            .verifier
            .assemble(attestations, &Sequential)
            .expect("quorum assembles");
        let gateway = ed25519::PrivateKey::from_seed(2);
        let cert = DaCert {
            header: header.clone(),
            certificate,
            claimed_root: ClaimedRoot::sign(
                NAMESPACE,
                &gateway,
                &header.commitment,
                Fr::from(4242u64),
            ),
        };

        let encoded = cert.encode();
        let decoded =
            DaCert::decode_cfg(encoded.clone(), &(PARTICIPANTS as usize)).expect("cert decodes");
        assert_eq!(cert, decoded);

        // Every truncation fails, and so does a signer bitmap wider than the participant set.
        for cut in 0..encoded.len() {
            assert!(DaCert::decode_cfg(&encoded[..cut], &(PARTICIPANTS as usize)).is_err());
        }
        assert!(DaCert::decode_cfg(encoded, &1usize).is_err());
    }

    #[test]
    fn p1_cert_claimed_root_outside_attestation() {
        let mut rng = test_rng();
        let fixture = fixture::<Scheme, MinSig, _>(
            &mut rng,
            NAMESPACE,
            PARTICIPANTS,
            Scheme::signer,
            Scheme::verifier,
        );
        let header = header_at(9);
        let attestations: Vec<Attestation> = fixture.schemes[..7]
            .iter()
            .map(|scheme| scheme.sign::<Unused>(&header).expect("scheme can sign"))
            .collect();
        let certificate = fixture
            .verifier
            .assemble(attestations, &Sequential)
            .expect("quorum assembles");
        let gateway = ed25519::PrivateKey::from_seed(2);
        let mut cert = DaCert {
            header: header.clone(),
            certificate,
            claimed_root: ClaimedRoot::sign(
                NAMESPACE,
                &gateway,
                &header.commitment,
                Fr::from(1u64),
            ),
        };
        assert!(cert.claimed_root.verify(NAMESPACE, &cert.header.commitment));

        // Rewriting the claimed root leaves the attestations untouched, which is the whole point:
        // availability is attested, structure is only claimed.
        cert.claimed_root.root = Fr::from(2u64);
        assert!(fixture.verifier.verify_certificate::<_, Unused>(
            &mut rng,
            &cert.header,
            &cert.certificate,
            &Sequential
        ));
        assert!(!cert.claimed_root.verify(NAMESPACE, &cert.header.commitment));

        // The gateway signature is also bound to the commitment and the namespace.
        let honest = ClaimedRoot::sign(NAMESPACE, &gateway, &header.commitment, Fr::from(1u64));
        assert!(!honest.verify(
            NAMESPACE,
            &Summary::decode([8u8; 32].as_slice()).expect("summary is 32 bytes")
        ));
        assert!(!honest.verify(b"_COMMONWARE_OTHER", &header.commitment));

        // Rewriting the attested subject breaks the certificate.
        cert.header.dispersal_view = View::new(10);
        assert!(!fixture.verifier.verify_certificate::<_, Unused>(
            &mut rng,
            &cert.header,
            &cert.certificate,
            &Sequential
        ));
    }
}
