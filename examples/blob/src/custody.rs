//! Durable custody of the shards this validator has attested to.
//!
//! A record is stored under the commitment of the batch it belongs to and indexed by the view the
//! gateway dispersed it at. Indexing by view is what makes expiry a single call: once a view is
//! old enough that a certificate dispersed in it can no longer be included and can no longer be
//! within its retrievability window, every shard from that view is dead weight.
//!
//! # Expiry
//!
//! [`Custody::prune`] drops everything dispersed below `finalized - FRESHNESS - WINDOW`. The
//! archive prunes whole sections of [`ITEMS_PER_SECTION`] views, so the floor is effectively
//! rounded down: a shard outlives its horizon by up to a section rather than expiring inside it.
//! The certificate registry rounds identically, so a certificate it still calls live is one whose
//! shards are genuinely still held. Because the section is what actually changes, a floor that has
//! not crossed a boundary returns without touching the archive, and pruning can be called on every
//! finalization.
//!
//! # Ownership
//!
//! [`prunable::Archive`] is move-through: `put_multi` and `prune` consume the archive and return
//! it only on success, so a failed mutation, or a future dropped part-way through one, destroys
//! the handle. [`Custody`] holds the archive in an [`Option`] and rebinds it after every await.
//! A failed mutation therefore leaves the slot empty and every later call returns
//! [`Error::Poisoned`]. That is deliberate: a failed mutable-storage operation is fatal to the
//! store, and continuing against a store whose contents are unknown would let this validator
//! attest to a shard it may not actually hold.

use crate::{
    constants::{FRESHNESS, ITEMS_PER_SECTION, WINDOW},
    wire::StrongShard,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_coding::CodecConfig;
use commonware_consensus::types::View;
use commonware_cryptography::transcript::Summary;
use commonware_runtime::{BufferPooler, Metrics, Storage, buffer::paged::CacheRef};
use commonware_storage::{
    archive::{
        Archive as _, Error as ArchiveError, Identifier, MultiArchive as _,
        prunable::{self, Archive},
    },
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZUsize};
use std::num::{NonZeroU16, NonZeroUsize};

/// Page size of the key journal's cache.
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);

/// Pages held by the key journal's cache.
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(16);

/// Bytes buffered before a journal write reaches storage.
const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(4096);

/// Failures of the custody store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The archive itself failed.
    #[error("archive: {0}")]
    Archive(#[from] ArchiveError),
    /// A previous mutation failed, so the store no longer holds an archive.
    #[error("custody store was poisoned by a failed mutation")]
    Poisoned,
}

/// One validator's holding for one batch.
///
/// The index is stored alongside the shard because it is what the shard was checked against: a
/// shard is only meaningful as "column `index` of this commitment", and on restart nothing else
/// records which column this validator held when it attested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyRecord {
    /// Position of the shard in the encoding, and of this validator in the participant set.
    pub index: u16,
    /// The shard itself.
    pub shard: StrongShard,
}

impl Write for CustodyRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.index.write(buf);
        self.shard.write(buf);
    }
}

impl EncodeSize for CustodyRecord {
    fn encode_size(&self) -> usize {
        self.index.encode_size() + self.shard.encode_size()
    }
}

impl Read for CustodyRecord {
    /// Bounds the shard's variable-length portion.
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, cfg: &CodecConfig) -> Result<Self, CodecError> {
        Ok(Self {
            index: u16::read(buf)?,
            shard: StrongShard::read_cfg(buf, cfg)?,
        })
    }
}

/// The validator's shard store.
///
/// See the module documentation for why the archive lives in an [`Option`] and what an empty slot
/// means.
pub struct Custody<E: BufferPooler + Metrics + Storage> {
    archive: Option<Archive<TwoCap, E, Summary, CustodyRecord>>,
    /// Section the last prune reached, so a floor that has not left it costs nothing.
    pruned: Option<u64>,
}

impl<E: BufferPooler + Metrics + Storage> Custody<E> {
    /// Opens the store, replaying whatever a previous run left behind.
    ///
    /// `prefix` names the partitions, so two stores sharing a prefix share their contents.
    pub async fn init(context: E, prefix: &str, shard: CodecConfig) -> Result<Self, Error> {
        let cfg = prunable::Config {
            translator: TwoCap,
            key_partition: format!("{prefix}-custody-key"),
            key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            value_partition: format!("{prefix}-custody-value"),
            compression: None,
            codec_config: shard,
            items_per_section: ITEMS_PER_SECTION,
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        };
        Ok(Self {
            archive: Some(Archive::init(context, cfg).await?),
            pruned: None,
        })
    }

    /// Stores `record` for `commitment`, dispersed at `view`.
    ///
    /// Returns only once the write is durable, because the caller signs an attestation on the
    /// strength of it. Two batches at one view is ordinary, so this stores rather than dropping
    /// the second: a plain put keeps the first item at an index and silently discards the rest.
    pub async fn put(
        &mut self,
        view: View,
        commitment: Summary,
        record: CustodyRecord,
    ) -> Result<(), Error> {
        let archive = self.archive.take().ok_or(Error::Poisoned)?;
        self.archive = Some(
            archive
                .put_multi_sync(view.get(), commitment, record)
                .await?,
        );
        Ok(())
    }

    /// Returns the record held for `commitment`, if any.
    ///
    /// A commitment held at more than one view resolves to any one of them, which is enough: a
    /// commitment binds the encoding, so every record stored under it holds the same shard.
    pub async fn get(&self, commitment: &Summary) -> Result<Option<CustodyRecord>, Error> {
        let archive = self.archive.as_ref().ok_or(Error::Poisoned)?;
        Ok(archive.get(Identifier::Key(commitment)).await?)
    }

    /// Returns whether `commitment` is stored at `view`.
    ///
    /// Narrower than [`Custody::get`], which answers for the commitment at any view and may
    /// return any of the records stored under it.
    pub async fn has_at(&self, view: View, commitment: &Summary) -> Result<bool, Error> {
        let archive = self.archive.as_ref().ok_or(Error::Poisoned)?;
        Ok(archive.has_at(view.get(), commitment).await?)
    }

    /// Returns every record stored at `view`.
    ///
    /// `None` distinguishes a view that holds nothing, or was pruned, from a view that holds an
    /// empty list, which cannot happen.
    #[cfg(test)]
    pub async fn get_all(&self, view: View) -> Result<Option<Vec<CustodyRecord>>, Error> {
        let archive = self.archive.as_ref().ok_or(Error::Poisoned)?;
        Ok(archive.get_all(view.get()).await?)
    }

    /// Drops every shard that can no longer be needed, given the latest `finalized` view.
    ///
    /// A certificate dispersed at view `D` is includable until `D + FRESHNESS` and retrievable for
    /// `WINDOW` views after that, so nothing dispersed before `finalized - FRESHNESS - WINDOW` can
    /// still be owed to anyone. The floor saturates at view zero, which makes pruning a young
    /// chain a no-op.
    ///
    /// Called on every finalization, but only acted on when the floor crosses a section boundary.
    /// The archive prunes whole sections, so a floor that has moved within one would drop nothing;
    /// skipping it turns a per-view scan into per-[`ITEMS_PER_SECTION`] work with no change to
    /// what is kept.
    pub async fn prune(&mut self, finalized: View) -> Result<(), Error> {
        let floor = finalized.saturating_sub(FRESHNESS).saturating_sub(WINDOW);
        let section = floor.get() / ITEMS_PER_SECTION.get();
        if self.pruned == Some(section) {
            return Ok(());
        }
        let archive = self.archive.take().ok_or(Error::Poisoned)?;
        self.archive = Some(archive.prune(floor.get()).await?);
        self.pruned = Some(section);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{dispersal, shard_cfg};
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use std::time::Duration;

    /// Partition prefix shared by every store in these tests.
    const PREFIX: &str = "custody";

    #[test]
    fn put_get_roundtrip() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let (header, shards) = dispersal(7, 1);
            let mut custody = Custody::init(context.child("custody"), PREFIX, shard_cfg())
                .await
                .expect("custody opens");

            let record = CustodyRecord {
                index: 2,
                shard: shards[2].clone(),
            };
            custody
                .put(header.dispersal_view, header.commitment, record.clone())
                .await
                .expect("record stores");

            assert_eq!(
                custody.get(&header.commitment).await.expect("lookup"),
                Some(record)
            );

            // A commitment that was never stored is absent, not an error.
            let (other, _) = dispersal(7, 2);
            assert_eq!(custody.get(&other.commitment).await.expect("lookup"), None);
        });
    }

    #[test]
    fn two_batches_same_view() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            // A gateway may seal more than one batch in a view, and so may two gateways.
            let (first, first_shards) = dispersal(9, 3);
            let (second, second_shards) = dispersal(9, 4);
            assert_ne!(first.commitment, second.commitment);

            let mut custody = Custody::init(context.child("custody"), PREFIX, shard_cfg())
                .await
                .expect("custody opens");
            let first_record = CustodyRecord {
                index: 0,
                shard: first_shards[0].clone(),
            };
            let second_record = CustodyRecord {
                index: 0,
                shard: second_shards[0].clone(),
            };
            custody
                .put(first.dispersal_view, first.commitment, first_record.clone())
                .await
                .expect("first record stores");
            custody
                .put(
                    second.dispersal_view,
                    second.commitment,
                    second_record.clone(),
                )
                .await
                .expect("second record stores");

            // Neither displaced the other.
            assert_eq!(
                custody.get(&first.commitment).await.expect("lookup"),
                Some(first_record)
            );
            assert_eq!(
                custody.get(&second.commitment).await.expect("lookup"),
                Some(second_record)
            );
        });
    }

    #[test]
    fn prune_drops_expired_keeps_live() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let (expired, expired_shards) = dispersal(5, 5);
            let (live, live_shards) = dispersal(200, 6);

            let mut custody = Custody::init(context.child("custody"), PREFIX, shard_cfg())
                .await
                .expect("custody opens");
            custody
                .put(
                    expired.dispersal_view,
                    expired.commitment,
                    CustodyRecord {
                        index: 1,
                        shard: expired_shards[1].clone(),
                    },
                )
                .await
                .expect("expired record stores");
            let live_record = CustodyRecord {
                index: 1,
                shard: live_shards[1].clone(),
            };
            custody
                .put(live.dispersal_view, live.commitment, live_record.clone())
                .await
                .expect("live record stores");

            // A floor below both keeps both: view 100 leaves nothing expired.
            custody.prune(View::new(100)).await.expect("prune runs");
            assert!(
                custody
                    .get(&expired.commitment)
                    .await
                    .expect("lookup")
                    .is_some()
            );

            // Finalizing view 200 puts the floor at 200 - 32 - 64 = 104, past the older batch.
            custody.prune(View::new(200)).await.expect("prune runs");
            assert_eq!(
                custody.get(&expired.commitment).await.expect("lookup"),
                None
            );
            assert_eq!(
                custody.get(&live.commitment).await.expect("lookup"),
                Some(live_record)
            );
        });
    }

    #[test]
    fn restart_replays() {
        // Write in one run of the runtime, read in the next: the second run starts from the first
        // one's storage, so it sees exactly what a restarted validator would.
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        let (expected, checkpoint) = runner.start_and_recover(|context| async move {
            let (first, first_shards) = dispersal(11, 7);
            let (second, second_shards) = dispersal(12, 8);
            let mut custody = Custody::init(context.child("custody"), PREFIX, shard_cfg())
                .await
                .expect("custody opens");

            let first_record = CustodyRecord {
                index: 4,
                shard: first_shards[4].clone(),
            };
            let second_record = CustodyRecord {
                index: 4,
                shard: second_shards[4].clone(),
            };
            custody
                .put(first.dispersal_view, first.commitment, first_record.clone())
                .await
                .expect("first record stores");
            custody
                .put(
                    second.dispersal_view,
                    second.commitment,
                    second_record.clone(),
                )
                .await
                .expect("second record stores");

            vec![
                (first.commitment, first_record),
                (second.commitment, second_record),
            ]
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let custody = Custody::init(context.child("restarted"), PREFIX, shard_cfg())
                .await
                .expect("custody reopens");
            for (commitment, record) in expected {
                assert_eq!(
                    custody.get(&commitment).await.expect("lookup"),
                    Some(record),
                    "record survived the restart"
                );
            }
        });
    }
}
