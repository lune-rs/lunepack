//! The publisher-continuity check on Linux (M9, C7): there is none.

use lunepack_core::{PublisherCheck, PublisherError, SignedTree};

/// A [`PublisherCheck`] for a platform with no operating-system code signing: every pair of trees
/// is [`PublisherError::NotApplicable`], which every policy lets through. It reads nothing, so the
/// answer does not depend on either tree.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPublisherCheck;

impl PublisherCheck for NoPublisherCheck {
    fn same_publisher(
        &self,
        _installed: &SignedTree,
        _candidate: &SignedTree,
    ) -> Result<bool, PublisherError> {
        Err(PublisherError::NotApplicable)
    }
}
