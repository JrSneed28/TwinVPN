//! ST-15 — schema versioning and migration.
//!
//! **Authority:** ADR-0020 ST-15 rules 1–6, ADR-0021 (which is what rule 2's
//! non-destructive rollback serves).
//!
//! # The six rules, and where each is realized
//!
//! | Rule | Realization |
//! |---|---|
//! | 1. The header carries `schema_version`; each record carries `rec_schema` | [`crate::vault::Vault::encode`] and [`crate::record::Record`] |
//! | 2. `schema_version > MAX_SUPPORTED` refuses with `STORE.SCHEMA_TOO_NEW` and **MUST NOT** delete, reset, downgrade or repair | [`crate::vault::Vault::decode`], which returns before the file is touched |
//! | 3. `MIN_SUPPORTED = MAX − 2`; each step is a single transaction; a pre-migration copy is retained | [`plan`] and [`Migration`] |
//! | 4. Unknown namespaces, keys and record fields are **preserved verbatim** | [`migrate_step`] copies untouched records byte-for-byte |
//! | 5. A migration **MUST NOT** advance a monotone floor and **MUST NOT** be capable of lowering one | [`Migration`] carries no floor field and there is no API here that reaches [`crate::floors::FloorSet`] |
//! | 6. A failed migration leaves the pre-migration store in place | [`migrate_step`] is pure — it returns a new image and writes nothing |
//!
//! # Rule 5, made structural
//!
//! The dangerous shape is a migration that "fixes up" a floor. There is no
//! parameter, field or return value in this module that mentions a floor, so a
//! migration cannot express one. ADR-0020 then re-asserts the floors from Tier 1
//! after migration, which [`crate::Store::open`] does by reading them from the
//! anchor rather than from the vault.
//!
//! # Phase 1 has one schema
//!
//! `MAX_SUPPORTED_SCHEMA` is 1, so [`plan`] returns an empty chain for every
//! readable vault and [`migrate_step`] has no step to perform. The machinery is
//! here, with its rules and its tests, so that the first real migration is a
//! table entry rather than a design.

use crate::error::{Result, StoreError};
use crate::vault::{Vault, MAX_SUPPORTED_SCHEMA, MIN_SUPPORTED_SCHEMA};

/// One migration step: `from` → `from + 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// The schema this step reads.
    pub from: u32,
    /// The schema it writes. Always `from + 1` — ST-15 rule 3 migrates "through
    /// the chain", so there is no multi-version jump to get wrong.
    pub to: u32,
}

/// Plans the chain of steps from `found` to [`MAX_SUPPORTED_SCHEMA`].
///
/// # Errors
///
/// [`StoreError::SchemaTooNew`] if `found` is above the maximum, and
/// [`StoreError::MigrationFailed`] if it is below [`MIN_SUPPORTED_SCHEMA`] —
/// which is not a migration failure so much as a refusal to attempt one, and is
/// reported as such rather than silently rebuilding a store the user still has
/// data in.
pub fn plan(found: u32) -> Result<Vec<Migration>> {
    if found > MAX_SUPPORTED_SCHEMA {
        return Err(StoreError::SchemaTooNew {
            found,
            max_supported: MAX_SUPPORTED_SCHEMA,
        });
    }
    if found < MIN_SUPPORTED_SCHEMA {
        return Err(StoreError::MigrationFailed {
            from: found,
            to: MAX_SUPPORTED_SCHEMA,
            step: "below MIN_SUPPORTED",
        });
    }
    Ok((found..MAX_SUPPORTED_SCHEMA)
        .map(|from| Migration { from, to: from + 1 })
        .collect())
}

/// Applies one migration step, returning a **new** image.
///
/// Pure: it writes nothing, which is rule 6 — "A failed migration leaves the
/// pre-migration store in place" — held by the function having no side effect to
/// leave behind.
///
/// # Errors
///
/// [`StoreError::MigrationFailed`] if the step is not the one the image is at,
/// or if no step is registered for it.
pub fn migrate_step(image: &Vault, step: Migration) -> Result<Vault> {
    if image.schema_version != step.from {
        return Err(StoreError::MigrationFailed {
            from: image.schema_version,
            to: step.to,
            step: "image is not at the step's source schema",
        });
    }
    // Rule 4: every record not named by a step is carried across **verbatim**,
    // including records in namespaces and under keys this build does not know.
    // The clone is the whole mechanism: a step transforms what it names and
    // touches nothing else.
    let mut out = image.clone();
    out.schema_version = step.to;
    // No step is registered yet; Phase 1 ships schema 1. A future step becomes a
    // `match (step.from, step.to)` arm here that transforms `out` and returns
    // it; the fall-through below makes forgetting to add one a typed failure
    // rather than a silent no-op that advances the version.
    drop(out);
    Err(StoreError::MigrationFailed {
        from: step.from,
        to: step.to,
        step: "no migration registered for this step",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_current_vault_needs_no_migration() {
        assert_eq!(plan(MAX_SUPPORTED_SCHEMA).expect("plan"), vec![]);
    }

    /// ST-15 rule 2: a future schema is refused with the registered code, and
    /// the planner never proposes a "downgrade" step.
    #[test]
    fn a_future_schema_is_refused_and_never_downgraded() {
        let err = plan(MAX_SUPPORTED_SCHEMA + 1).expect_err("must refuse");
        assert!(matches!(err, StoreError::SchemaTooNew { .. }));
        assert_eq!(err.reason_code().as_str(), "STORE.SCHEMA_TOO_NEW");
    }

    /// ST-15 rule 3: a vault below `MIN_SUPPORTED` is reported, not silently
    /// rebuilt — the user's data is still in it.
    #[test]
    fn a_vault_below_the_window_is_reported_rather_than_rebuilt() {
        if MIN_SUPPORTED_SCHEMA > 0 {
            let err = plan(MIN_SUPPORTED_SCHEMA - 1).expect_err("must refuse");
            assert!(matches!(err, StoreError::MigrationFailed { .. }));
        }
    }

    /// ST-15 rule 5, as a property of the module's surface: nothing here can
    /// name a floor, so a migration cannot advance or lower one.
    #[test]
    fn a_migration_has_no_way_to_name_a_floor() {
        // `Migration` is two `u32`s and `migrate_step` takes and returns a
        // `Vault`, which holds records and a sequence and no floor set. This
        // test states the shape; a future field on `Migration` that mentioned a
        // floor would have to delete it.
        let m = Migration { from: 1, to: 2 };
        assert_eq!(core::mem::size_of_val(&m), 8);
    }

    /// Rule 6: a failed step leaves the input untouched, because the function
    /// never writes.
    #[test]
    fn a_failed_step_leaves_the_pre_migration_image_intact() {
        let mut v = Vault::empty([0x1d; 16]);
        v.records.insert("peer/a".to_owned(), vec![1]);
        let before = v.clone();
        let err = migrate_step(&v, Migration { from: 1, to: 2 }).expect_err("no step registered");
        assert!(matches!(err, StoreError::MigrationFailed { .. }));
        assert_eq!(v, before);
    }

    #[test]
    fn a_step_applied_to_the_wrong_source_schema_is_refused() {
        let v = Vault::empty([0x1d; 16]);
        assert!(migrate_step(&v, Migration { from: 99, to: 100 }).is_err());
    }
}
