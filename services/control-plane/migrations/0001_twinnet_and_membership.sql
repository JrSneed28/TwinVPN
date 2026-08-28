-- 0001 — the TwinNet, its write lease, and the membership it is authoritative for.
--
-- Authority: docs/architecture.md §5 rows S-02, S-03, S-08, S-26, S-28;
-- ADR-0002 §11.3 and N-4; ADR-0008 N-1 and N-7; ADR-0009 §11.2.
--
-- REVERSIBLE: yes. `DROP TABLE device, twinnet CASCADE;` restores the empty
-- database. It is destructive of data, as any migration that creates the tables
-- holding the data must be, and there is no forward path that needs it.
--
-- IDEMPOTENT: yes. Every statement is IF NOT EXISTS, so re-running this file
-- against a database that already has it is a no-op rather than an error.
--
-- ===========================================================================
-- THE SCHEMA ENFORCES THE INVARIANTS. IT DOES NOT TRUST THE APPLICATION.
-- ===========================================================================
-- Every monotone rule below is a CHECK, a UNIQUE, or a trigger. The application
-- enforces the same rules in `src/tx.rs`, and that is deliberate duplication:
-- ADR-0008 §7.1 calls the anti-rollback property "a genuine security control",
-- and a security control with exactly one enforcement point is one bug away
-- from absent.

BEGIN;

-- ---------------------------------------------------------------------------
-- S-26 / S-28: the TwinNet, its log position and its write lease.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS twinnet (
    twinnet_id        TEXT PRIMARY KEY,

    -- ADR-0002 N-3: allocated INSIDE the mutating transaction. Starts at 1
    -- because net_seq == 0 means "no position", and a durable event carrying
    -- one is a defect the client refuses outright.
    next_net_seq      BIGINT NOT NULL DEFAULT 1 CHECK (next_net_seq >= 1),

    -- S-03. ADR-0009 R-6: MUST NOT decrease, in any document, ever.
    trust_epoch       BIGINT NOT NULL DEFAULT 0 CHECK (trust_epoch >= 0),

    -- S-28: the fencing token. "A write presenting a lower one is refused at
    -- commit."
    shard_epoch       BIGINT NOT NULL DEFAULT 1 CHECK (shard_epoch >= 1),

    -- S-06.
    policy_version    BIGINT NOT NULL DEFAULT 0 CHECK (policy_version >= 0),

    -- The lowest net_seq still retained. A cursor below it is
    -- CONTROL.CURSOR_TOO_OLD.
    retained_from     BIGINT NOT NULL DEFAULT 1 CHECK (retained_from >= 1),

    -- S-08: the next free /32 offset inside 100.64.0.0/10.
    next_v4_offset    BIGINT NOT NULL DEFAULT 1 CHECK (next_v4_offset >= 1),

    -- ADR-0002 N-4: the lease holder and its expiry. NULL means unheld.
    lease_holder      TEXT,
    lease_expires_at  TIMESTAMPTZ,

    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Three monotone columns, enforced by the database rather than by review.
-- ADR-0009 R-6/R-7: the high-water record lives OUTSIDE the log's compaction
-- scope, which is why it is a column here and not a derived maximum over
-- `event`.
CREATE OR REPLACE FUNCTION twinnet_monotone() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.trust_epoch < OLD.trust_epoch THEN
        RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: trust_epoch % -> %',
            OLD.trust_epoch, NEW.trust_epoch;
    END IF;
    IF NEW.next_net_seq < OLD.next_net_seq THEN
        RAISE EXCEPTION 'INTERNAL.INVARIANT_VIOLATED: net_seq counter regressed';
    END IF;
    IF NEW.shard_epoch < OLD.shard_epoch THEN
        RAISE EXCEPTION 'CONTROL.WRITE_LEADER_UNAVAILABLE: shard_epoch % -> %',
            OLD.shard_epoch, NEW.shard_epoch;
    END IF;
    IF NEW.policy_version < OLD.policy_version THEN
        RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: policy_version % -> %',
            OLD.policy_version, NEW.policy_version;
    END IF;
    IF NEW.retained_from < OLD.retained_from THEN
        RAISE EXCEPTION 'INTERNAL.INVARIANT_VIOLATED: retention floor moved backwards';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS twinnet_monotone_trg ON twinnet;
CREATE TRIGGER twinnet_monotone_trg
    BEFORE UPDATE ON twinnet
    FOR EACH ROW EXECUTE FUNCTION twinnet_monotone();

-- ---------------------------------------------------------------------------
-- S-02: membership. The control plane is the single authoritative writer.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device (
    twinnet_id           TEXT   NOT NULL REFERENCES twinnet(twinnet_id) ON DELETE CASCADE,

    -- 32 bytes, DERIVED ON-DEVICE. `device_id_echo` is an echo, never an
    -- assignment, so nothing here generates one.
    device_id            BYTEA  NOT NULL CHECK (octet_length(device_id) = 32),
    identity_id          BYTEA  NOT NULL CHECK (octet_length(identity_id) = 32),

    -- The uniqueness key that makes RegisterDevice linearizable on
    -- (twinnet_id, device_pubkey). "Non-linearizable admission => duplicate
    -- devices on retry and two devices at one TwinNet address => blackholed
    -- traffic (R-03)."
    identity_public_key  BYTEA  NOT NULL,

    generation           INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    tk_generation        INTEGER NOT NULL DEFAULT 0 CHECK (tk_generation >= 0),

    label                TEXT   NOT NULL DEFAULT '',
    version              BIGINT NOT NULL DEFAULT 1 CHECK (version >= 1),
    membership_epoch     BIGINT NOT NULL DEFAULT 1 CHECK (membership_epoch >= 1),

    -- S-08. BOTH are NOT NULL: "a Device with one set and not the other is
    -- malformed — that asymmetry is exactly how a v6-aware design degrades into
    -- a v4-only one."
    twinnet_addr_v4      BYTEA  NOT NULL CHECK (octet_length(twinnet_addr_v4) = 4),
    twinnet_addr_v6      BYTEA  NOT NULL CHECK (octet_length(twinnet_addr_v6) = 16),

    encoded              BYTEA  NOT NULL,

    -- ADR-0008 N-7: false -> true only. Enforced below.
    revoked              BOOLEAN NOT NULL DEFAULT FALSE,

    net_seq              BIGINT NOT NULL CHECK (net_seq >= 1),
    created_at_ms        BIGINT NOT NULL,

    PRIMARY KEY (twinnet_id, device_id)
);

-- Linearizable admission, at the database.
CREATE UNIQUE INDEX IF NOT EXISTS device_pubkey_unique
    ON device (twinnet_id, identity_public_key);

-- S-08: an address is allocated once and is immutable. A collision is "refused
-- AT ALLOCATION TIME, never resolved at runtime" — which is what these two
-- indexes make true even if the application forgets to look.
CREATE UNIQUE INDEX IF NOT EXISTS device_addr_v4_unique
    ON device (twinnet_id, twinnet_addr_v4);
CREATE UNIQUE INDEX IF NOT EXISTS device_addr_v6_unique
    ON device (twinnet_id, twinnet_addr_v6);

-- The label becomes a DNS label (ADR-0011 §11.3), so it is unique among live
-- devices. A revoked device keeps its row and releases its name.
CREATE UNIQUE INDEX IF NOT EXISTS device_label_unique
    ON device (twinnet_id, label) WHERE label <> '' AND NOT revoked;

CREATE OR REPLACE FUNCTION device_monotone() RETURNS TRIGGER AS $$
BEGIN
    -- ADR-0008 N-7: "an operation that would shrink the revoked set MUST be
    -- rejected." A mutable revoked flag is "precisely the shape that permits
    -- un-revocation by replaying an older record."
    IF OLD.revoked AND NOT NEW.revoked THEN
        RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: un-revocation is impossible by construction';
    END IF;
    IF NEW.version < OLD.version THEN
        RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: device.version % -> %', OLD.version, NEW.version;
    END IF;
    -- ADR-0007 N-22: both counters are monotone.
    IF NEW.generation < OLD.generation OR NEW.tk_generation < OLD.tk_generation THEN
        RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: identity generation regressed';
    END IF;
    -- ADR-0007 N-2/N-21: a rotation does NOT change device_id, or S-08's
    -- immutable allocation breaks on every rotation.
    IF NEW.device_id <> OLD.device_id THEN
        RAISE EXCEPTION 'AUTH.IDENTITY_MISMATCH: device_id is immutable';
    END IF;
    IF NEW.twinnet_addr_v4 <> OLD.twinnet_addr_v4 OR NEW.twinnet_addr_v6 <> OLD.twinnet_addr_v6 THEN
        RAISE EXCEPTION 'INTERNAL.INVARIANT_VIOLATED: TwinNet addresses are immutable (S-08)';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS device_monotone_trg ON device;
CREATE TRIGGER device_monotone_trg
    BEFORE UPDATE ON device
    FOR EACH ROW EXECUTE FUNCTION device_monotone();

-- ---------------------------------------------------------------------------
-- S-03: the never-shrinking revoked set.
-- ---------------------------------------------------------------------------
-- A separate table, insert-only, with no DELETE grant in 0004. The device row's
-- `revoked` flag is the denormalised view; this is the record.
CREATE TABLE IF NOT EXISTS revocation (
    twinnet_id    TEXT   NOT NULL REFERENCES twinnet(twinnet_id) ON DELETE CASCADE,
    device_id     BYTEA  NOT NULL CHECK (octet_length(device_id) = 32),

    -- Assigned by the shard writer at admission, under its fenced lease. The
    -- Owner authorizes by signing; the writer numbers.
    trust_epoch   BIGINT NOT NULL CHECK (trust_epoch >= 1),
    net_seq       BIGINT NOT NULL CHECK (net_seq >= 1),

    -- The Owner-signed RevocationStatement, VERBATIM. Never re-encoded (W-4).
    statement     BYTEA  NOT NULL,

    admitted_at_ms BIGINT NOT NULL,

    PRIMARY KEY (twinnet_id, device_id)
);

-- One epoch is assigned once. A second row at the same epoch would be a forked
-- revocation history, which E-1 forbids outright.
CREATE UNIQUE INDEX IF NOT EXISTS revocation_epoch_unique
    ON revocation (twinnet_id, trust_epoch);

CREATE OR REPLACE FUNCTION revocation_is_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: the revoked set never shrinks (ADR-0008 N-7)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS revocation_append_only_trg ON revocation;
CREATE TRIGGER revocation_append_only_trg
    BEFORE UPDATE OR DELETE ON revocation
    FOR EACH ROW EXECUTE FUNCTION revocation_is_append_only();

COMMIT;
