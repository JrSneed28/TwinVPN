-- 0002 — the per-TwinNet append-only event log, and the third layer of
-- sole-publisher enforcement.
--
-- Authority: ADR-0002 §11.3 (the relation), N-3 (net_seq inside the mutating
-- transaction), N-5 (independently applicable), N-8 (compaction announced in
-- band), S-4 (publisher_principal checked AT WRITE TIME);
-- docs/protocol.md §7; contracts/docs/contract-matrix.md §4.
--
-- REVERSIBLE: **NO, and deliberately not.**
-- Dropping this table destroys the revocation history. ADR-0009 §11.3 R-7
-- requires a high-water record kept outside the log's compaction scope
-- precisely so that a restore can be checked mechanically, and ADR-0008 §13
-- records that "an operator restoring old state cannot silently rewind
-- devices". A down-migration that recreated an empty log would present a lower
-- net_seq under the same shard_epoch, which devices read as a rebuilt log
-- (R-8) — a full re-read for every device in the fleet, at best. There is no
-- supported rollback; the recovery procedure is the epoch bump in ADR-0008
-- §10.1, not a schema reversal.
--
-- IDEMPOTENT: yes, every statement is IF NOT EXISTS / CREATE OR REPLACE.

BEGIN;

-- ---------------------------------------------------------------------------
-- The log.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event (
    twinnet_id           TEXT   NOT NULL REFERENCES twinnet(twinnet_id) ON DELETE CASCADE,

    -- Dense and monotone per twinnet_id. There is no cross-TwinNet order
    -- (protocol.md §15.2), which is why this is not a global sequence.
    net_seq              BIGINT NOT NULL CHECK (net_seq >= 1),

    -- The stable tag from src/event.rs, identical to the client's
    -- `EventClass::event_type`.
    event_type           TEXT   NOT NULL,

    -- protocol.md §7 / ADR-0002 S-4: "checked against the single-publisher
    -- table AT WRITE TIME".
    publisher_principal  TEXT   NOT NULL,

    -- ADR-0002 N-5: the whole signed document, or a {doc_type, version, digest}
    -- reference sufficient to pull it. NEVER a delta against a predecessor —
    -- which is what makes compaction safe.
    encoded              BYTEA  NOT NULL,

    -- Evidence only. Never a timer input (ADR-0018 CD-1: WallClock is evidence).
    committed_at_ms      BIGINT NOT NULL,

    PRIMARY KEY (twinnet_id, net_seq)
);

CREATE INDEX IF NOT EXISTS event_cursor_scan ON event (twinnet_id, net_seq);

-- ---------------------------------------------------------------------------
-- LAYER 3 of sole-publisher enforcement.
-- ---------------------------------------------------------------------------
-- Layer 1 is construction (`DurableEvent::new` stamps the publisher and there
-- is no setter); layer 2 is `DurableEvent::check_publisher` on every append.
-- This is the layer that holds when a write arrives by any other path — a
-- migration, a repair script, a second service that should not exist.
--
-- protocol.md §7's table names the coordination service as sole publisher of
-- every C2 event type, INCLUDING the rows that transport a statement it cannot
-- forge: RouteAdvertised is PUBLISHED by coordination and AUTHORED by the
-- advertiser, and conflating the two is exactly the capability Rule B removes
-- from the infrastructure.
ALTER TABLE event DROP CONSTRAINT IF EXISTS event_sole_publisher;
ALTER TABLE event ADD CONSTRAINT event_sole_publisher CHECK (
    publisher_principal = 'coordination_service'
);

-- Only DURABLE event types may appear here at all. An ephemeral event that
-- reached the log would be resumable from a cursor and replayable, which N-9
-- forbids — and for PresenceUpdated it would be the permanent movement and
-- IP-address history of the Owner that protocol.md §6.1 calls a privacy defect.
ALTER TABLE event DROP CONSTRAINT IF EXISTS event_is_durable;
ALTER TABLE event ADD CONSTRAINT event_is_durable CHECK (
    event_type IN (
        'device_registered',
        'device_metadata_updated',
        'device_revoked',
        'device_credential_rotated',
        'pairing_requested',
        'pairing_approved',
        'pairing_rejected',
        'pairing_expired',
        'pairing_revoked',
        'peer_added',
        'peer_updated',
        'peer_removed',
        'policy_bundle_updated',
        'route_advertised',
        'route_withdrawn',
        'exit_node_advertised',
        'exit_node_withdrawn',
        'relay_region_policy_changed',
        'relay_epoch_floor_advanced',
        'stream_compacted'
    )
);

-- ---------------------------------------------------------------------------
-- Append-only, at the database.
-- ---------------------------------------------------------------------------
-- DELETE is permitted for exactly one thing: compaction below the retention
-- floor. `event_append_only` therefore blocks UPDATE unconditionally and blocks
-- DELETE of anything at or above the TwinNet's `retained_from`. Compaction
-- raises `retained_from` first, in the same transaction, so a delete that has
-- not been announced cannot happen.
--
-- ADR-0002 N-8: "a compaction MUST be announced in band and in order as
-- StreamCompacted{up_to_net_seq}. SILENT OMISSION IS PROHIBITED." This is what
-- makes the silent version unreachable from SQL as well as from Rust.
CREATE OR REPLACE FUNCTION event_append_only() RETURNS TRIGGER AS $$
DECLARE
    floor_seq BIGINT;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'INTERNAL.INVARIANT_VIOLATED: the event log is append-only';
    END IF;
    SELECT retained_from INTO floor_seq FROM twinnet WHERE twinnet_id = OLD.twinnet_id;
    IF floor_seq IS NULL OR OLD.net_seq >= floor_seq THEN
        RAISE EXCEPTION
            'CONTROL.STREAM_COMPACTED: net_seq % is at or above the retention floor %; raise it first',
            OLD.net_seq, floor_seq;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS event_append_only_trg ON event;
CREATE TRIGGER event_append_only_trg
    BEFORE UPDATE OR DELETE ON event
    FOR EACH ROW EXECUTE FUNCTION event_append_only();

-- ---------------------------------------------------------------------------
-- Density.
-- ---------------------------------------------------------------------------
-- "net_seq is DENSE and monotone per twinnet_id" (ADR-0002 §11.3). A gap that
-- was not announced is indistinguishable, at the device, from a dropped event —
-- and the device's only correct response to an unexplained gap is to distrust
-- the stream. So a non-contiguous append is refused here.
CREATE OR REPLACE FUNCTION event_is_dense() RETURNS TRIGGER AS $$
DECLARE
    prev BIGINT;
    floor_seq BIGINT;
BEGIN
    SELECT MAX(net_seq) INTO prev FROM event WHERE twinnet_id = NEW.twinnet_id;
    SELECT retained_from INTO floor_seq FROM twinnet WHERE twinnet_id = NEW.twinnet_id;
    IF prev IS NULL THEN
        -- The first retained event may sit anywhere at or above the floor: a
        -- compacted log legitimately starts above 1.
        IF NEW.net_seq < COALESCE(floor_seq, 1) THEN
            RAISE EXCEPTION 'INTERNAL.INVARIANT_VIOLATED: append below the retention floor';
        END IF;
    ELSIF NEW.net_seq <> prev + 1 THEN
        RAISE EXCEPTION
            'INTERNAL.INVARIANT_VIOLATED: net_seq must be dense; expected %, got %',
            prev + 1, NEW.net_seq;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS event_is_dense_trg ON event;
CREATE TRIGGER event_is_dense_trg
    BEFORE INSERT ON event
    FOR EACH ROW EXECUTE FUNCTION event_is_dense();

COMMIT;
