-- 0003 — pairings (S-04), warehoused signed documents (S-06/S-07/S-32/S-33),
-- advertisements (S-16), the relay-token issuance record (S-30), and the
-- idempotency dedup log (ADR-0008 N-5).
--
-- Authority: docs/architecture.md §5; ADR-0007 N-17; ADR-0008 N-1/N-2/N-5;
-- ADR-0009 §11.3 R-2..R-7; ownership.md §8 W-3 (S-09 is relay-directory's; only
-- S-30 is here); contracts/registry/limits.json.
--
-- REVERSIBLE: partially, and the split matters.
--   `pairing`, `state_document`, `route_set`, `exit_offer`, `relay_token`
--   can be dropped and rebuilt from the log, because ADR-0002 N-5 makes every
--   durable event independently applicable — that is exactly what "a device can
--   reach a correct state using pull alone" means, applied to the server.
--   `idempotency` CANNOT: it holds recorded ceremony outcomes that exist
--   nowhere else, and losing one turns a client's retry into a re-executed
--   ceremony. Dropping it is a data loss with a named consequence, not a
--   schema rollback.
--
-- IDEMPOTENT: yes.

BEGIN;

-- ---------------------------------------------------------------------------
-- S-04: the registered half of a Pairing. Each device owns its own TrustedPeer
-- half, which is LOCAL and has no row here — a control-plane row for it would
-- be the remote authority over trust that protocol.md §7 warns about.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pairing (
    twinnet_id       TEXT   NOT NULL REFERENCES twinnet(twinnet_id) ON DELETE CASCADE,

    -- limits.json identifiers.pairing_id_bytes. COMPUTED BY THE JOINING DEVICE:
    -- "a server-minted value would … let the rendezvous correlate a handle to a
    -- secret it must never see."
    pairing_id       BYTEA  NOT NULL CHECK (octet_length(pairing_id) = 16),

    state            TEXT   NOT NULL CHECK (state IN
                        ('pending','completed','rejected','cancelled','expired','revoked')),
    version          BIGINT NOT NULL DEFAULT 1 CHECK (version >= 1),

    -- ADR-0007 N-17: 120 s, enforced independently by both devices AND the
    -- rendezvous AND here.
    expires_at_ms    BIGINT NOT NULL,

    initiator        BYTEA  NOT NULL CHECK (octet_length(initiator) = 32),

    -- The RECORDED outcome. This is what a replay returns, and returning
    -- anything else is what produces asymmetric trust.
    outcome          BYTEA,

    -- limits.json pairing.max_failed_runs.
    failed_attempts  INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),

    PRIMARY KEY (twinnet_id, pairing_id)
);

-- A pairing_id is SINGLE-USE. Once terminal it never returns to pending, and a
-- completed one never loses or changes its recorded outcome: "reissuing it would
-- reset the 5-attempt budget", and rewriting the outcome is the asymmetric-trust
-- bug arriving through the storage layer.
CREATE OR REPLACE FUNCTION pairing_is_single_use() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.state <> 'pending' THEN
        IF NEW.state <> OLD.state THEN
            RAISE EXCEPTION
                'AUTH.PAIRING_NOT_AUTHORIZED: pairing_id is single-use; % is terminal', OLD.state;
        END IF;
        IF OLD.outcome IS NOT NULL AND NEW.outcome IS DISTINCT FROM OLD.outcome THEN
            RAISE EXCEPTION
                'AUTH.TRUST_HISTORY_FORKED: a recorded pairing outcome is immutable';
        END IF;
    END IF;
    IF NEW.version < OLD.version THEN
        RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: pairing.version % -> %', OLD.version, NEW.version;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS pairing_single_use_trg ON pairing;
CREATE TRIGGER pairing_single_use_trg
    BEFORE UPDATE ON pairing
    FOR EACH ROW EXECUTE FUNCTION pairing_is_single_use();

-- ---------------------------------------------------------------------------
-- The warehoused signed documents. ADR-0009 §11.3 R-2..R-7.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS state_document (
    twinnet_id      TEXT   NOT NULL REFERENCES twinnet(twinnet_id) ON DELETE CASCADE,

    -- policy.proto's StateDocumentType, 1..7. Identical to the client's
    -- `state::DocumentType`, because a server and a client that disagreed about
    -- which number means POLICY_BUNDLE would warehouse a policy under the relay
    -- map's high-water mark.
    doc_type        INTEGER NOT NULL CHECK (doc_type BETWEEN 1 AND 7),

    -- R-2: accept iff strictly greater. R-5: a lower version is a rollback.
    version         BIGINT NOT NULL CHECK (version >= 1),

    -- R-3/R-4: equal version + equal digest is a no-op; equal version +
    -- different digest is a FORK and a security event.
    content_digest  BYTEA  NOT NULL CHECK (octet_length(content_digest) = 32),

    -- The Owner-signed octets, VERBATIM. This service did not author them and
    -- must never re-encode them (W-4, and Auth.signed_payload's own rule).
    octets          BYTEA  NOT NULL,

    net_seq         BIGINT NOT NULL CHECK (net_seq >= 1),
    trust_epoch     BIGINT NOT NULL CHECK (trust_epoch >= 0),
    issued_at_ms    BIGINT NOT NULL,

    PRIMARY KEY (twinnet_id, doc_type)
);

-- R-7: the high-water record lives OUTSIDE the log's compaction scope, "so that
-- the §10.2 restore procedure is mechanically checkable". This table is never
-- compacted, and the trigger below is the mechanical check.
CREATE OR REPLACE FUNCTION state_document_monotone() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.version < OLD.version THEN
        RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: doc_type % version % -> %',
            OLD.doc_type, OLD.version, NEW.version;
    END IF;
    IF NEW.version = OLD.version AND NEW.content_digest <> OLD.content_digest THEN
        RAISE EXCEPTION 'AUTH.TRUST_HISTORY_FORKED: doc_type % has two contents at version %',
            OLD.doc_type, OLD.version;
    END IF;
    IF NEW.trust_epoch < OLD.trust_epoch THEN
        RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: trust_epoch % -> %',
            OLD.trust_epoch, NEW.trust_epoch;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS state_document_monotone_trg ON state_document;
CREATE TRIGGER state_document_monotone_trg
    BEFORE UPDATE ON state_document
    FOR EACH ROW EXECUTE FUNCTION state_document_monotone();

-- ---------------------------------------------------------------------------
-- S-16 and the exit-node offers: the WHOLE desired set, per advertiser, under a
-- monotone epoch. Never a delta — a reused epoch is "a delta in disguise".
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS route_set (
    twinnet_id  TEXT   NOT NULL REFERENCES twinnet(twinnet_id) ON DELETE CASCADE,
    advertiser  BYTEA  NOT NULL CHECK (octet_length(advertiser) = 32),
    epoch       BIGINT NOT NULL CHECK (epoch >= 1),
    -- Empty means "withdraw everything", carried by a HIGHER epoch so it cannot
    -- be reordered ahead of the advertisement it withdraws.
    octets      BYTEA  NOT NULL,
    PRIMARY KEY (twinnet_id, advertiser)
);

CREATE TABLE IF NOT EXISTS exit_offer (
    twinnet_id  TEXT   NOT NULL REFERENCES twinnet(twinnet_id) ON DELETE CASCADE,
    offerer     BYTEA  NOT NULL CHECK (octet_length(offerer) = 32),
    epoch       BIGINT NOT NULL CHECK (epoch >= 1),
    octets      BYTEA  NOT NULL,
    PRIMARY KEY (twinnet_id, offerer)
);

CREATE OR REPLACE FUNCTION advertisement_epoch_advances() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.epoch <= OLD.epoch THEN
        RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: advertisement epoch % -> % must strictly advance',
            OLD.epoch, NEW.epoch;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS route_set_epoch_trg ON route_set;
CREATE TRIGGER route_set_epoch_trg
    BEFORE UPDATE ON route_set
    FOR EACH ROW EXECUTE FUNCTION advertisement_epoch_advances();

DROP TRIGGER IF EXISTS exit_offer_epoch_trg ON exit_offer;
CREATE TRIGGER exit_offer_epoch_trg
    BEFORE UPDATE ON exit_offer
    FOR EACH ROW EXECUTE FUNCTION advertisement_epoch_advances();

-- ---------------------------------------------------------------------------
-- S-30 ONLY. S-09 — the relay fleet registry AND its ranking — belongs to
-- relay-directory and lives in `twinvpn_relay_directory`
-- (ownership.md §8 W-3, infra/postgres/initdb/10-databases.sh). There is
-- deliberately no `relay` table in this database.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS relay_token (
    twinnet_id    TEXT   NOT NULL REFERENCES twinnet(twinnet_id) ON DELETE CASCADE,
    device_id     BYTEA  NOT NULL CHECK (octet_length(device_id) = 32),
    -- MONOTONE. "A token whose epoch is below the device's known floor MUST NOT
    -- be used."
    epoch         BIGINT NOT NULL CHECK (epoch >= 1),
    octets        BYTEA  NOT NULL,
    -- limits.json relay.token_lifetime_ms from issuance.
    not_after_ms  BIGINT NOT NULL,
    PRIMARY KEY (twinnet_id, device_id)
);

CREATE OR REPLACE FUNCTION relay_token_epoch_advances() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.epoch <= OLD.epoch THEN
        RAISE EXCEPTION 'AUTH.TRUST_EPOCH_ROLLBACK: relay token epoch % -> %', OLD.epoch, NEW.epoch;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS relay_token_epoch_trg ON relay_token;
CREATE TRIGGER relay_token_epoch_trg
    BEFORE UPDATE ON relay_token
    FOR EACH ROW EXECUTE FUNCTION relay_token_epoch_advances();

-- ---------------------------------------------------------------------------
-- ADR-0008 N-5: (device_id, idempotency_key) -> (outcome, response), durable,
-- for the dedup window.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS idempotency (
    twinnet_id            TEXT   NOT NULL REFERENCES twinnet(twinnet_id) ON DELETE CASCADE,

    -- N-4: scoped to the authenticated DeviceIdentity, so one device cannot
    -- replay another's ceremony by guessing its key.
    device_id             BYTEA  NOT NULL CHECK (octet_length(device_id) = 32),

    -- limits.json identifiers.idempotency_key_{min,max}_bytes: >= 128 bits.
    idempotency_key       BYTEA  NOT NULL
                            CHECK (octet_length(idempotency_key) BETWEEN 16 AND 64),

    command               TEXT   NOT NULL,

    -- The REPLAY form of the response, stored so a duplicate is answered with
    -- these octets literally verbatim — no decode, no re-encode.
    response              BYTEA  NOT NULL,

    committed_at_net_seq  BIGINT NOT NULL,
    stored_at_ms          BIGINT NOT NULL,

    PRIMARY KEY (twinnet_id, device_id, idempotency_key)
);

-- The retention sweep. limits.json control_plane.idempotency_dedup_window_ms is
-- 24 h; N-6 closes the expiry cliff with the version precondition, not with a
-- longer window, so deleting an expired record is safe and is what bounds the
-- table (ADR-0008 §14 revisit condition 3: 10 MB per TwinNet).
CREATE INDEX IF NOT EXISTS idempotency_expiry ON idempotency (stored_at_ms);

-- A recorded outcome is IMMUTABLE. Overwriting one is how a replay comes to
-- return a different answer from the one it was promised.
CREATE OR REPLACE FUNCTION idempotency_is_immutable() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'AUTH.TRUST_HISTORY_FORKED: a recorded ceremony outcome is immutable (ADR-0008 N-5)';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS idempotency_immutable_trg ON idempotency;
CREATE TRIGGER idempotency_immutable_trg
    BEFORE UPDATE ON idempotency
    FOR EACH ROW EXECUTE FUNCTION idempotency_is_immutable();

COMMIT;
