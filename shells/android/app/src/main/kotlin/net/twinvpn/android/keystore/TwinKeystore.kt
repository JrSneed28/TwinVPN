package net.twinvpn.android.keystore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore: CB-5 identity operations and CB-7 Tier-1 storage.
 *
 * Authority: ADR-0020 §11's Android rows (EC P-256, `setIsStrongBoxBacked(true)`
 * falling back to the TEE falling back to software keymaster;
 * `setUserAuthenticationRequired(false)` **and**
 * `setUnlockedDeviceRequired(false)` with the key and the vault in
 * **credential-encrypted** storage; SEK as a Keystore AES-256-GCM key at the
 * same `SecurityLevel` with `setRandomizedEncryptionRequired(true)`), **ST-7**;
 * ADR-0018 CB-5, **CB-6a**, CB-7, §11.16 (c) and (l); ADR-0007 N-5, N-6;
 * ADR-0022 **LC-15**.
 *
 * # ST-7, and why the key is *not* unlock-bound
 *
 * ADR-0007 §7.3's Android row originally specified
 * `setUnlockedDeviceRequired(true)`. **ADR-0020 ST-7 corrects it**: that is
 * functionally wrong for a background VPN, because a rekey while the screen is
 * off would fail. The Android equivalent of `AfterFirstUnlock` is
 * *credential-encrypted storage with no user-authentication requirement*, and
 * that is what is used here. The residual is stated rather than hidden: the
 * vault is unreadable before the **first** unlock after a reboot, so an
 * always-on VPN start at boot fails closed and named until then (LC-15), and
 * ADR-0020 §13 records it as an availability gap rather than a leak.
 *
 * # CB-6a: the platform performs the record AEAD
 *
 * `setRandomizedEncryptionRequired(true)` on an AES-256-GCM Keystore key means
 * the AEAD happens **inside Keystore** and the key is never materialised in this
 * process or in the core's. That is what makes Android one of the **two of ten**
 * targets in ADR-0020's survey, and why `record_aead_custody` reports
 * `PlatformPerformed`.
 *
 * # I4, at the API
 *
 * There is no method here that returns private key material and no parameter
 * that accepts any. The identity key is generated with
 * `setUserAuthenticationRequired(false)` and is **non-exportable by
 * construction** — `KeyStore.PrivateKeyEntry.privateKey` on a Keystore-resident
 * key is a handle, not a scalar, and `getEncoded()` on it returns `null`.
 *
 * # Never logged
 *
 * §6 rule 11. Nothing in this file logs a key, an alias's contents, a plaintext
 * item, or an exception message — the Rust side maps the exception **class
 * name** and never reads the message, precisely because a Keystore message can
 * quote an alias.
 */
internal class TwinKeystore(context: Context) {

    private companion object {
        const val PROVIDER = "AndroidKeyStore"

        /** The device identity key (IK). ES256, ADR-0007. */
        const val ALIAS_IDENTITY = "twinvpn.identity"

        /** The Tier-1 wrapping key. AES-256-GCM, `setRandomizedEncryptionRequired`. */
        const val ALIAS_ITEMS = "twinvpn.items"

        const val GCM_TAG_BITS = 128

        /** `KeyProperties.SECURITY_LEVEL_*`, as the bridge encodes them. */
        const val LEVEL_STRONGBOX = 0
        const val LEVEL_TEE = 1
        const val LEVEL_SOFTWARE = 2
        const val LEVEL_ABSENT = 3

        /** The key tags `identitySign` takes. Mirrors `IdentityKeyRef`. */
        const val KEY_IDENTITY = 0
    }

    /**
     * Tier-1 ciphertext lives beside the vault, in **credential-encrypted** app
     * storage, mode 0700 by the platform's own app-UID isolation.
     *
     * Whole-blob per item, which is the shape CB-7 names: *"whole-blob atomic
     * replacement, which is the shape Keychain / Keystore / DPAPI / libsecret
     * actually have"*. The record envelope, namespaces, schema, migration,
     * monotone rejection and the recovery ladder are **all core-side**.
     */
    private val itemsDir = File(context.filesDir, "tier1").apply { mkdirs() }

    private val store: KeyStore? = runCatching {
        KeyStore.getInstance(PROVIDER).apply { load(null) }
    }.getOrNull()

    // -----------------------------------------------------------------------
    // Identity (CB-5)
    // -----------------------------------------------------------------------

    /**
     * The `SecurityLevel` the identity key actually reached.
     *
     * §11.16 (l): reported **truthfully**, and a `false` is a fact to record
     * rather than a reason to refuse. `LEVEL_ABSENT` where Keystore could not be
     * opened at all — the Rust side then reports `hardware_backed: false` and
     * refuses every operation instead of substituting a file-backed signer.
     */
    fun securityLevel(): Int {
        val entry = identityEntry() ?: return LEVEL_ABSENT
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            // Below API 31 there is no `KeyInfo.getSecurityLevel()`. The
            // pre-31 answer is `isInsideSecureHardware`, which distinguishes
            // hardware from software but NOT StrongBox from the TEE — so the
            // honest report is the TEE, never StrongBox. Claiming the stronger
            // level from a weaker signal is the substitution §11.16 (l) forbids.
            return if (isInsideSecureHardwareLegacy(entry)) LEVEL_TEE else LEVEL_SOFTWARE
        }
        return securityLevelModern(entry)
    }

    /** `device_id ‖ identity_id ‖ generation (u32 BE) ‖ spki`. */
    fun identityPublic(): ByteArray? {
        val certificate = store?.getCertificate(ALIAS_IDENTITY) ?: return null
        val spki = certificate.publicKey.encoded ?: return null
        // `device_id` and `identity_id` are SHA-256 digests the CORE derives
        // (ADR-0007). They are read back from the vault rather than computed
        // here: computing them would put an identity derivation in a shell.
        val device = readRaw("device_id") ?: return null
        val identity = readRaw("identity_id") ?: return null
        val generation = readRaw("identity_generation") ?: byteArrayOf(0, 0, 0, 0)
        return device + identity + generation + spki
    }

    /**
     * Signs inside the element. ES256, never exported (§11.16 (c)).
     *
     * `keyTag` names *which* key — it is `IdentityKeyRef`'s discriminant, not a
     * domain fact — and an unknown tag is refused rather than mapped onto the
     * identity key, which would sign with the wrong one.
     */
    fun sign(keyTag: Int, @Suppress("UNUSED_PARAMETER") generation: Int, message: ByteArray): ByteArray? {
        if (keyTag != KEY_IDENTITY) return null
        val entry = identityEntry() ?: return null
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(entry.privateKey as PrivateKey)
        signature.update(message)
        return signature.sign()
    }

    /**
     * The Android Key Attestation chain, DER-concatenated, or `null`.
     *
     * `null` is ADR-0020's `HARDWARE_UNATTESTED` — *"some Android OEM builds"* —
     * and ADR-0007 N-6 says a peer MUST NOT treat hardware backing as evidence
     * without it. The Rust side reports the format tag only alongside a chain,
     * so the two can never disagree.
     */
    fun attestation(): ByteArray? {
        val chain = store?.getCertificateChain(ALIAS_IDENTITY) ?: return null
        if (chain.isEmpty()) return null
        return chain.fold(ByteArray(0)) { acc, cert -> acc + cert.encoded }
    }

    // -----------------------------------------------------------------------
    // Tier 1 (CB-7, CB-6a)
    // -----------------------------------------------------------------------

    /** Reads an item. `null` is **absent**, a normal first-run state. */
    fun read(key: String): ByteArray? {
        val file = itemFile(key)
        if (!file.exists()) return null
        val blob = file.readBytes()
        if (blob.size <= 12) return null
        val iv = blob.copyOfRange(0, 12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, itemKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(blob, 12, blob.size - 12)
    }

    /**
     * Writes an item **atomically**: a temporary file plus a rename.
     *
     * A torn write of the SEK would make the whole vault unreadable, and
     * ADR-0020's recovery ladder cannot recover a key it never received.
     */
    fun write(key: String, value: ByteArray) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // No IV is supplied. `setRandomizedEncryptionRequired(true)` makes
        // Keystore generate one and REFUSE a caller-supplied one, which is what
        // stops an IV being reused across two writes of the same item.
        cipher.init(Cipher.ENCRYPT_MODE, itemKey())
        val blob = cipher.iv + cipher.doFinal(value)
        val target = itemFile(key)
        val temporary = File(target.parentFile, "${target.name}.tmp")
        temporary.writeBytes(blob)
        if (!temporary.renameTo(target)) {
            temporary.delete()
            throw IllegalStateException("atomic replace failed")
        }
    }

    /** Deletes an item. Idempotent. */
    fun delete(key: String) {
        itemFile(key).delete()
    }

    // -----------------------------------------------------------------------
    // Key material
    // -----------------------------------------------------------------------

    private fun identityEntry(): KeyStore.PrivateKeyEntry? {
        val existing = runCatching { store?.getEntry(ALIAS_IDENTITY, null) }.getOrNull()
        if (existing is KeyStore.PrivateKeyEntry) return existing
        generateIdentity()
        return runCatching { store?.getEntry(ALIAS_IDENTITY, null) }
            .getOrNull() as? KeyStore.PrivateKeyEntry
    }

    /**
     * ADR-0020 §11's Android row, verbatim: EC P-256, StrongBox where available
     * falling back to the TEE, with an attestation challenge.
     */
    private fun generateIdentity() {
        val generator = java.security.KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            PROVIDER,
        )
        val spec = KeyGenParameterSpec.Builder(
            ALIAS_IDENTITY,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            // ST-7: NOT unlock-bound and NOT user-auth bound. A rekey with the
            // screen off must work.
            .setUserAuthenticationRequired(false)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setUnlockedDeviceRequired(false)
                    setIsStrongBoxBacked(true)
                }
                // The challenge is the CORE's nonce, read back from Tier 1. A
                // challenge invented here would attest to a value no verifier
                // asked for.
                readRaw("attestation_challenge")?.let { setAttestationChallenge(it) }
            }
            .build()
        runCatching {
            generator.initialize(spec)
            generator.generateKeyPair()
        }.onFailure {
            // ADR-0020's ladder: StrongBox → TEE. The FALL-BACK IS REPORTED via
            // `securityLevel()`, which reads what was actually reached rather
            // than what was asked for.
            val fallback = KeyGenParameterSpec.Builder(
                ALIAS_IDENTITY,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build()
            generator.initialize(fallback)
            generator.generateKeyPair()
        }
    }

    /** The AES-256-GCM key CB-6a's mandatory platform AEAD runs on. */
    private fun itemKey(): SecretKey {
        (store?.getEntry(ALIAS_ITEMS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            ALIAS_ITEMS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            // CB-6a. Keystore generates the IV and refuses a caller-supplied
            // one, which is the property that makes reuse unrepresentable.
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setUnlockedDeviceRequired(false)
                    setIsStrongBoxBacked(true)
                }
            }
            .build()
        return runCatching {
            generator.init(spec)
            generator.generateKey()
        }.getOrElse {
            val fallback = KeyGenParameterSpec.Builder(
                ALIAS_ITEMS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .build()
            generator.init(fallback)
            generator.generateKey()
        }
    }

    private fun itemFile(key: String) = File(itemsDir, key)

    private fun readRaw(key: String): ByteArray? = runCatching { read(key) }.getOrNull()

    private fun isInsideSecureHardwareLegacy(entry: KeyStore.PrivateKeyEntry): Boolean =
        runCatching {
            val factory = java.security.KeyFactory.getInstance(entry.privateKey.algorithm, PROVIDER)
            @Suppress("DEPRECATION")
            factory.getKeySpec(entry.privateKey, android.security.keystore.KeyInfo::class.java)
                .isInsideSecureHardware
        }.getOrDefault(false)

    private fun securityLevelModern(entry: KeyStore.PrivateKeyEntry): Int = runCatching {
        val factory = java.security.KeyFactory.getInstance(entry.privateKey.algorithm, PROVIDER)
        val info = factory.getKeySpec(entry.privateKey, android.security.keystore.KeyInfo::class.java)
        when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> LEVEL_STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> LEVEL_TEE
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> LEVEL_SOFTWARE
            // `SECURITY_LEVEL_UNKNOWN` and `_UNKNOWN_SECURE` both exist. Neither
            // is claimed as hardware: an unproven backing reported as proven is
            // the one direction §11.16 (l) forbids.
            else -> LEVEL_SOFTWARE
        }
    }.getOrDefault(LEVEL_ABSENT)
}
