package com.cashpilot.companion

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SecurePendingTransactionStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun enqueue(transaction: NormalizedTransaction) = synchronized(LOCK) {
        val pending = read().toMutableList()
        if (pending.any { it.eventId == transaction.eventId }) return@synchronized
        if (pending.size >= MAX_PENDING) throw IllegalStateException("Pending transaction queue is full")
        pending.add(transaction)
        write(pending)
    }

    fun pending(): List<NormalizedTransaction> = synchronized(LOCK) { read() }

    fun remove(eventId: String) = synchronized(LOCK) {
        val pending = read()
        if (pending.any { it.eventId == eventId }) write(pending.filterNot { it.eventId == eventId })
    }

    fun clear() = synchronized(LOCK) {
        if (!preferences.edit().remove(KEY_IV).remove(KEY_CIPHERTEXT).commit()) {
            throw IllegalStateException("Could not clear pending transaction queue")
        }
    }

    private fun read(): List<NormalizedTransaction> {
        val ivValue = preferences.getString(KEY_IV, null)
        val ciphertextValue = preferences.getString(KEY_CIPHERTEXT, null)
        if (ivValue == null && ciphertextValue == null) return emptyList()
        if (ivValue.isNullOrBlank() || ciphertextValue.isNullOrBlank()) {
            throw IllegalStateException("Pending transaction queue is incomplete")
        }
        val cleartext = try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateKey(),
                GCMParameterSpec(128, Base64.decode(ivValue, Base64.NO_WRAP))
            )
            String(cipher.doFinal(Base64.decode(ciphertextValue, Base64.NO_WRAP)), Charsets.UTF_8)
        } catch (error: Exception) {
            throw IllegalStateException("Pending transaction queue could not be decrypted", error)
        }
        val records = try {
            JSONArray(cleartext)
        } catch (error: Exception) {
            throw IllegalStateException("Pending transaction queue has invalid data", error)
        }
        if (records.length() > MAX_PENDING) throw IllegalStateException("Pending transaction queue exceeds its limit")
        return (0 until records.length()).map { index ->
            val item = records.optJSONObject(index)
                ?: throw IllegalStateException("Pending transaction queue has an invalid record")
            val transaction = NormalizedTransaction(
                eventId = item.optString("eventId", ""),
                direction = item.optString("direction", ""),
                amountMinor = item.optLong("amountMinor", 0L),
                currency = item.optString("currency", ""),
                occurredAt = item.optString("occurredAt", "")
            )
            if (!transaction.eventId.matches(EVENT_ID) ||
                transaction.direction !in setOf("debit", "credit") ||
                transaction.amountMinor !in 1..MAX_AMOUNT_MINOR ||
                transaction.currency != "INR" ||
                transaction.occurredAt.isBlank()
            ) throw IllegalStateException("Pending transaction queue has invalid transaction data")
            transaction
        }
    }

    private fun write(transactions: List<NormalizedTransaction>) {
        if (transactions.isEmpty()) {
            clear()
            return
        }
        val records = JSONArray()
        transactions.forEach { transaction ->
            records.put(
                JSONObject()
                    .put("eventId", transaction.eventId)
                    .put("direction", transaction.direction)
                    .put("amountMinor", transaction.amountMinor)
                    .put("currency", transaction.currency)
                    .put("occurredAt", transaction.occurredAt)
            )
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val ciphertext = cipher.doFinal(records.toString().toByteArray(Charsets.UTF_8))
        val saved = preferences.edit()
            .putString(KEY_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .putString(KEY_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .commit()
        if (!saved) throw IllegalStateException("Could not save pending transaction queue")
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        private val LOCK = Any()
        private val EVENT_ID = Regex("[0-9a-f]{64}")
        private const val PREFERENCES = "secure_pending_transactions"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "cashpilot_pending_queue_aes_gcm"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_IV = "iv"
        private const val KEY_CIPHERTEXT = "ciphertext"
        private const val MAX_PENDING = 1000
        private const val MAX_AMOUNT_MINOR = 1_000_000_000_000L
    }
}
