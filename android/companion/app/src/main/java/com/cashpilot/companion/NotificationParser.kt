package com.cashpilot.companion

import java.math.BigDecimal
import java.math.RoundingMode
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Locale

object NotificationParser {
    private const val MAX_AMOUNT_MINOR = 1_000_000_000_000L
    private const val NUMBER = "(?:\\d{1,3}(?:,\\d{2,3})+|\\d+)(?:\\.\\d{1,2})?"
    private val amountPattern = Regex(
        "(?i)(?:₹|INR\\b|Rs\\.?)\\s*($NUMBER)(?![\\d,.])|(?<![\\d,.])($NUMBER)\\s*(?:₹|INR\\b|Rs\\.?(?=\\s|$))"
    )
    private val debitPattern = Regex("\\b(?:debit(?:ed)?|spent|purchase(?:d)?|withdraw(?:n|al)?|paid|sent)\\b", RegexOption.IGNORE_CASE)
    private val creditPattern = Regex("\\b(?:credit(?:ed)?|received|refund(?:ed)?|deposit(?:ed)?)\\b", RegexOption.IGNORE_CASE)
    private val otpPattern = Regex("\\b(?:otp|pin|one[ -]time password|verification code|security code|passcode)\\b", RegexOption.IGNORE_CASE)
    private val uncertainStatusPattern = Regex("\\b(?:failed|failure|declined|reversed|cancelled|canceled|pending|unsuccessful|not completed|unable to|scheduled|authorization|authorized|authorised|attempt(?:ed)?|processing|in progress|credit card)\\b|\\b(?:not(?:\\s+been)?|no|will(?:\\s+be)?)\\s+(?:debited|credited|debit|credit)\\b", RegexOption.IGNORE_CASE)
    private val balanceAmountPrefixPattern = Regex(
        "\\b(?:(?:available|avail|current|avl\\.?|a/c)\\s+)?(?:balance|bal|minimum\\s+due|total\\s+due|credit\\s+limit)\\b[^\\n₹]{0,30}$",
        RegexOption.IGNORE_CASE
    )

    fun parse(text: String, packageName: String, notificationKey: String, postedAtMillis: Long): NormalizedTransaction? {
        if (text.isBlank() || otpPattern.containsMatchIn(text) || uncertainStatusPattern.containsMatchIn(text)) return null

        val actions = (debitPattern.findAll(text).map { Action(it.range.first, it.range.last, "debit") } +
            creditPattern.findAll(text).map { Action(it.range.first, it.range.last, "credit") }).toList()
        if (actions.isEmpty()) return null

        val matches = amountPattern.findAll(text).toList()
        val candidates = matches.mapNotNull { match ->
            val prefix = text.substring(maxOf(0, match.range.first - 80), match.range.first)
            if (balanceAmountPrefixPattern.containsMatchIn(prefix)) return@mapNotNull null

            val distances = actions.map { action -> action to action.distanceTo(match.range.first, match.range.last) }
            val nearestDistance = distances.minOf { it.second }
            if (nearestDistance > 80) return@mapNotNull null
            val nearestDirections = distances.filter { it.second == nearestDistance }.map { it.first.direction }.distinct()
            if (nearestDirections.size != 1) return@mapNotNull null
            match to nearestDirections.single()
        }
        if (candidates.size != 1) return null

        val (match, direction) = candidates.single()
        val groups = match.groupValues
        val rawAmount = groups[1].ifBlank { groups[2] }
        val amountMinor = try {
            BigDecimal(rawAmount.replace(",", ""))
                .movePointRight(2)
                .setScale(0, RoundingMode.UNNECESSARY)
                .longValueExact()
        } catch (_: ArithmeticException) {
            return null
        } catch (_: NumberFormatException) {
            return null
        }
        if (amountMinor !in 1..MAX_AMOUNT_MINOR || postedAtMillis <= 0L) return null

        return NormalizedTransaction(
            eventId = eventId(packageName, notificationKey, postedAtMillis),
            direction = direction,
            amountMinor = amountMinor,
            occurredAt = Instant.ofEpochMilli(postedAtMillis).toString()
        )
    }

    private data class Action(val start: Int, val end: Int, val direction: String) {
        fun distanceTo(amountStart: Int, amountEnd: Int): Int = when {
            end < amountStart -> amountStart - end - 1
            start > amountEnd -> start - amountEnd - 1
            else -> 0
        }
    }

    fun eventId(packageName: String, notificationKey: String, postedAtMillis: Long): String {
        val input = "$packageName\n$notificationKey\n$postedAtMillis"
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(StandardCharsets.UTF_8))
        return digest.joinToString("") { byte -> "%02x".format(Locale.ROOT, byte.toInt() and 0xff) }
    }
}