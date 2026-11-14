package com.cashpilot.companion

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationParserTest {
    @Test
    fun parsesOneClearDebitAmountToPaise() {
        val result = NotificationParser.parse("Your account was debited by Rs. 1,234.50", "bank.app", "key-1", 1_700_000_000_000)
        assertNotNull(result)
        assertEquals("debit", result!!.direction)
        assertEquals(123_450L, result.amountMinor)
        assertEquals("INR", result.currency)
        assertTrue(result.eventId.matches(Regex("[0-9a-f]{64}")))
        assertTrue(result.occurredAt.endsWith("Z"))
    }

    @Test
    fun parsesClearCredit() {
        val result = NotificationParser.parse("INR 250 credited to your account", "bank.app", "key-2", 1_700_000_000_000)
        assertEquals("credit", result?.direction)
        assertEquals(25_000L, result?.amountMinor)
    }

    @Test
    fun extractsTransactionAmountAndIgnoresBalanceAmount() {
        val debit = NotificationParser.parse(
            "Your account was debited by Rs. 1,234.50. Available balance is Rs. 5,000.00",
            "bank.app",
            "key-debit-balance",
            1_700_000_000_000
        )
        assertEquals("debit", debit?.direction)
        assertEquals(123_450L, debit?.amountMinor)

        val credit = NotificationParser.parse(
            "INR 250 credited to your account. Avl Bal: INR 800",
            "bank.app",
            "key-credit-balance",
            1_700_000_000_000
        )
        assertEquals("credit", credit?.direction)
        assertEquals(25_000L, credit?.amountMinor)
    }

    @Test
    fun skipsOtpAndBalances() {
        assertNull(NotificationParser.parse("OTP 123456 for debit of Rs 500", "bank.app", "key", 1_700_000_000_000))
        assertNull(NotificationParser.parse("Available balance is INR 500", "bank.app", "key", 1_700_000_000_000))
        assertNull(NotificationParser.parse("Balance is INR 500", "bank.app", "key", 1_700_000_000_000))
        assertNull(NotificationParser.parse("Debit of INR 500 failed", "bank.app", "key", 1_700_000_000_000))
        assertNull(NotificationParser.parse("Your account will be debited INR 500", "bank.app", "key", 1_700_000_000_000))
        assertNull(NotificationParser.parse("INR 500 not debited", "bank.app", "key", 1_700_000_000_000))
        assertNull(NotificationParser.parse("Credit card balance INR 500", "bank.app", "key", 1_700_000_000_000))
    }

    @Test
    fun skipsUnknownAmbiguousAndMultipleAmounts() {
        assertNull(NotificationParser.parse("Transaction successful: INR 500", "bank.app", "key", 1_700_000_000_000))
        assertNull(NotificationParser.parse("Debited INR 500 and credited INR 400", "bank.app", "key", 1_700_000_000_000))
        assertNull(NotificationParser.parse("Debited INR 500; fee INR 5", "bank.app", "key", 1_700_000_000_000))
        assertNull(NotificationParser.parse("Debited 500", "bank.app", "key", 1_700_000_000_000))
    }

    @Test
    fun eventIdIsStableAndSensitiveToNotificationIdentity() {
        val first = NotificationParser.eventId("bank.app", "notification-key", 1000)
        assertEquals(first, NotificationParser.eventId("bank.app", "notification-key", 1000))
        assertTrue(first != NotificationParser.eventId("bank.app", "notification-key-2", 1000))
        assertTrue(first != NotificationParser.eventId("bank.app", "notification-key", 1001))
    }
}