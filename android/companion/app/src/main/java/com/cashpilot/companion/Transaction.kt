package com.cashpilot.companion

data class NormalizedTransaction(
    val eventId: String,
    val direction: String,
    val amountMinor: Long,
    val currency: String = "INR",
    val occurredAt: String
)