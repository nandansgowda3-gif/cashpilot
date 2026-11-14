package com.cashpilot.companion

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import java.security.GeneralSecurityException
import java.util.concurrent.Executors

class NotificationCaptureService : NotificationListenerService() {
    private val persistence = Executors.newSingleThreadExecutor()

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val sourcePackage = sbn.packageName ?: return
        if (sourcePackage == packageName) return

        val appLabel = try {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(sourcePackage, 0)).toString()
        } catch (_: Exception) {
            sourcePackage
        }
        val preferences = AppPreferences(this)
        preferences.observeSource(sourcePackage, appLabel)

        if (!preferences.autoImport || !preferences.isSourceEnabled(sourcePackage)) return
        if (SecureTokenStore(this).read() == null) return

        val text = notificationText(sbn.notification) ?: return
        val normalized = NotificationParser.parse(text, sourcePackage, sbn.key, sbn.postTime) ?: return
        persistence.execute {
            try {
                SecurePendingTransactionStore(this).enqueue(normalized)
                preferences.uploadStatus = "A transaction alert was saved securely and is syncing."
                TransactionUploadWorker.enqueue(this)
            } catch (_: IllegalStateException) {
                preferences.uploadStatus = "A transaction alert could not be saved for sync. Check device storage."
            } catch (_: GeneralSecurityException) {
                preferences.uploadStatus = "A transaction alert could not be encrypted for sync."
            }
        }
    }

    private fun notificationText(notification: Notification): String? {
        val extras = notification.extras ?: return null
        val parts = ArrayList<CharSequence>()
        listOf(Notification.EXTRA_TITLE, Notification.EXTRA_TEXT, Notification.EXTRA_BIG_TEXT).forEach { key ->
            extras.getCharSequence(key)?.let(parts::add)
        }
        extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.forEach { parts.add(it) }
        return parts.takeIf { it.isNotEmpty() }?.joinToString(" ")
    }

    override fun onDestroy() {
        persistence.shutdown()
        super.onDestroy()
    }
}