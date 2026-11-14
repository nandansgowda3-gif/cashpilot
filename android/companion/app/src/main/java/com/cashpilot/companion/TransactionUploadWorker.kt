package com.cashpilot.companion

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.io.IOException
import java.util.concurrent.TimeUnit

class TransactionUploadWorker(context: Context, parameters: WorkerParameters) : Worker(context, parameters) {
    override fun doWork(): Result {
        val preferences = AppPreferences(applicationContext)
        val token = SecureTokenStore(applicationContext).read()
        if (token == null) {
            preferences.uploadStatus = "Pair this phone again to sync queued transaction alerts."
            return Result.failure()
        }

        val queue = SecurePendingTransactionStore(applicationContext)
        val api = ApiClient(preferences.baseUrl)
        while (true) {
            val pending = queue.pending()
            if (pending.isEmpty()) {
                preferences.uploadStatus = "All queued transaction alerts are synced."
                return Result.success()
            }
            for (transaction in pending) {
                try {
                    api.upload(token, transaction)
                } catch (error: ApiHttpException) {
                    if (error.statusCode in 400..499 && error.statusCode !in setOf(408, 425, 429)) {
                        preferences.uploadStatus = "Sync paused. Check the pairing and server URL."
                        return Result.failure()
                    }
                    preferences.uploadStatus = "Waiting to retry transaction alert sync."
                    return Result.retry()
                } catch (error: IOException) {
                    preferences.uploadStatus = "Waiting to retry transaction alert sync."
                    return Result.retry()
                }
                queue.remove(transaction.eventId)
            }
        }
    }

    companion object {
        private const val UNIQUE_WORK_NAME = "cashpilot_transaction_alert_upload"

        fun enqueue(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            val request = OneTimeWorkRequestBuilder<TransactionUploadWorker>()
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 10, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context.applicationContext)
                .enqueueUniqueWork(UNIQUE_WORK_NAME, ExistingWorkPolicy.APPEND_OR_REPLACE, request)
        }
    }
}
