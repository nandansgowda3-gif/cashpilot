package com.cashpilot.companion

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.provider.Settings
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val background = Executors.newSingleThreadExecutor()
    private lateinit var preferences: AppPreferences
    private lateinit var tokenStore: SecureTokenStore
    private lateinit var baseUrlField: EditText
    private lateinit var pairCodeField: EditText
    private lateinit var deviceNameField: EditText
    private lateinit var autoImportSwitch: Switch
    private lateinit var accessState: TextView
    private lateinit var status: TextView
    private lateinit var sourcesContainer: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        preferences = AppPreferences(this)
        tokenStore = SecureTokenStore(this)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(28))
        }
        val scroll = ScrollView(this).apply { addView(content) }
        setContentView(scroll)

        content.addView(text("CashPilot Companion", 26, true))
        content.addView(text(
            "Imports selected transaction alerts locally. CashPilot never requests SMS permission. " +
                "Notification access must be explicitly enabled in Android Settings; choose only trusted source apps. " +
                "Notification text is inspected only after you select a source and enable auto-import.", 15
        ))
        content.addView(text("Server base URL", 18, true))
        baseUrlField = editField(preferences.baseUrl).also { content.addView(it) }
        content.addView(text("Pair your device", 18, true))
        pairCodeField = editField("").apply { hint = "16-character pairing code"; content.addView(this) }
        deviceNameField = editField(android.os.Build.MODEL.orEmpty().ifBlank { "Android phone" }).apply {
            hint = "Device name"
            content.addView(this)
        }
        content.addView(button("Pair device") { pairDevice() })
        content.addView(button("Disconnect device") { disconnectDevice() })
        content.addView(text("Notification access", 18, true))
        accessState = text("Checking…", 15)
        content.addView(accessState)
        content.addView(button("Notification access settings") {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        })
        content.addView(text("Observed notification sources", 18, true))
        content.addView(text("Only package names and display names are recorded until you enable a source below.", 14))
        sourcesContainer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(sourcesContainer)
        autoImportSwitch = Switch(this).apply {
            text = "Auto-import (off by default)"
            isChecked = preferences.autoImport
            setOnCheckedChangeListener { _, checked ->
                preferences.autoImport = checked
                status.text = if (checked) "Auto-import enabled for selected sources." else "Auto-import is off."
            }
        }
        content.addView(autoImportSwitch)
        content.addView(text("Only clear INR debit/credit alerts are accepted; ambiguous alerts are skipped. Normalized transactions are encrypted locally and retried when connected. No raw notification text is stored or sent.", 14))
        status = text(if (tokenStore.read() == null) "Not paired" else preferences.uploadStatus.ifBlank { "Paired" })
        content.addView(status)
        renderSources()
        updateAccessState()
        if (tokenStore.read() != null) TransactionUploadWorker.enqueue(this)
    }

    override fun onResume() {
        super.onResume()
        if (::accessState.isInitialized) updateAccessState()
        if (::sourcesContainer.isInitialized) renderSources()
        if (::status.isInitialized) {
            status.text = if (tokenStore.read() == null) "Not paired" else preferences.uploadStatus.ifBlank { "Paired" }
        }
    }

    private fun pairDevice() {
        val base = baseUrlField.text.toString().trim()
        val code = pairCodeField.text.toString().trim()
        val name = deviceNameField.text.toString().trim().ifBlank { "Android phone" }
        preferences.baseUrl = base
        status.text = "Pairing…"
        background.execute {
            try {
                val token = ApiClient(base).pair(code, name)
                tokenStore.save(token)
                TransactionUploadWorker.enqueue(this)
                runOnUiThread {
                    pairCodeField.text.clear()
                    status.text = "Paired. The token is protected by Android Keystore."
                }
            } catch (_: Exception) {
                runOnUiThread { status.text = "Pairing failed. Check the URL, code, and network." }
            }
        }
    }

    private fun disconnectDevice() {
        val token = tokenStore.read()
        if (token == null) {
            status.text = "This device is not paired."
            return
        }
        preferences.baseUrl = baseUrlField.text.toString().trim()
        status.text = "Disconnecting…"
        background.execute {
            try {
                ApiClient(preferences.baseUrl).disconnect(token)
                tokenStore.clear()
                SecurePendingTransactionStore(this).clear()
                preferences.autoImport = false
                preferences.uploadStatus = ""
                runOnUiThread {
                    autoImportSwitch.isChecked = false
                    status.text = "Disconnected. The local token was removed."
                }
            } catch (_: Exception) {
                runOnUiThread { status.text = "Disconnect failed. Check the URL and network; the token was kept." }
            }
        }
    }

    private fun renderSources() {
        sourcesContainer.removeAllViews()
        val sources = preferences.sources().toSortedMap()
        if (sources.isEmpty()) {
            sourcesContainer.addView(text("No notification sources observed yet. Allow a source app to post a notification.", 14))
            return
        }
        sources.forEach { (packageName, label) ->
            val checkbox = CheckBox(this).apply {
                text = "$label\n$packageName"
                isChecked = preferences.isSourceEnabled(packageName)
                setOnCheckedChangeListener { _, enabled -> preferences.setSourceEnabled(packageName, enabled) }
            }
            sourcesContainer.addView(checkbox)
        }
    }

    private fun updateAccessState() {
        val enabled = try {
            val listeners = Settings.Secure.getString(contentResolver, "enabled_notification_listeners").orEmpty()
            listeners.split(':').any { it.equals(
                android.content.ComponentName(this, NotificationCaptureService::class.java).flattenToString(), true
            ) }
        } catch (_: Exception) { false }
        accessState.text = if (enabled) "Enabled. Source selection and auto-import are still required." else
            "Not enabled. Explicitly enable CashPilot in Android Settings to observe source app names."
    }

    private fun editField(value: String): EditText = EditText(this).apply {
        setSingleLine(true)
        setText(value)
        layoutParams = matchWidth()
    }

    private fun button(label: String, action: () -> Unit): Button = Button(this).apply {
        text = label
        setOnClickListener { action() }
        layoutParams = matchWidth()
    }

    private fun text(value: String, size: Int = 15, bold: Boolean = false): TextView = TextView(this).apply {
        text = value
        textSize = size.toFloat()
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setPadding(0, dp(8), 0, dp(8))
        layoutParams = matchWidth()
    }

    private fun matchWidth() = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    override fun onDestroy() {
        background.shutdown()
        super.onDestroy()
    }
}