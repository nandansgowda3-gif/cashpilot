package com.cashpilot.companion

import android.content.Context
import org.json.JSONObject

class AppPreferences(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences("companion_settings", Context.MODE_PRIVATE)

    var baseUrl: String
        get() = preferences.getString(KEY_BASE_URL, DEFAULT_BASE_URL) ?: DEFAULT_BASE_URL
        set(value) { preferences.edit().putString(KEY_BASE_URL, value.trim()).apply() }

    var autoImport: Boolean
        get() = preferences.getBoolean(KEY_AUTO_IMPORT, false)
        set(value) { preferences.edit().putBoolean(KEY_AUTO_IMPORT, value).apply() }

    var uploadStatus: String
        get() = preferences.getString(KEY_UPLOAD_STATUS, "") ?: ""
        set(value) { preferences.edit().putString(KEY_UPLOAD_STATUS, value).apply() }

    fun sources(): Map<String, String> {
        val json = try { JSONObject(preferences.getString(KEY_SOURCES, "{}") ?: "{}") } catch (_: Exception) { JSONObject() }
        return json.keys().asSequence().mapNotNull { packageName ->
            val label = json.optString(packageName, "")
            if (packageName.isNotBlank()) packageName to label.ifBlank { packageName } else null
        }.toMap()
    }

    fun observeSource(packageName: String, displayName: String) {
        if (packageName.isBlank()) return
        val json = try { JSONObject(preferences.getString(KEY_SOURCES, "{}") ?: "{}") } catch (_: Exception) { JSONObject() }
        json.put(packageName, displayName.ifBlank { packageName })
        preferences.edit().putString(KEY_SOURCES, json.toString()).apply()
    }

    fun isSourceEnabled(packageName: String): Boolean = enabledSources().contains(packageName)

    fun setSourceEnabled(packageName: String, enabled: Boolean) {
        val values = enabledSources().toMutableSet()
        if (enabled) values.add(packageName) else values.remove(packageName)
        preferences.edit().putStringSet(KEY_ENABLED_SOURCES, values).apply()
    }

    private fun enabledSources(): Set<String> = preferences.getStringSet(KEY_ENABLED_SOURCES, emptySet())?.toSet() ?: emptySet()

    companion object {
        const val DEFAULT_BASE_URL = "https://cashpilot-gs-e14e.vercel.app"
        private const val KEY_BASE_URL = "base_url"
        private const val KEY_AUTO_IMPORT = "auto_import"
        private const val KEY_UPLOAD_STATUS = "upload_status"
        private const val KEY_SOURCES = "observed_sources"
        private const val KEY_ENABLED_SOURCES = "enabled_sources"
    }
}