package com.cashpilot.companion

import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

class ApiHttpException(val statusCode: Int) : IOException("Request failed")

class ApiClient(private val baseUrl: String) {
    fun pair(code: String, deviceName: String): String {
        val body = JSONObject().put("code", code.trim().uppercase()).put("deviceName", deviceName.trim())
        val response = request("POST", "/api/mobile/pair", body, null)
        return response.optString("token").takeIf { it.isNotBlank() }
            ?: throw IOException("Invalid pairing response")
    }

    fun upload(token: String, transaction: NormalizedTransaction) {
        val item = JSONObject()
            .put("eventId", transaction.eventId)
            .put("direction", transaction.direction)
            .put("amountMinor", transaction.amountMinor)
            .put("currency", transaction.currency)
            .put("occurredAt", transaction.occurredAt)
        request("POST", "/api/mobile/transactions", JSONObject().put("transactions", JSONArray().put(item)), token)
    }

    fun disconnect(token: String) {
        request("DELETE", "/api/mobile/device", null, token)
    }

    private fun request(method: String, path: String, body: JSONObject?, token: String?): JSONObject {
        val uri = validatedBaseUri()
        val connection = URL(uri.toString().trimEnd('/') + path).openConnection() as HttpURLConnection
        connection.requestMethod = method
        connection.connectTimeout = 15_000
        connection.readTimeout = 15_000
        connection.instanceFollowRedirects = false
        connection.setRequestProperty("Accept", "application/json")
        if (token != null) connection.setRequestProperty("Authorization", "Bearer $token")
        try {
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val status = connection.responseCode
            if (status !in 200..299) throw ApiHttpException(status)
            val response = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            return if (response.isBlank()) JSONObject() else JSONObject(response)
        } finally {
            connection.disconnect()
        }
    }

    private fun validatedBaseUri(): URI {
        val uri = try { URI(baseUrl.trim().trimEnd('/')) } catch (_: Exception) { throw IOException("Invalid server URL") }
        if (uri.host.isNullOrBlank() || uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null ||
            (!uri.rawPath.isNullOrEmpty() && uri.rawPath != "/")) throw IOException("Invalid server URL")
        val secure = uri.scheme.equals("https", ignoreCase = true)
        val localHttp = uri.scheme.equals("http", ignoreCase = true) &&
            uri.host.lowercase() in setOf("localhost", "127.0.0.1", "10.0.2.2", "::1")
        if (!secure && !localHttp) throw IOException("Server URL must use HTTPS")
        return uri
    }
}