package ch.veehait.devicecheck.appattest.receipt

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

interface AppleReceiptExchangeHttpClientAdapter {
    data class Response(val body: ByteArray, val statusCode: Int) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Response

            if (!body.contentEquals(other.body)) return false
            if (statusCode != other.statusCode) return false

            return true
        }

        override fun hashCode(): Int {
            var result = body.contentHashCode()
            result = 31 * result + statusCode
            return result
        }
    }

    fun post(uri: URI, authorizationHeader: Map<String, String>, body: ByteArray): Response
}

internal class SimpleAppleReceiptExchangeHttpClientAdapter : AppleReceiptExchangeHttpClientAdapter {
    private val httpClient = HttpClient.newHttpClient()
    override fun post(
        uri: URI,
        authorizationHeader: Map<String, String>,
        body: ByteArray,
    ): AppleReceiptExchangeHttpClientAdapter.Response {
        val request = HttpRequest.newBuilder()
            .uri(uri)
            .apply { authorizationHeader.forEach { (k, v) -> header(k, v) } }
            .POST(HttpRequest.BodyPublishers.ofByteArray(body))
            .build()

        val httpResponse = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray())
        return AppleReceiptExchangeHttpClientAdapter.Response(httpResponse.body(), httpResponse.statusCode())
    }
}
