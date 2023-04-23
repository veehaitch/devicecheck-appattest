package ch.veehait.devicecheck.appattest.receipt

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import javax.annotation.processing.Generated

interface AppleReceiptExchangeHttpClientAdapter {
    data class Response(val statusCode: Int, val headers: HttpHeaders, val body: ByteArray) {
        @Generated
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Response

            if (!body.contentEquals(other.body)) return false
            if (statusCode != other.statusCode) return false
            if (headers != other.headers) return false

            return true
        }

        @Generated
        override fun hashCode(): Int {
            var result = body.contentHashCode()
            result = 31 * result + statusCode
            result = 31 * result + headers.hashCode()
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
        return AppleReceiptExchangeHttpClientAdapter.Response(
            statusCode = httpResponse.statusCode(),
            headers = httpResponse.headers(),
            body = httpResponse.body(),
        )
    }
}
