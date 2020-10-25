package ch.veehait.devicecheck.appattest

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput
import org.apache.commons.codec.binary.Base64
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.util.io.pem.PemReader
import java.security.MessageDigest
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

object Utils {
    internal fun readPemX590Certificate(pem: String) =
        readDerX509Certificate(PemReader(pem.byteInputStream().reader()).readPemObject().content)

    internal fun readDerX509Certificate(der: ByteArray) =
        CertificateFactory.getInstance("X509").generateCertificate(der.inputStream()) as X509Certificate

    internal fun parseAuthenticatorData(
        authenticatorData: ByteArray,
        cborObjectMapper: ObjectMapper,
    ): AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> {
        val converter = AuthenticatorDataConverter(
            ObjectConverter(ObjectMapper().registerKotlinModule(), cborObjectMapper)
        )
        return converter.convert(authenticatorData)
    }
}

object Extensions {

    fun List<X509Certificate>.verifyChain(
        trustAnchor: TrustAnchor,
        date: Date = Date.from(Instant.now()),
    ) {
        val certFactory = CertificateFactory.getInstance("X509")
        val certPath = certFactory.generateCertPath(this)
        val certPathValidator = CertPathValidator.getInstance("PKIX")
        val pkixParameters = PKIXParameters(setOf(trustAnchor)).apply {
            isRevocationEnabled = false
            this.date = date
        }

        certPathValidator.validate(certPath, pkixParameters)
    }

    inline operator fun <reified T : Any> ASN1Sequence.get(index: Int): T = this.getObjectAt(index) as T
    inline fun <reified T : Any> ASN1InputStream.readObjectAs(): T = this.readObject() as T

    fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)
    fun ByteArray.toBase64(): String = Base64.encodeBase64String(this)

    fun ByteArray.fromBase64(): ByteArray = Base64.decodeBase64(this)
    fun String.fromBase64(): ByteArray = Base64.decodeBase64(this)
}
