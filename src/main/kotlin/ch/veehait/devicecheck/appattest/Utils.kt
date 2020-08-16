package ch.veehait.devicecheck.appattest

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.io.pem.PemReader
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Date

internal fun readPemX590Certificate(pem: String) =
    readDerX509Certificate(PemReader(pem.byteInputStream().reader()).readPemObject().content)

internal fun readDerX509Certificate(der: ByteArray) =
    CertificateFactory.getInstance("X509").generateCertificate(der.inputStream()) as X509Certificate

internal fun verifyCertificateChain(
    certs: List<X509Certificate>,
    rootCaCertificate: X509Certificate,
    date: Date = Date.from(Instant.now())
) {
    val certFactory = CertificateFactory.getInstance("X509")
    val certPath = certFactory.generateCertPath(certs)

    val certPathValidator = CertPathValidator.getInstance("PKIX")
    val trustAnchor = TrustAnchor(rootCaCertificate, null)
    val pkixParameters = PKIXParameters(setOf(trustAnchor)).apply {
        isRevocationEnabled = false
        this.date = date
    }

    certPathValidator.validate(certPath, pkixParameters)
}

fun readX509PublicKey(encoded: ByteArray): PublicKey {
    val factory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
    return factory.generatePublic(X509EncodedKeySpec(encoded))
}

fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)
fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)

fun ByteArray.fromBase64(): ByteArray = Base64.getDecoder().decode(this)
fun String.fromBase64(): ByteArray = this.toByteArray().fromBase64()
