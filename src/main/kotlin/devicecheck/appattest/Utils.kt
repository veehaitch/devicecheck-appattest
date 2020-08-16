package devicecheck.appattest

import org.bouncycastle.util.io.pem.PemReader
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*


internal fun readPemX590Certificate(pem: String) =
    readDerX509Certificate(PemReader(pem.byteInputStream().reader()).readPemObject().content)

internal fun readDerX509Certificate(der: ByteArray) =
    CertificateFactory.getInstance("X509").generateCertificate(der.inputStream()) as X509Certificate

fun ByteArray.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(this)
fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)

fun ByteArray.fromBase64(): ByteArray = Base64.getDecoder().decode(this)
fun String.fromBase64(): ByteArray = this.toByteArray().fromBase64()
