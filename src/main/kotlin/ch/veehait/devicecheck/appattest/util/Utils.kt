package ch.veehait.devicecheck.appattest.util

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput
import org.bouncycastle.util.io.pem.PemReader
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

internal object Utils {
    fun readPemX590Certificate(pem: String) =
        readDerX509Certificate(PemReader(pem.byteInputStream().reader()).readPemObject().content)

    fun readDerX509Certificate(der: ByteArray) =
        CertificateFactory.getInstance("X509").generateCertificate(der.inputStream()) as X509Certificate

    fun parseAuthenticatorData(
        authenticatorData: ByteArray,
        cborObjectMapper: ObjectMapper,
    ): AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> {
        val converter = AuthenticatorDataConverter(
            ObjectConverter(ObjectMapper().registerKotlinModule(), cborObjectMapper)
        )
        return converter.convert(authenticatorData)
    }
}
