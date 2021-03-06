package ch.veehait.devicecheck.appattest.receipt

import ch.veehait.devicecheck.appattest.util.Extensions.fromBase64
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Clock
import java.util.Date

class AppleJwsGeneratorImpl(
    override val teamIdentifier: String,
    override val keyIdentifier: String,
    privateKeyPem: String,
    private val clock: Clock = Clock.systemUTC(),
) : AppleJwsGenerator {
    private fun parsePrivateKey(pem: String): PrivateKey = pem
        .replace(Regex("-----(BEGIN|END) PRIVATE KEY-----"), "")
        .trim()
        .fromBase64()
        .let(::PKCS8EncodedKeySpec)
        .let(KeyFactory.getInstance("EC")::generatePrivate)

    override val privateKey: PrivateKey = parsePrivateKey(privateKeyPem)

    private val jwsEcdsaSigner = ECDSASigner(privateKey, Curve.P_256)

    override fun issueToken(): String {
        val jwsHeader = JWSHeader
            .Builder(JWSAlgorithm.ES256)
            .keyID(keyIdentifier)
            .build()

        val jwsClaims = JWTClaimsSet
            .Builder()
            .issuer(teamIdentifier)
            .issueTime(Date.from(clock.instant()))
            .build()

        val jws = SignedJWT(jwsHeader, jwsClaims).apply {
            sign(jwsEcdsaSigner)
        }

        return jws.serialize()
    }
}
