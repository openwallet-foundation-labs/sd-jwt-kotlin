package org.sd_jwt

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT

/**
 * An SD-JWT verifier that selects the issuer key used for verification based on the iss-claim in the SD-JWT.
 *
 * @param issuerKeys The issuer keys. The keys are matched against the iss claim in the SD-JWT and the values must be encoded JWKs.
 */
class TrustedIssuersSdJwtVerifier(private val issuerKeys: Map<String, String>) : SdJwtVerifier {
    override fun jwsVerifier(jwt: SignedJWT): JWSVerifier {
        val payload = jwt.payload.toJSONObject()
        val issuer = payload["iss"] ?: throw Exception("Could not find issuer in JWT")
        val key = issuerKeys[issuer] ?: throw Exception("Could not find signing key to verify JWT")
        return JWK.parse(key).jwsVerifier()
    }
}