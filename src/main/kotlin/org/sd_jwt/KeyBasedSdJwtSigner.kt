package org.sd_jwt

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.*

/**
 * Data class for setting the SD-JWT header parameters typ and cty.
 * @param type: typ header parameter (example: JOSEObjectType("vc+sd-jwt"))
 * @param cty:  cty header parameter (example: "credential-claims-set+json")
 */
data class SdJwtHeader(val type: JOSEObjectType? = null, val cty: String? = null)


/**
 * A simple key-based implementation of an SD-JWT signer.
 *
 * @param key the private JWK for creating the JWSHeader and the JWSSigner.
 * @param sdJwtHeader set a value for the SD-JWT header parameters 'typ' and 'cty' (optional).
 */
class KeyBasedSdJwtSigner(key: JWK, sdJwtHeader: SdJwtHeader = SdJwtHeader()): SdJwtSigner {
    private val signer: JWSSigner
    private val publicJWK: JWK
    private val header: JWSHeader.Builder

    init {
        when (key.keyType) {
            KeyType.OKP -> {
                signer = Ed25519Signer(key as OctetKeyPair)
                header = JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(key.keyID)
            }

            KeyType.RSA -> {
                signer = RSASSASigner(key as RSAKey)
                header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID)
            }

            KeyType.EC -> {
                signer = ECDSASigner(key as ECKey)
                header = JWSHeader.Builder(signer.supportedECDSAAlgorithm()).keyID(key.keyID)
            }

            else -> {
                throw NotImplementedError("JWK signing algorithm not implemented")
            }
        }
        publicJWK = key.toPublicJWK()

        if (sdJwtHeader.type != null) {
            header.type(sdJwtHeader.type)
        }
        if (sdJwtHeader.cty != null) {
            header.contentType(sdJwtHeader.cty)
        }
    }
    override fun sdJwtHeader(): JWSHeader {
        return header.build()
    }

    override fun jwsSigner(): JWSSigner {
        return signer
    }

    override fun getPublicJWK(): JWK {
        return publicJWK
    }
}
