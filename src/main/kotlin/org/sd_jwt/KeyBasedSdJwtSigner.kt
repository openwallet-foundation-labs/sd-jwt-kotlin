package org.sd_jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.*

/**
 * A simple key-based implementation of an SD-JWT signer.
 *
 * @param key the private JWK for creating the JWSHeader and the JWSSigner.
 */
class KeyBasedSdJwtSigner(private val key: JWK): SdJwtSigner {
    private val signer: JWSSigner
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
    }
    override fun baseHeader(): JWSHeader.Builder {
        return header
    }

    override fun jwsSigner(): JWSSigner {
        return signer
    }
}
