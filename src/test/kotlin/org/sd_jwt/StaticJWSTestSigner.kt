package org.sd_jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL

class StaticJWSTestSigner: StaticJWSSigner {
    private val jwkJSON = """{"kty":"EC","d":"9frWMdpKIDC8YtEcucGoPypR47Hk_at5U87gKA0edEw","use":"sig","crv":"P-256","kid":"00001","x":"GN79E-mOsEGQIlyAznOmLzwic_TxlZfxbD26XTF16CM","y":"prRUQBIIcP9BXixqZnGa0Aed5_d9IgxA2IwbgsAshdI"}"""
    private val jwk = ECKey.parse(jwkJSON)
    val publicJWK: ECKey = jwk.toPublicJWK()
    private val jwsAlgorithm = JWSAlgorithm.ES256
    private val keyId = "00001"

    private val jcaContext = JCAContext()
    override fun getAlgorithm(): JWSAlgorithm {
        return jwsAlgorithm
    }

    override fun getKeyID(): String {
        return keyId
    }

    override fun getJCAContext(): JCAContext {
        return jcaContext
    }

    override fun supportedJWSAlgorithms(): MutableSet<JWSAlgorithm> {
        return mutableSetOf(getAlgorithm())
    }

    override fun sign(header: JWSHeader?, signingInput: ByteArray?): Base64URL {
        return ECDSASigner(jwk).sign(header, signingInput)
    }
}