package org.sd_jwt

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner

/**
 * A generic interface for SD-JWT signers.
 */
interface SdJwtSigner {

    /**
     * Gets the SD-JWT header that is configured with all parameters required for signing and SD-JWT specific parameters.
     *
     * @return the SD-JWT header.
     */
    fun sdJwtHeader(): JWSHeader

    /**
     * Gets the JWS signer used for signing SD-JWTs.
     *
     * @return the JWS signer.
     */
    fun jwsSigner(): JWSSigner
}
