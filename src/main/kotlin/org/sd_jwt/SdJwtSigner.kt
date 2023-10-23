package org.sd_jwt

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner

/**
 * A generic interface for SD-JWT signers.
 */
interface SdJwtSigner {

    /**
     * Gets the base header builder of the JWS that is already preconfigured with parameters required for signing
     * such as the algorithm.
     *
     * @return the base header builder.
     */
    fun baseHeader(): JWSHeader.Builder

    /**
     * Gets the JWS signer used for signing SD-JWTs.
     *
     * @return the JWS signer.
     */
    fun jwsSigner(): JWSSigner
}
