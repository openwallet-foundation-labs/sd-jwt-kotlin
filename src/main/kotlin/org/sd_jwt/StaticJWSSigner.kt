package org.sd_jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner

/**
 * A generic interface for JWS signers which are preconfigured with the algorithm and key ID to be used for signing.
 */
interface StaticJWSSigner: JWSSigner {

    /**
     * Gets the algorithm to be used for signing.
     * Should be used for specifying the algorithm parameter in the JWS header for subsequent signing requests.
     *
     * @return the JWS signing algorithm used for signing.
     */
    fun getAlgorithm(): JWSAlgorithm

    /**
     * Gets the key ID (kid) of the key be used for signing.
     * Should be used for specifying the kid parameter in the JWS header for subsequent signing calls.
     *
     * @return the key ID (kid) associated with the key used for signing.
     */
    fun getKeyID(): String
}