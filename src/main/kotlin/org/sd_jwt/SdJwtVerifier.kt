package org.sd_jwt

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jwt.SignedJWT

/**
 * Implements verification rules for an SD-JWT.
 */
interface SdJwtVerifier {
    /**
     * This method returns a JWSVerifier based on a given SignedJWT (containing the SD-JWT payload).
     *
     * This approach allows to respect values set in the header and claims to construct the JWSVerifier and thus allows
     * to implement the necessary verification steps demanded by specifications like SD-JWT VC.
     *
     * @return a JWSVerifier that will be used to verify the SD-JWT signature.
     */
    fun jwsVerifier(jwt: SignedJWT): JWSVerifier
}