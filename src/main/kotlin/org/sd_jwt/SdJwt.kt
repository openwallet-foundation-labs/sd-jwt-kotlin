package org.sd_jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*

/** @suppress */
fun createHash(value: String): String {
    val hashFunction = MessageDigest.getInstance("SHA-256")
    val messageDigest = hashFunction.digest(value.toByteArray(Charsets.UTF_8))
    return b64Encoder(messageDigest)
}

/** @suppress */
fun buildSvcAndSdClaims(claims: JSONObject, depth: Int): Pair<JSONObject, JSONObject> {
    val svcClaims = JSONObject()
    val sdClaims = JSONObject()

    val secureRandom = SecureRandom()

    for (key in claims.keys()) {
        if (claims[key] is String || claims[key] is JSONArray || depth == 0) {
            // Generate salt
            val randomness = ByteArray(16)
            secureRandom.nextBytes(randomness)
            val salt = b64Encoder(randomness)

            // Encode salt and value together
            val saltValueEncoded = JSONArray().put(salt).put(claims[key]).toString()
            svcClaims.put(key, saltValueEncoded)

            sdClaims.put(key, createHash(saltValueEncoded))
        } else if (claims[key] is JSONObject && depth > 0) {
            val (svcClaimsChild, sdClaimsChild) = buildSvcAndSdClaims(claims.getJSONObject(key), depth - 1)
            svcClaims.put(key, svcClaimsChild)
            sdClaims.put(key, sdClaimsChild)
        } else {
            throw Exception("Cannot encode class")
        }
    }

    return Pair(svcClaims, sdClaims)
}

/**
 * This method creates a SD-JWT credential that contains the claims
 * passed to the method and is signed with the issuer's key.
 *
 * @param claims        A kotlinx serializable data class that contains the user's claims
 * @param holderPubKey  The holder's public key if holder binding is required
 * @param issuer        URL that identifies the issuer
 * @param issuerKey     The issuer's private key to sign the SD-JWT
 * @param depth         Specifies to which level the claims should be individually disclosable (default 0)
 * @return              Serialized SD-JWT + SVC to send to the holder
 */
inline fun <reified T> createCredential(claims: T, holderPubKey: JWK?, issuer: String, issuerKey: JWK, depth: Int = 0): String {
    val jsonClaims = JSONObject(Json.encodeToString(claims))
    val (svcClaims, sdClaims) = buildSvcAndSdClaims(jsonClaims, depth)

    val svc = JSONObject().put("sd_release", svcClaims)
    val svcEncoded = b64Encoder(svc.toString())

    val date = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC)
    val claimsSet = JSONObject()
        .put("iss", issuer)
        .put("iat", date)
        .put("exp", date + 3600 * 24)
        .put("sd_hash_alg", "sha-256")
        .put("sd_digests", sdClaims)
    if (holderPubKey != null) {
        claimsSet.put("sub_jwk", holderPubKey.toJSONObject())
    }

    val sdJwtEncoded = buildJWT(claimsSet.toString(), issuerKey)

    return "$sdJwtEncoded.$svcEncoded"
}

/** @suppress */
fun buildReleaseSdClaims(releaseClaims: JSONObject, svc: JSONObject): JSONObject {
    val releaseClaimsResult = JSONObject()

    for (key in releaseClaims.keys()) {
        if (releaseClaims[key] is String && releaseClaims[key] == "disclose") {
            releaseClaimsResult.put(key, svc.getString(key))
        } else if (releaseClaims[key] is JSONObject && svc[key] is String) {
            releaseClaimsResult.put(key, svc.getString(key))
        } else if (releaseClaims[key] is JSONArray && releaseClaims.getJSONArray(key)[0] == "disclose") {
            releaseClaimsResult.put(key, svc.getString(key))
        } else if (releaseClaims[key] is JSONObject) {
            val rCR = buildReleaseSdClaims(releaseClaims.getJSONObject(key), svc.getJSONObject(key))
            releaseClaimsResult.put(key, rCR)
        }
    }
    return releaseClaimsResult
}

/**
 * This method takes a SD-JWT and SVC and creates a presentation that
 * only discloses the desired claims.
 *
 * @param credential    A string containing the SD-JWT and SVC concatenated by a period character
 * @param releaseClaims An object of the same class as the credential and every claim that should be disclosed contains the string "disclose"
 * @param audience      The value of the "aud" claim in the SD-JWT Release
 * @param nonce         The value of the "nonce" claim in the SD-JWT Release
 * @param holderKey     If holder binding is required, you have to pass the private key, otherwise you can just pass null
 * @return              Serialized SD-JWT + SD-JWT Release concatenated by a period character
 */
inline fun <reified T> createPresentation(credential: String, releaseClaims: T, audience: String, nonce: String, holderKey: JWK?): String {
    // Extract svc as the last part of the credential and parse it as a JSON object
    val credentialParts = credential.split(".")
    val svc = JSONObject(b64Decode(credentialParts[3]))
    val rC = JSONObject(Json.encodeToString(releaseClaims))

    val releaseDocument = JSONObject()
    releaseDocument.put("nonce", nonce)
    releaseDocument.put("aud", audience)
    releaseDocument.put("sd_release", buildReleaseSdClaims(rC, svc.getJSONObject("sd_release")))

    // Check if credential has holder binding. If so throw an exception
    // if no holder key is passed to the method.
    val body = JSONObject(b64Decode(credentialParts[1]))
    if (!body.isNull("sub_jwk") && holderKey == null) {
        throw Exception("SD-JWT has holder binding. SD-JWT-R must be signed with the holder key.")
    }

    // Check whether the bound key is the same as the key that
    // was passed to this method
    if (!body.isNull("sub_jwk") && holderKey != null) {
        val boundKey = JWK.parse(body.getJSONObject("sub_jwk").toString())
        if (jwkThumbprint(boundKey) != jwkThumbprint(holderKey)) {
            throw Exception("Passed holder key is not the same as in the credential")
        }
    }

    val releaseDocumentEncoded = buildJWT(releaseDocument.toString(), holderKey)

    return "${credentialParts[0]}.${credentialParts[1]}.${credentialParts[2]}.$releaseDocumentEncoded"
}

/** @suppress */
fun buildJWT(claims: String, key: JWK?): String {
    if (key == null) {
        val header = b64Encoder("{\"alg\":\"none\"}")
        val body = b64Encoder(claims)
        return "$header.$body."
    }
    return when (key.keyType) {
        KeyType.OKP -> {
            val signer = Ed25519Signer(key as OctetKeyPair)
            val signedSdJwt = JWSObject(JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(key.keyID).build(), Payload(claims))
            signedSdJwt.sign(signer)
            signedSdJwt.serialize()
        }
        KeyType.RSA -> {
            val signer = RSASSASigner(key as RSAKey)
            val signedSdJwt = JWSObject(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(), Payload(claims))
            signedSdJwt.sign(signer)
            signedSdJwt.serialize()
        }
        else -> {
            throw NotImplementedError("JWT signing algorithm not implemented")
        }
    }
}

/** @suppress */
fun parseAndVerifySdClaims(sdClaims: JSONObject, svc: JSONObject): JSONObject {
    val sdClaimsParsed = JSONObject()
    for (key in svc.keys()) {
        if (svc[key] is String) {
            // Verify that the hash in the SD-JWT matches the one created from the SD-JWT Release
            if (createHash(svc.getString(key)) != sdClaims.getString(key)) {
                throw Exception("Could not verify credential claims (Claim $key has wrong hash value)")
            }
            val sVArray = JSONArray(svc.getString(key))
            if (sVArray.length() != 2) {
                throw Exception("Could not verify credential claims (Claim $key has wrong number of array entries)")
            }
            sdClaimsParsed.put(key, sVArray[1])
        } else if (svc[key] is JSONObject) {
            val sCPChild = parseAndVerifySdClaims(sdClaims.getJSONObject(key), svc.getJSONObject(key))
            sdClaimsParsed.put(key, sCPChild)
        }
    }
    return sdClaimsParsed
}

/**
 * The method takes a serialized SD-JWT + SD-JWT Release, parses it and checks
 * the validity of the credential. The disclosed claims are returned in an object
 * of the credential class.
 *
 * @param presentation  Serialized presentation containing the SD-JWT and SD-JWT Release
 * @param trustedIssuer A map that contains issuer urls and the corresponding JWKs in JSON format serialized as strings
 * @param expectedNonce The value that is expected in the nonce claim of the SD-JWT Release
 * @param expectedAud   The value that is expected in the aud claim of the SD-JWT Release
 * @return              An object of the class filled with the disclosed claims
 */
inline fun <reified T> verifyPresentation(presentation: String, trustedIssuer: Map<String, String>, expectedNonce: String, expectedAud: String): T {
    val pS = presentation.split(".")
    if (pS.size != 6) {
        throw Exception("Presentation has wrong format (Needed 6 parts separated by '.')")
    }

    // Verify SD-JWT
    val sdJwt = "${pS[0]}.${pS[1]}.${pS[2]}"
    val sdJwtParsed = verifyJWTSignature(sdJwt, trustedIssuer, true)
    verifyJwtClaims(sdJwtParsed)

    // Verify SD-JWT Release
    val sdJwtRelease = "${pS[3]}.${pS[4]}.${pS[5]}"
    val holderBinding = getHolderBinding(sdJwtParsed)
    val sdJwtReleaseParsed = verifyJWTSignature(sdJwtRelease, holderBinding, false)
    verifyJwtClaims(sdJwtReleaseParsed, expectedNonce, expectedAud)

    val sdClaimsParsed = parseAndVerifySdClaims(sdJwtParsed.getJSONObject("sd_digests"), sdJwtReleaseParsed.getJSONObject("sd_release"))

    return Json.decodeFromString(sdClaimsParsed.toString())
}

/** @suppress */
fun verifyJWTSignature(jwt: String, trustedIssuer: Map<String, String>, sdJwt: Boolean): JSONObject {
    val splits = jwt.split(".")
    val header = JSONObject(b64Decode(splits[0]))
    val body = JSONObject(b64Decode(splits[1]))

    if (header.getString("alg") == "none") {
        return body
    }

    // Get JWK to verify the signature
    val issuer = if (sdJwt && !body.isNull("iss")) {
        body.getString("iss")
    } else if (!sdJwt) {
        "holderKey"
    } else {
        throw Exception("Could not find issuer in JWT")
    }
    if (!trustedIssuer.containsKey(issuer)) {
        throw Exception("Could not find signing key to verify JWT")
    }

    // Create verifier object
    val jwk = JWK.parse(trustedIssuer[issuer])
    val verifier = when (jwk.keyType) {
        KeyType.OKP -> {
            Ed25519Verifier(jwk.toOctetKeyPair())
        }
        KeyType.RSA -> {
            RSASSAVerifier(jwk.toRSAKey())
        }
        else -> {
            throw NotImplementedError("JWT signing algorithm not implemented")
        }
    }

    val jwtParsed = SignedJWT.parse(jwt)
    // Verify JWT
    if(!jwtParsed.verify(verifier)) {
        throw Exception("Invalid JWT signature")
    }

    return body
}

/** @suppress */
fun getHolderBinding(sdJwt: JSONObject): Map<String, String>  {
    return if (sdJwt.isNull("sub_jwk")) {
        mapOf()
    } else {
        mapOf("holderKey" to sdJwt.getJSONObject("sub_jwk").toString())
    }
}

/** @suppress */
fun verifyJwtClaims(claims: JSONObject, expectedNonce: String? = null, expectedAud: String? = null) {
    if (expectedNonce != null && claims.getString("nonce") != expectedNonce) {
        throw Exception("JWT claims verification failed (invalid nonce)")
    }
    if (expectedAud != null && claims.getString("aud") != expectedAud) {
        throw Exception("JWT claims verification failed (invalid audience)")
    }

    val date = Date(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC) * 1000)
    // Check that the JWT is already valid with an offset of 30 seconds
    if (!claims.isNull("iat") && !date.after(Date((claims.getLong("iat") - 30) * 1000))) {
        throw Exception("JWT not yet valid")
    }
    if (!claims.isNull("exp") && !date.before(Date(claims.getLong("exp") * 1000))) {
        throw Exception("JWT is expired")
    }
}

/** @suppress */
fun b64Encoder(str: String): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(str.toByteArray())
}

/** @suppress */
fun b64Encoder(b: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b)
}

/** @suppress */
fun b64Decode(str: String): String {
    return String(Base64.getUrlDecoder().decode(str))
}

/** @suppress */
fun jwkThumbprint(jwk: JWK): String {
    return b64Encoder(jwk.computeThumbprint().decode())
}
