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

val SD_DIGEST_KEY = "_sd"
val DIGEST_ALG_KEY = "_sd_alg"
val HOLDER_BINDING_KEY = "cnf"
val SEPARATOR = "~"
val DECOY_MIN = 2
val DECOY_MAX = 5

/** @suppress */
fun createHash(value: String): String {
    val hashFunction = MessageDigest.getInstance("SHA-256")
    val messageDigest = hashFunction.digest(value.toByteArray(Charsets.UTF_8))
    return b64Encoder(messageDigest)
}

/** @suppress */
fun generateSalt(): String {
    val secureRandom = SecureRandom()
    val randomness = ByteArray(16)
    secureRandom.nextBytes(randomness)
    return b64Encoder(randomness)
}

/** @suppress */
fun createSdClaimEntry(key: String, value: Any, disclosures: MutableList<String>): String {
    val disclosure = JSONArray()
        .put(generateSalt())
        .put(key)
        .put(value)
        .toString()
    val disclosureB64 = b64Encoder(disclosure)
    disclosures.add(disclosureB64)
    return createHash(disclosureB64)
}

/** @suppress */
fun createSdClaims(
    userClaims: Any,
    nonSdClaims: Any,
    disclosures: MutableList<String>,
    decoy: Boolean
): Any {
    if (userClaims is JSONObject && nonSdClaims is JSONObject) {
        val secureRandom = SecureRandom()
        val sdClaims = JSONObject()
        val sdDigest = mutableListOf<String>()
        for (key in userClaims.keys()) {
            if (!nonSdClaims.isNull(key)) {
                sdClaims.put(
                    key,
                    createSdClaims(userClaims.get(key), nonSdClaims.get(key), disclosures, decoy)
                )
            } else {
                sdDigest.add(createSdClaimEntry(key, userClaims.get(key), disclosures))
            }
        }
        if (decoy) {
            for (i in 0 until secureRandom.nextInt(DECOY_MIN, DECOY_MAX)) {
                sdDigest.add(createHash(generateSalt()))
            }
        }
        if (sdDigest.isNotEmpty()) {
            sdDigest.shuffle(secureRandom)
            sdClaims.put(SD_DIGEST_KEY, sdDigest)
        }
        return sdClaims
    } else if (userClaims is JSONArray) {
        val reference = if (nonSdClaims !is JSONArray || nonSdClaims.length() == 0) {
            JSONObject()
        } else {
            nonSdClaims.get(0)
        }
        val sdClaims = JSONArray()
        for (i in 0 until userClaims.length()) {
            sdClaims.put(
                createSdClaims(
                    userClaims.get(i),
                    reference,
                    disclosures,
                    decoy
                )
            )
        }
        return sdClaims
    } else {
        return userClaims
    }
}

/**
 * This method creates a SD-JWT credential that contains the claims
 * passed to the method and is signed with the issuer's key.
 *
 * @param userClaims        A kotlinx serializable data class that contains the user's claims (all types must be nullable and default value must be null)
 * @param holderPubKey      The holder's public key if holder binding is required
 * @param issuer            URL that identifies the issuer
 * @param issuerKey         The issuer's private key to sign the SD-JWT
 * @param noneSdClaims      Class that has a non-null value for every object that should be disclosable separately
 * @param decoy             If true, add decoy values to the SD digest arrays
 * @return                  Serialized SD-JWT + disclosures to send to the holder
 */
inline fun <reified T> createCredential(
    userClaims: T,
    holderPubKey: JWK?,
    issuer: String,
    issuerKey: JWK,
    noneSdClaims: T? = null,
    decoy: Boolean = true
): String {
    val format = Json { encodeDefaults = true }
    val jsonUserClaims = JSONObject(format.encodeToString(userClaims))
    val jsonNoneSdClaims = if (noneSdClaims != null) {
        JSONObject(format.encodeToString(noneSdClaims))
    } else {
        JSONObject()
    }

    val disclosures = mutableListOf<String>()
    val claimsSet = createSdClaims(jsonUserClaims, jsonNoneSdClaims, disclosures, decoy) as JSONObject

    val date = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC)
    claimsSet.put("iss", issuer)
        .put("iat", date)
        .put("exp", date + 3600 * 24)
        .put(DIGEST_ALG_KEY, "sha-256")
    if (holderPubKey != null) {
        claimsSet.put(
            HOLDER_BINDING_KEY,
            JSONObject().put("jwk", holderPubKey.toJSONObject())
        )
    }

    val sdJwtEncoded = buildJWT(claimsSet.toString(), issuerKey)

    return sdJwtEncoded + SEPARATOR + disclosures.joinToString(SEPARATOR)
}

/** @suppress */
fun chooseClaim(releaseClaim: Any?, svcValue: Any): String? {
    if (releaseClaim != null && svcValue is String) {
        return svcValue
    }
    return null
}

/**
 * This method takes a SD-JWT and SVC and creates a presentation that
 * only discloses the desired claims.
 *
 * @param credential    A string containing the SD-JWT and SVC concatenated by a period character
 * @param releaseClaims An object of the same class as the credential and every claim that should be disclosed contains a non-null value
 * @param audience      The value of the "aud" claim in the SD-JWT Release
 * @param nonce         The value of the "nonce" claim in the SD-JWT Release
 * @param holderKey     If holder binding is required, you have to pass the private key, otherwise you can just pass null
 * @return              Serialized SD-JWT + SD-JWT Release concatenated by a period character
 */
inline fun <reified T> createPresentation(
    credential: String,
    releaseClaims: T,
    audience: String,
    nonce: String,
    holderKey: JWK?
): String {
    // Extract svc as the last part of the credential and parse it as a JSON object
    val credentialParts = credential.split(".")
    val svc = JSONObject(b64Decode(credentialParts[3]))
    val rC = JSONObject(Json.encodeToString(releaseClaims))

    val releaseDocument = JSONObject()
    releaseDocument.put("nonce", nonce)
    releaseDocument.put("aud", audience)
    releaseDocument.put("sd_release", walkByStructure(rC, svc.getJSONObject("sd_release"), ::chooseClaim))

    // Check if credential has holder binding. If so throw an exception
    // if no holder key is passed to the method.
    val body = JSONObject(b64Decode(credentialParts[1]))
    if (!body.isNull("cnf") && holderKey == null) {
        throw Exception("SD-JWT has holder binding. SD-JWT-R must be signed with the holder key.")
    }

    // Check whether the bound key is the same as the key that
    // was passed to this method
    if (!body.isNull("cnf") && holderKey != null) {
        val boundKey = JWK.parse(body.getJSONObject("cnf").getJSONObject("jwk").toString())
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
            throw NotImplementedError("JWK signing algorithm not implemented")
        }
    }
}

/** @suppress */
fun verifyClaim(sdDigest: Any?, svc: Any): Any {
    if (sdDigest is String && svc is String) {
        // Verify that the hash in the SD-JWT matches the one created from the SD-JWT Release
        if (createHash(svc) != sdDigest) {
            throw Exception("Could not verify credential claims (Claim $svc has wrong hash value)")
        }
        val sVObject = JSONObject(svc)
        if (sVObject.isNull("s") || sVObject.isNull("v")) {
            throw Exception("Could not verify credential claims (Claim $svc has wrong format)")
        }
        return sVObject["v"]
    } else {
        throw Exception("sd_digest and SVC structure is different")
    }
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
inline fun <reified T> verifyPresentation(
    presentation: String,
    trustedIssuer: Map<String, String>,
    expectedNonce: String,
    expectedAud: String
): T {
    val pS = presentation.split(".")
    if (pS.size != 6) {
        throw Exception("Presentation has wrong format (Needed 6 parts separated by '.')")
    }

    // Verify SD-JWT
    val sdJwt = "${pS[0]}.${pS[1]}.${pS[2]}"
    val sdJwtParsed = verifySDJWT(sdJwt, trustedIssuer)
    verifyJwtClaims(sdJwtParsed)

    // Verify SD-JWT Release
    val sdJwtRelease = "${pS[3]}.${pS[4]}.${pS[5]}"
    val holderPubKey = if (!sdJwtParsed.isNull("cnf")) {
        sdJwtParsed.getJSONObject("cnf").getJSONObject("jwk").toString()
    } else {
        null
    }
    val sdJwtReleaseParsed = verifySDJWTR(sdJwtRelease, holderPubKey)
    verifyJwtClaims(sdJwtReleaseParsed, expectedNonce, expectedAud)

    val sdClaimsParsed =
        walkByStructure(
            sdJwtParsed.getJSONObject("sd_digests"),
            sdJwtReleaseParsed.getJSONObject("sd_release"),
            ::verifyClaim
        )

    return Json.decodeFromString(sdClaimsParsed.toString())
}

/** @suppress */
fun verifySDJWT(jwt: String, trustedIssuer: Map<String, String>): JSONObject {
    val splits = jwt.split(".")
    val body = JSONObject(b64Decode(splits[1]))

    val issuer = if (!body.isNull("iss")) {
        body.getString("iss")
    } else {
        throw Exception("Could not find issuer in JWT")
    }
    if (!trustedIssuer.containsKey(issuer)) {
        throw Exception("Could not find signing key to verify JWT")
    }

    if (verifyJWTSignature(jwt, trustedIssuer[issuer]!!)) {
        return body
    } else {
        throw Exception("Could not verify SD-JWT")
    }
}

/** @suppress */
fun verifySDJWTR(jwt: String, holderPubKey: String?): JSONObject {
    val splits = jwt.split(".")
    val body = JSONObject(b64Decode(splits[1]))

    if (holderPubKey.isNullOrEmpty() || verifyJWTSignature(jwt, holderPubKey)) {
        return body
    } else {
        throw Exception("Could not verify SD-JWT-Release")
    }
}

/** @suppress */
fun verifyJWTSignature(jwt: String, jwkStr: String): Boolean {
    // Create verifier object
    val jwk = JWK.parse(jwkStr)
    val verifier = when (jwk.keyType) {
        KeyType.OKP -> {
            Ed25519Verifier(jwk.toOctetKeyPair())
        }

        KeyType.RSA -> {
            RSASSAVerifier(jwk.toRSAKey())
        }

        else -> {
            throw NotImplementedError("JWK signing algorithm not implemented")
        }
    }

    // Verify JWT
    return SignedJWT.parse(jwt).verify(verifier)
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
fun walkByStructure(structure: JSONArray, obj: JSONArray, fn: (s: Any?, o: Any) -> Any?): JSONArray {
    val result = JSONArray()
    var s = structure[0]
    for (i in 0 until obj.length()) {
        if (structure.length() > 1) {
            s = structure[i]
        }
        if (s is JSONObject && obj[i] is JSONObject) {
            val value = walkByStructure(s, obj.getJSONObject(i), fn)
            result.put(value)
        } else if (s is JSONArray && obj[i] is JSONArray) {
            val value = walkByStructure(s, obj.getJSONArray(i), fn)
            result.put(value)
        } else {
            val value = fn(s, obj[i])
            result.put(value)
        }
    }
    return result
}

/** @suppress */
fun walkByStructure(structure: JSONObject, obj: JSONObject, fn: (s: Any?, o: Any) -> Any?): JSONObject {
    val result = JSONObject()
    for (key in obj.keys()) {
        if (structure.opt(key) is JSONObject && obj[key] is JSONObject) {
            val value = walkByStructure(structure.getJSONObject(key), obj.getJSONObject(key), fn)
            result.put(key, value)
        } else if (structure.opt(key) is JSONArray && obj[key] is JSONArray) {
            val value = walkByStructure(structure.getJSONArray(key), obj.getJSONArray(key), fn)
            result.put(key, value)
        } else {
            val value = fn(structure.opt(key), obj[key])
            result.put(key, value)
        }
    }
    return result
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
