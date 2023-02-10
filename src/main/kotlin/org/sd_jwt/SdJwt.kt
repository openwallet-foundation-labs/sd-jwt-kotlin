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
import kotlin.collections.HashMap

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
fun parseDisclosures(credentialParts: List<String>, endOffset: Int = 0): HashMap<String, String> {
    val disclosures = HashMap<String, String>()
    for (disclosure in credentialParts.subList(1, credentialParts.size - endOffset)) {
        disclosures[createHash(disclosure)] = disclosure
    }
    return disclosures
}

/** @suppress */
fun findDisclosures(
    credentialClaims: Any,
    revealeClaims: Any,
    disclosures: HashMap<String, String>,
    findAll: Boolean = false
): List<String> {
    val revealeDisclosures = mutableListOf<String>()
    if (credentialClaims is JSONObject && (revealeClaims is JSONObject || findAll)) {
        for (key in credentialClaims.keys()) {
            if (key == SD_DIGEST_KEY) {
                for (digest in credentialClaims.getJSONArray(key)) {
                    if (disclosures.containsKey(digest)) {
                        val b64Disclosure = disclosures[digest]
                        val disclosure = JSONArray(b64Decode(b64Disclosure))
                        if ((revealeClaims as JSONObject).has(disclosure.getString(1)) || findAll) {
                            revealeDisclosures.add(b64Disclosure!!)
                        }
                    }
                }
            } else if ((revealeClaims as JSONObject).has(key) || findAll) {
                revealeDisclosures.addAll(
                    findDisclosures(
                        credentialClaims.get(key),
                        if (!findAll) revealeClaims.get(key) else revealeClaims,
                        disclosures,
                        findAll
                    )
                )
            }
        }
    } else if (credentialClaims is JSONArray) {
        val reference = if (revealeClaims !is JSONArray || revealeClaims.length() == 0) {
            JSONObject()
        } else {
            revealeClaims.get(0)
        }
        for (item in credentialClaims) {
            revealeDisclosures.addAll(findDisclosures(item, reference, disclosures, findAll))
        }
    }
    return revealeDisclosures
}

/** @suppress */
fun parseJWT(jwt: String): JSONObject {
    return JSONObject(SignedJWT.parse(jwt).payload.toJSONObject())
}

/**
 * This method checks if every disclosure has a matching digest in the SD-JWT.
 */
fun checkDisclosuresMatchingDigest(sdJwt: JSONObject, disclosureMap: HashMap<String, String>) {
    val allDisclosures = findDisclosures(sdJwt, JSONObject(), disclosureMap, true)
    val credentialDisclosureList = disclosureMap.values
    if (!allDisclosures.containsAll(credentialDisclosureList) || !credentialDisclosureList.containsAll(allDisclosures)) {
        throw Exception("Digest and disclosure values do not match")
    }
}

/**
 * This method takes an SD-JWT and its disclosures and
 * creates a presentation that discloses only the desired claims.
 *
 * @param credential    A string containing the SD-JWT and its disclosures concatenated by a period character
 * @param releaseClaims An object of the same class as the credential and every claim that should be disclosed contains a non-null value
 * @param audience      The value of the "aud" claim in the holder binding JWT
 * @param nonce         The value of the "nonce" claim in the holder binding JWT
 * @param holderKey     If holder binding is required, you have to pass the private key, otherwise you can just pass null
 * @return              Serialized SD-JWT + disclosures [+ holder binding JWT] concatenated by a ~ character
 */
inline fun <reified T> createPresentation(
    credential: String,
    releaseClaims: T,
    audience: String,
    nonce: String,
    holderKey: JWK?
): String {
    val credentialParts = credential.split(SEPARATOR)

    // Parse credential into formats suitable to process it
    val sdJwt = parseJWT(credentialParts[0])
    val disclosureMap = parseDisclosures(credentialParts)
    val releaseClaimsParsed = JSONObject(Json.encodeToString(releaseClaims))

    checkDisclosuresMatchingDigest(sdJwt, disclosureMap)

    val releaseDisclosures = findDisclosures(sdJwt, releaseClaimsParsed, disclosureMap)
    var presentation = credentialParts[0] + SEPARATOR + releaseDisclosures.joinToString(SEPARATOR)

    // Check if credential has holder binding. If so throw an exception
    // if no holder key is passed to the method.
    if (!sdJwt.isNull(HOLDER_BINDING_KEY) && holderKey == null) {
        throw Exception("SD-JWT has holder binding. SD-JWT-R must be signed with the holder key.")
    }

    // Check whether the bound key is the same as the key that
    // was passed to this method
    if (!sdJwt.isNull(HOLDER_BINDING_KEY) && holderKey != null) {
        val boundKey = JWK.parse(sdJwt.getJSONObject(HOLDER_BINDING_KEY).getJSONObject("jwk").toString())
        if (jwkThumbprint(boundKey) != jwkThumbprint(holderKey)) {
            throw Exception("Passed holder key is not the same as in the credential")
        }
    }

    if (holderKey != null) {
        val date = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC)
        val holderBindingJwt = JSONObject()
        holderBindingJwt.put("nonce", nonce)
        holderBindingJwt.put("aud", audience)
        holderBindingJwt.put("iat", date)
        presentation += SEPARATOR + buildJWT(holderBindingJwt.toString(), holderKey)
    }

    return presentation
}


/** @suppress */
fun buildJWT(claims: String, key: JWK): String {
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
fun verifyAndBuildCredential(credentialClaims: Any, disclosures: HashMap<String, String>): Any {
    if (credentialClaims is JSONObject) {
        val claims = JSONObject()
        for (key in credentialClaims.keys()) {
            if (key == SD_DIGEST_KEY) {
                for (digest in credentialClaims.getJSONArray(key)) {
                    if (disclosures.containsKey(digest)) {
                        val b64Disclosure = disclosures[digest]
                        val disclosure = JSONArray(b64Decode(b64Disclosure))
                        claims.put(disclosure[1] as String, disclosure[2])
                    }
                }
            } else {
                claims.put(key, verifyAndBuildCredential(credentialClaims.get(key), disclosures))
            }
        }
        return claims
    } else if (credentialClaims is JSONArray) {
        val claims = JSONArray()
        for (item in credentialClaims) {
            claims.put(verifyAndBuildCredential(item, disclosures))
        }
        return claims
    }
    // Assume we have a real claim and not a digest value
    return credentialClaims
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
 * @param holderBinding If the verifier policy requires holder binding, the presentation must contain a holder binding JWT
 * @return              An object of the class filled with the disclosed claims
 */
inline fun <reified T> verifyPresentation(
    presentation: String,
    trustedIssuer: Map<String, String>,
    expectedNonce: String,
    expectedAud: String,
    holderBinding: Boolean,
): T {
    val presentationSplit = presentation.split(SEPARATOR)

    // Verify SD-JWT
    val sdJwtParsed = verifySDJWT(presentationSplit[0], trustedIssuer)
    verifyJwtClaims(sdJwtParsed)

    // Verify holder binding if required by the verifier's policy
    if (holderBinding) {
        val sdJwtReleaseParsed = verifyHolderBindingJwt(presentationSplit.last(), sdJwtParsed)
        verifyJwtClaims(sdJwtReleaseParsed, expectedNonce, expectedAud)
    }

    val disclosureMap = parseDisclosures(presentationSplit, booleanToInt(holderBinding))

    checkDisclosuresMatchingDigest(sdJwtParsed, disclosureMap)

    val sdClaimsParsed = verifyAndBuildCredential(sdJwtParsed, disclosureMap)

    val format = Json { ignoreUnknownKeys = true }
    return format.decodeFromString(sdClaimsParsed.toString())
}

/** @suppress */
fun verifySDJWT(jwt: String, trustedIssuer: Map<String, String>): JSONObject {
    val jwtPayload = parseJWT(jwt)

    val issuer = if (!jwtPayload.isNull("iss")) {
        jwtPayload.getString("iss")
    } else {
        throw Exception("Could not find issuer in JWT")
    }
    if (!trustedIssuer.containsKey(issuer)) {
        throw Exception("Could not find signing key to verify JWT")
    }

    if (verifyJWTSignature(jwt, trustedIssuer[issuer]!!)) {
        return jwtPayload
    } else {
        throw Exception("Could not verify SD-JWT")
    }
}

/** @suppress */
fun verifyHolderBindingJwt(jwt: String, sdJwtParsed: JSONObject): JSONObject {
    val holderPubKey = if (!sdJwtParsed.isNull(HOLDER_BINDING_KEY)) {
        sdJwtParsed.getJSONObject(HOLDER_BINDING_KEY).getJSONObject("jwk").toString()
    } else {
        throw Exception("Holder binding is missing in SD-JWT. Expected $HOLDER_BINDING_KEY claim with a JWK.")
    }

    if (verifyJWTSignature(jwt, holderPubKey)) {
        return parseJWT(jwt)
    } else {
        throw Exception("Could not verify holder binding JWT")
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
fun b64Decode(str: String?): String {
    return String(Base64.getUrlDecoder().decode(str))
}

/** @suppress */
fun jwkThumbprint(jwk: JWK): String {
    return b64Encoder(jwk.computeThumbprint().decode())
}

/** @suppress */
fun booleanToInt(b: Boolean) = if (b) 1 else 0
