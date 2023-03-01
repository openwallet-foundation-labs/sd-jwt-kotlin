package org.sd_jwt

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.PlainHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*
import kotlin.collections.HashMap

/** @suppress */
val SD_DIGEST_KEY = "_sd"

/** @suppress */
val DIGEST_ALG_KEY = "_sd_alg"

/** @suppress */
val HOLDER_BINDING_KEY = "cnf"

/** @suppress */
val SEPARATOR = "~"
val DECOY_MIN = 2
val DECOY_MAX = 5

data class SdJwtHeader(val type: JOSEObjectType? = null, val cty: String? = null)

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
    discloseStructure: Any,
    disclosures: MutableList<String>,
    decoy: Boolean
): Any {
    if (userClaims is JSONObject && discloseStructure is JSONObject) {
        val secureRandom = SecureRandom()
        val sdClaims = JSONObject()
        val sdDigest = mutableListOf<String>()
        for (key in userClaims.keys()) {
            if (!discloseStructure.isNull(key)) {
                sdClaims.put(
                    key,
                    createSdClaims(userClaims.get(key), discloseStructure.get(key), disclosures, decoy)
                )
            } else {
                sdDigest.add(createSdClaimEntry(key, userClaims.get(key), disclosures))
            }
        }
        if (sdDigest.isNotEmpty() && decoy) {
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
        val reference = if (discloseStructure !is JSONArray || discloseStructure.length() == 0) {
            JSONObject()
        } else {
            discloseStructure.get(0)
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
 * @param issuerKey         The issuer's private key to sign the SD-JWT
 * @param holderPubKey      Optional: The holder's public key if holder binding is required
 * @param discloseStructure Optional: Class that has a non-null value for each object that should be disclosable separately
 * @param decoy             Optional: If true, add decoy values to the SD digest arrays (default: true)
 * @return                  Serialized SD-JWT + disclosures to send to the holder
 */
inline fun <reified T> createCredential(
    userClaims: T,
    issuerKey: JWK,
    holderPubKey: JWK? = null,
    discloseStructure: T? = null,
    sdJwtHeader: SdJwtHeader = SdJwtHeader(),
    decoy: Boolean = true
): String {
    val format = Json { encodeDefaults = true }
    val jsonUserClaims = JSONObject(format.encodeToString(userClaims))
    val jsonDiscloseStructure = if (discloseStructure != null) {
        JSONObject(format.encodeToString(discloseStructure))
    } else {
        JSONObject()
    }

    val disclosures = mutableListOf<String>()
    val sdClaimsSet = createSdClaims(jsonUserClaims, jsonDiscloseStructure, disclosures, decoy) as JSONObject

    val sdJwtPayload = JWTClaimsSet.Builder()

    for (key in sdClaimsSet.keys()) {
        if (sdClaimsSet.get(key) is JSONObject) {
            sdJwtPayload.claim(key, sdClaimsSet.getJSONObject(key).toMap())
        } else if (sdClaimsSet.get(key) is JSONArray) {
            sdJwtPayload.claim(key, sdClaimsSet.getJSONArray(key).toList())
        } else {
            sdJwtPayload.claim(key, sdClaimsSet.get(key))
        }
    }

    sdJwtPayload.claim(DIGEST_ALG_KEY, "sha-256")

    if (holderPubKey != null) {
        sdJwtPayload.claim(
            HOLDER_BINDING_KEY,
            JSONObject().put("jwk", holderPubKey.toJSONObject()).toMap()
        )
    }

    val sdJwtEncoded = buildJWT(sdJwtPayload.build(), issuerKey, sdJwtHeader)

    return sdJwtEncoded + SEPARATOR + disclosures.joinToString(SEPARATOR)
}


/** @suppress */
fun parseDisclosures(credentialParts: List<String>, offset: Int = 0): Pair<HashMap<String, String>, String?> {
    val disclosures = HashMap<String, String>()
    var holderJwt: String? = null
    for (disclosure in credentialParts.subList(1, credentialParts.size - offset)) {
        disclosures[createHash(disclosure)] = disclosure
    }
    if (credentialParts.last() != "") {
        holderJwt = credentialParts.last()
    }
    return Pair(disclosures, holderJwt)
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

/**
 * @suppress
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
 * @param audience      Optional: The value of the "aud" claim in the holder JWT
 * @param nonce         Optional: The value of the "nonce" claim in the holder JWT
 * @param holderKey     Optional: The holder's private key, only needed if holder binding is required
 * @return              Serialized SD-JWT + disclosures &lsqb;+ holder JWT&rsqb; concatenated by a ~ character
 */
inline fun <reified T> createPresentation(
    credential: String,
    releaseClaims: T,
    audience: String? = null,
    nonce: String? = null,
    holderKey: JWK? = null,
): String {
    val credentialParts = credential.split(SEPARATOR)
    var presentation = credentialParts[0]

    // Parse credential into formats suitable to process it
    val sdJwt = parseJWT(credentialParts[0])
    val (disclosureMap, _) = parseDisclosures(credentialParts)
    val releaseClaimsParsed = JSONObject(Json.encodeToString(releaseClaims))

    checkDisclosuresMatchingDigest(sdJwt, disclosureMap)

    val releaseDisclosures = findDisclosures(sdJwt, releaseClaimsParsed, disclosureMap)

    if (releaseDisclosures.isNotEmpty()) {
        presentation += SEPARATOR + releaseDisclosures.joinToString(SEPARATOR)
    }

    // Throw an exception if the holderKey is not null but there is no
    // key referenced in the credential.
    if (sdJwt.isNull(HOLDER_BINDING_KEY) && holderKey != null) {
        throw Exception("SD-JWT has no holder binding and the holderKey is not null. Presentation would be signed with a key not referenced in the credential.")
    }

    // Check whether the bound key is the same as the key that
    // was passed to this method
    if (!sdJwt.isNull(HOLDER_BINDING_KEY) && holderKey != null) {
        val boundKey = JWK.parse(sdJwt.getJSONObject(HOLDER_BINDING_KEY).getJSONObject("jwk").toString())
        if (jwkThumbprint(boundKey) != jwkThumbprint(holderKey)) {
            throw Exception("Passed holder key is not the same as in the credential")
        }
    }

    if (nonce != null || audience != null) {
        val holderBindingJwtPayload = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date.from(Instant.now()))
            .claim("nonce", nonce)
            .build()
        presentation += SEPARATOR + buildJWT(holderBindingJwtPayload, holderKey)
    } else {
        presentation += SEPARATOR
    }

    return presentation
}


/** @suppress */
fun buildJWT(claims: JWTClaimsSet, key: JWK?, sdJwtHeader: SdJwtHeader = SdJwtHeader()): String {
    if (key == null) {
        val header = PlainHeader.Builder()
        if (sdJwtHeader.type != null) {
            header.type(sdJwtHeader.type)
        }
        if (sdJwtHeader.cty != null) {
            header.contentType(sdJwtHeader.cty)
        }
        return PlainJWT(header.build(), claims).serialize()
    }

    val signer: JWSSigner
    val header: JWSHeader.Builder
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

    if (sdJwtHeader.type != null) {
        header.type(sdJwtHeader.type)
    }
    if (sdJwtHeader.cty != null) {
        header.contentType(sdJwtHeader.cty)
    }

    val signedSdJwt = SignedJWT(header.build(), claims)
    signedSdJwt.sign(signer)
    return signedSdJwt.serialize()
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
 * The method takes a serialized SD-JWT + disclosures &lsqb;+ holder JWT&rsqb;, parses it and checks
 * the validity of the credential. The disclosed claims are returned in an object
 * of the credential class.
 *
 * @param presentation          Serialized presentation containing the SD-JWT and the disclosures
 * @param trustedIssuer         A map that contains issuer urls and the corresponding JWKs in JSON format serialized as strings
 * @param expectedNonce         Optional: The value that is expected in the nonce claim of the holder JWT
 * @param expectedAud           Optional: The value that is expected in the aud claim of the holder JWT
 * @param verifyHolderBinding   Optional: Determine whether holder binding is required by the verifier's policy (default: true)
 * @return                      An object of the credential class filled with the disclosed claims
 */
inline fun <reified T> verifyPresentation(
    presentation: String,
    trustedIssuer: Map<String, String>,
    expectedNonce: String? = null,
    expectedAud: String? = null,
    verifyHolderBinding: Boolean = true,
): T {
    val presentationSplit = presentation.split(SEPARATOR)
    val (disclosureMap, holderJwt) = parseDisclosures(presentationSplit, 1)

    // Verify SD-JWT
    val sdJwtParsed = verifySDJWT(presentationSplit[0], trustedIssuer)
    verifyJwtClaims(sdJwtParsed)

    // Verify holder binding if required by the verifier's policy.
    // If holder binding is not required check nonce and aud if passed to this method.
    if (verifyHolderBinding && holderJwt == null) {
        throw Exception("No holder binding in presentation but required by the verifier's policy.")
    }
    if (verifyHolderBinding) {
        val parsedHolderJwt = verifyHolderBindingJwt(holderJwt!!, sdJwtParsed)
        verifyJwtClaims(parsedHolderJwt, expectedNonce, expectedAud)
    } else if ((expectedNonce != null || expectedAud != null) && holderJwt != null) {
        val parsedHolderJwt = parsePlainJwt(holderJwt)
        verifyJwtClaims(parsedHolderJwt, expectedNonce, expectedAud)
    } else if (expectedNonce != null || expectedAud != null) {
        throw Exception("Verifier wants to verify nonce or aud claim but there was no holder JWT in the credential.")
    }

    // Check that every disclosure has a matching digest
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

        KeyType.EC -> {
            ECDSAVerifier(jwk.toECKey())
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
fun parseJWT(jwt: String): JSONObject {
    return JSONObject(SignedJWT.parse(jwt).payload.toJSONObject())
}

/** @suppress */
fun parsePlainJwt(jwt: String): JSONObject {
    return JSONObject(PlainJWT.parse(jwt).payload.toJSONObject())
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
