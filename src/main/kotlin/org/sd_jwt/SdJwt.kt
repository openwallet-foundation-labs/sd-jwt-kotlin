package org.sd_jwt

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.PlainHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
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

/** @suppress */
const val HIDE_NAME = "59af18d6-03b8-4349-89a9-3710d51477e9:"

/**
 * @suppress
 * This method is not for API users.
 */
private fun createHash(value: String): String {
    val hashFunction = MessageDigest.getInstance("SHA-256")
    val messageDigest = hashFunction.digest(value.toByteArray(Charsets.UTF_8))
    return b64Encoder(messageDigest)
}

/**
 * @suppress
 * This method is not for API users.
 */
private fun generateSalt(): String {
    val secureRandom = SecureRandom()
    val randomness = ByteArray(16)
    secureRandom.nextBytes(randomness)
    return b64Encoder(randomness)
}

/**
 * @suppress
 * This method is not for API users.
 */
private fun createSdClaimEntry(key: String, value: Any, disclosures: MutableList<String>): String {
    val disclosure = JSONArray()
        .put(generateSalt())
        .put(key)
        .put(value)
        .toString()
    val disclosureB64 = b64Encoder(disclosure)
    disclosures.add(disclosureB64)
    return createHash(disclosureB64)
}

/**
 * @suppress
 * This method is not for API users.
 */
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
            if (key.startsWith(HIDE_NAME)) {
                val disclosureContent =
                    createSdClaims(userClaims.get(key), discloseStructure.get(key), disclosures, decoy)
                val strippedKey = key.replace(HIDE_NAME, "")
                sdDigest.add(createSdClaimEntry(strippedKey, disclosureContent, disclosures))
            } else if (discloseStructure.has(key)) {
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
 * passed to the method and is signed by the provided signer.
 *
 * @param userClaims        A kotlinx serializable data class that contains the user's claims (all types must be nullable and default value must be null)
 * @param signer            A concrete signer instance for signing the SD-JWT as the issuer
 * @param holderPubKey      Optional: The holder's public key if holder binding is required
 * @param discloseStructure Optional: Class that has a non-null value for each object that should be disclosable separately
 * @param decoy             Optional: If true, add decoy values to the SD digest arrays (default: true)
 * @return                  Serialized SD-JWT + disclosures to send to the holder
 */
inline fun <reified T> createCredential(
    userClaims: T,
    signer: SdJwtSigner,
    holderPubKey: JWK? = null,
    discloseStructure: T? = null,
    decoy: Boolean = true
): String {
    val jsonUserClaims = JSONObject(Json.encodeToString(userClaims))
    val jsonDiscloseStructure = if (discloseStructure != null) {
        JSONObject(Json.encodeToString(discloseStructure))
    } else {
        JSONObject()
    }

    return createCredential(
        userClaims = jsonUserClaims,
        signer = signer,
        holderPubKey = holderPubKey,
        discloseStructure = jsonDiscloseStructure,
        decoy = decoy
    )
}

/**
 * This method creates a SD-JWT credential that contains the claims
 * passed to the method and is signed by the provided signer.
 *
 * @param userClaims        A JSONObject that contains the user's claims (all types must be nullable and default value must be null)
 * @param signer            A concrete signer instance for signing the SD-JWT as the issuer
 * @param holderPubKey      Optional: The holder's public key if holder binding is required
 * @param discloseStructure Optional: JSONObject that has a non-null value for each element that should be disclosable separately
 * @param decoy             Optional: If true, add decoy values to the SD digest arrays (default: true)
 * @return                  Serialized SD-JWT + disclosures to send to the holder
 */
fun createCredential(
    userClaims: JSONObject,
    signer: SdJwtSigner,
    holderPubKey: JWK? = null,
    discloseStructure: JSONObject = JSONObject(),
    decoy: Boolean = true
): String {
    val disclosures = mutableListOf<String>()
    val sdClaimsSet = createSdClaims(userClaims, discloseStructure, disclosures, decoy) as JSONObject

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


    val sdJwtEncoded = buildJWT(sdJwtPayload.build(), signer)

    return sdJwtEncoded + SEPARATOR + disclosures.joinToString(SEPARATOR)
}

/**
 * @suppress
 * This method is not for API users.
 */
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

/**
 * @suppress
 * This method is not for API users.
 */
fun findDisclosures(
    credentialClaims: Any,
    revealClaims: Any,
    disclosures: HashMap<String, String>,
    findAll: Boolean = false
): List<String> {
    val revealDisclosures = mutableListOf<String>()
    if (credentialClaims is JSONObject && (revealClaims is JSONObject || findAll)) {
        for (key in credentialClaims.keys()) {
            if (key == SD_DIGEST_KEY) {
                for (digest in credentialClaims.getJSONArray(key)) {
                    if (disclosures.containsKey(digest)) {
                        val b64Disclosure = disclosures[digest]
                        val disclosure = JSONArray(b64Decode(b64Disclosure))
                        // If the disclosure contains a SD_DIGEST_KEY key, we have to recursively process the structure.
                        if (disclosure.get(2) is JSONObject && disclosure.getJSONObject(2).has(SD_DIGEST_KEY)
                            // Check whether the disclosure should be revealed based on the existence of the key
                            // in the revealClaims structure.
                            && ((revealClaims as JSONObject).has(HIDE_NAME + disclosure.getString(1)) || findAll)
                        ) {
                            revealDisclosures.add(b64Disclosure!!)
                            revealDisclosures.addAll(
                                findDisclosures(
                                    disclosure.getJSONObject(2),
                                    if (!findAll) revealClaims.get(HIDE_NAME + disclosure.getString(1)) else revealClaims,
                                    disclosures,
                                    findAll
                                )
                            )
                        } else if ((revealClaims as JSONObject).has(disclosure.getString(1)) || findAll) {
                            revealDisclosures.add(b64Disclosure!!)
                        }
                    }
                }
            } else if ((revealClaims as JSONObject).has(key) || findAll) {
                revealDisclosures.addAll(
                    findDisclosures(
                        credentialClaims.get(key),
                        if (!findAll) revealClaims.get(key) else revealClaims,
                        disclosures,
                        findAll
                    )
                )
            }
        }
    } else if (credentialClaims is JSONArray) {
        val reference = if (revealClaims !is JSONArray || revealClaims.length() == 0) {
            JSONObject()
        } else {
            revealClaims.get(0)
        }
        for (item in credentialClaims) {
            revealDisclosures.addAll(findDisclosures(item, reference, disclosures, findAll))
        }
    }
    return revealDisclosures
}

/**
 * @suppress
 * This method is not for API users.
 *
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
 * @param holderSigner  Optional: A signer instance for the holder, only needed if holder binding is required
 * @return              Serialized SD-JWT + disclosures [+ holder JWT] concatenated by a ~ character
 */
inline fun <reified T> createPresentation(
    credential: String,
    releaseClaims: T,
    audience: String? = null,
    nonce: String? = null,
    holderSigner: SdJwtSigner? = null,
): String {
    val releaseClaimsJson = JSONObject(Json.encodeToString(releaseClaims))

    return internalCreatePresentation(
        credential = credential,
        releaseClaims = releaseClaimsJson,
        audience = audience,
        nonce = nonce,
        holderSigner = holderSigner
    )
}

/**
 * @suppress
 * This method is not for API users.
 */
fun internalCreatePresentation(
    credential: String,
    releaseClaims: JSONObject,
    audience: String? = null,
    nonce: String? = null,
    holderSigner: SdJwtSigner? = null
): String {
    val credentialParts = credential.split(SEPARATOR)
    var presentation = credentialParts[0]

    // Parse credential into formats suitable to process it
    val sdJwt = parseJWT(credentialParts[0])
    val (disclosureMap, _) = parseDisclosures(credentialParts)

    checkDisclosuresMatchingDigest(sdJwt, disclosureMap)

    val releaseDisclosures = findDisclosures(sdJwt, releaseClaims, disclosureMap)

    if (releaseDisclosures.isNotEmpty()) {
        presentation += SEPARATOR + releaseDisclosures.joinToString(SEPARATOR)
    }

    // Throw an exception if the holderKey is not null but there is no
    // key referenced in the credential.
    if (sdJwt.isNull(HOLDER_BINDING_KEY) && holderSigner != null) {
        throw Exception("SD-JWT has no holder binding and the holderKey is not null. Presentation would be signed with a key not referenced in the credential.")
    }

    // Check whether the bound key is the same as the key that
    // was passed to this method
    if (!sdJwt.isNull(HOLDER_BINDING_KEY) && holderSigner != null) {
        val boundKey = JWK.parse(sdJwt.getJSONObject(HOLDER_BINDING_KEY).getJSONObject("jwk").toString())
        val holderPubKey = holderSigner.getPublicJWK()

        if (jwkThumbprint(boundKey) != jwkThumbprint(holderPubKey)) {
            throw Exception("Passed holder key is not the same as in the credential")
        }
    }

    if (nonce != null || audience != null) {
        val holderBindingJwtPayload = JWTClaimsSet.Builder()
            .audience(audience)
            .issueTime(Date.from(Instant.now()))
            .claim("nonce", nonce)
            .build()

        presentation += SEPARATOR + buildJWT(holderBindingJwtPayload, holderSigner)
    } else {
        presentation += SEPARATOR
    }

    return presentation
}

/**
 * This method takes an SD-JWT and its disclosures and
 * creates a presentation that discloses only the desired claims.
 *
 * @param credential    A string containing the SD-JWT and its disclosures concatenated by a period character
 * @param releaseClaims A JSONObject contains a non-null value for every claim that should be presented
 * @param audience      Optional: The value of the "aud" claim in the holder JWT
 * @param nonce         Optional: The value of the "nonce" claim in the holder JWT
 * @param holderSigner  Optional: A signer instance for the holder, only needed if holder binding is required
 * @return              Serialized SD-JWT + disclosures &lsqb;+ holder JWT&rsqb; concatenated by a ~ character
 */
fun createPresentation(
    credential: String,
    releaseClaims: JSONObject,
    audience: String? = null,
    nonce: String? = null,
    holderSigner: SdJwtSigner? = null
): String {
    return internalCreatePresentation(
        credential = credential,
        releaseClaims = releaseClaims,
        audience = audience,
        nonce = nonce,
        holderSigner = holderSigner
    )
}

/**
 * @suppress
 * This method is not for API users.
 */
fun buildJWT(claims: JWTClaimsSet, signer: SdJwtSigner?): String {
    if (signer == null) {
        val header = PlainHeader.Builder()
        return PlainJWT(header.build(), claims).serialize()
    }

    val signedJwt = SignedJWT(signer.sdJwtHeader(), claims)
    signedJwt.sign(signer.jwsSigner())
    return signedJwt.serialize()
}

/**
 * @suppress
 * This method is not for API users. Use 'verifyPresentation' method.
 */
fun verifyAndBuildCredential(credentialClaims: Any, disclosures: HashMap<String, String>): Any {
    if (credentialClaims is JSONObject) {
        val claims = JSONObject()
        for (key in credentialClaims.keys()) {
            if (key == SD_DIGEST_KEY) {
                for (digest in credentialClaims.getJSONArray(key)) {
                    if (disclosures.containsKey(digest)) {
                        val b64Disclosure = disclosures[digest]
                        val disclosure = JSONArray(b64Decode(b64Disclosure))
                        if (disclosure.get(2) is JSONObject && disclosure.getJSONObject(2).has(SD_DIGEST_KEY)) {
                            val keyWithPrefix = HIDE_NAME + disclosure[1]
                            claims.put(
                                keyWithPrefix,
                                verifyAndBuildCredential(disclosure.getJSONObject(2), disclosures)
                            )
                        } else {
                            claims.put(disclosure[1] as String, disclosure[2])
                        }
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
 * @param sdJwtVerifier         The verifier used to verify the SD-JWT
 * @param expectedNonce         Optional: The value that is expected in the nonce claim of the holder JWT
 * @param expectedAud           Optional: The value that is expected in the aud claim of the holder JWT
 * @param verifyHolderBinding   Optional: Determine whether holder binding is required by the verifier's policy (default: true)
 * @return                      An object of the credential class filled with the disclosed claims
 */
inline fun <reified T> verifyPresentation(
    presentation: String,
    sdJwtVerifier: SdJwtVerifier,
    expectedNonce: String? = null,
    expectedAud: String? = null,
    verifyHolderBinding: Boolean = true,
): T {

    val sdClaimsParsedJson = verifyPresentation(
        presentation, sdJwtVerifier, expectedNonce, expectedAud, verifyHolderBinding
    )

    val format = Json { ignoreUnknownKeys = true }
    return format.decodeFromString(sdClaimsParsedJson.toString())
}

/**
 * The method takes a serialized SD-JWT + disclosures &lsqb;+ holder JWT&rsqb;, parses it and checks
 * the validity of the credential. The disclosed claims are returned in an object
 * of the credential class.
 *
 * @param presentation          Serialized presentation containing the SD-JWT and the disclosures
 * @param sdJwtVerifier         The verifier used to verify the SD-JWT
 * @param expectedNonce         Optional: The value that is expected in the nonce claim of the holder JWT
 * @param expectedAud           Optional: The value that is expected in the aud claim of the holder JWT
 * @param verifyHolderBinding   Optional: Determine whether holder binding is required by the verifier's policy (default: true)
 * @return                      A JSONObject of the credential class filled with the disclosed claims
 */
fun verifyPresentation(
    presentation: String,
    sdJwtVerifier: SdJwtVerifier,
    expectedNonce: String? = null,
    expectedAud: String? = null,
    verifyHolderBinding: Boolean = true,
): JSONObject {
    val presentationSplit = presentation.split(SEPARATOR)
    val (disclosureMap, holderJwt) = parseDisclosures(presentationSplit, 1)

    // Verify SD-JWT
    val sdJwtParsed = verifySDJWT(presentationSplit[0], sdJwtVerifier)
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

    // Exclude technical claims
    val sdClaimsParsedFiltered = JSONObject(sdClaimsParsed.toString()).toMap().filterKeys { key ->
        key !in setOf(
            SD_DIGEST_KEY,
            DIGEST_ALG_KEY,
            HOLDER_BINDING_KEY
        )
    }

    return JSONObject(sdClaimsParsedFiltered)
}

/**
 * @suppress
 * This method is not for API users. Use 'verifyPresentation' method.
 */
fun verifySDJWT(jwt: String, sdJwtVerifier: SdJwtVerifier): JSONObject {
    val signedJwt = SignedJWT.parse(jwt)
    val jwtVerifier = sdJwtVerifier.jwsVerifier(signedJwt)

    if (signedJwt.verify(jwtVerifier)) {
        return JSONObject(signedJwt.payload.toJSONObject())
    } else {
        throw Exception("Could not verify SD-JWT")
    }
}

/**
 * @suppress
 * This method is not for API users. Use 'verifyPresentation' method.
 */
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

/**
 * @suppress
 * This method is not for API users. Use 'verifyPresentation' method.
 */
private fun verifyJWTSignature(jwt: String, jwkStr: String): Boolean {
    return SignedJWT.parse(jwt).verify(JWK.parse(jwkStr).jwsVerifier())
}

/**
 * @suppress
 * This method is not for API users. Use 'verifyPresentation' method.
 */
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


/**
 * @suppress
 * This method is not for API users.
 */
fun parseJWT(jwt: String): JSONObject {
    return JSONObject(SignedJWT.parse(jwt).payload.toJSONObject())
}

/**
 * @suppress
 * This method is not for API users.
 */
fun parsePlainJwt(jwt: String): JSONObject {
    return JSONObject(PlainJWT.parse(jwt).payload.toJSONObject())
}

/**
 * @suppress
 * This method is not for API users.
 */
fun b64Encoder(str: String): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(str.toByteArray())
}

/**
 * @suppress
 * This method is not for API users.
 */
private fun b64Encoder(b: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b)
}

/**
 * @suppress
 * This method is not for API users.
 */
fun b64Decode(str: String?): String {
    return String(Base64.getUrlDecoder().decode(str))
}

/**
 * @suppress
 * This method is not for API users.
 */
fun jwkThumbprint(jwk: JWK): String {
    return b64Encoder(jwk.computeThumbprint().decode())
}

internal fun JWK.jwsVerifier(): JWSVerifier = when (keyType) {
    KeyType.OKP -> {
        Ed25519Verifier(toOctetKeyPair())
    }
    KeyType.RSA -> {
        RSASSAVerifier(toRSAKey())
    }
    KeyType.EC -> {
        ECDSAVerifier(toECKey())
    }
    else -> {
        throw NotImplementedError("JWK signing algorithm not implemented")
    }
}