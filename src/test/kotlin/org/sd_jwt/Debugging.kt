package org.sd_jwt

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.*

internal class Debugging {
    private val verifier = "http://verifier.example.com"
    private val issuer = "http://issuer.example.com"

    private val issuerKeyJson =
        """{"kty":"OKP","d":"Pp1foKt6rJAvx0igrBEfOgrT0dgMVQDHmgJZbm2h518","crv":"Ed25519","kid":"IssuerKey","x":"1NYF4EFS2Ov9hqt35fVt2J-dktLV29hs8UFjxbOXnho"}"""
    private val issuerKey = OctetKeyPair.parse(issuerKeyJson)
    private val issuerSigner = KeyBasedSdJwtSigner(issuerKey)
    private val holderKeyJson =
        """{"kty":"OKP","d":"8G6whDz1owU1k7-TqtP3xEMasdI3t3j2AvpvXVwwrHQ","crv":"Ed25519","kid":"HolderKey","x":"s6gVLINLcCGhGEDTf_v1zMluLZcXj4GOXAfQlOWZM9Q"}"""
    private val holderKey = OctetKeyPair.parse(holderKeyJson)
    private val holderSigner = KeyBasedSdJwtSigner(holderKey)

    private val trustedIssuers = mutableMapOf<String, String>(issuer to issuerKey.toPublicJWK().toJSONString())

    private val nonce = "12345"

    @Serializable
    private data class Address(
        @SerialName("street_address") val streetAddress: String? = null,
        val locality: String? = null,
        val region: String? = null,
        val country: String? = null,
        @SerialName("zip_code") val zipCode: Int? = null
    )

    @Serializable
    private data class IdCredential(
        val iss: String,
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null,
        val birthday: String? = null,
        val nicknames: Set<String>? = null,
        @SerialName (HIDE_NAME + "address") val address: Address? = null,
        @SerialName("secret_club_membership") val secretClubMembership: String? = null
    )

    @Test
    fun debugging() {
        val claims = IdCredential(
            iss = issuer,
            givenName = "Alice",
            familyName = "Wonderland",
            email = "alice@example.com",
            birthday = "1950-01-01",
            nicknames = setOf("A", "B"),
            address = Address(
                streetAddress = "123 Main St",
                locality = "Anytown",
                region = "Anystate",
                country = "US",
                zipCode = 123456
            ),
            secretClubMembership = "SecretClub"
        )

        val discloseStructure = IdCredential(iss = "", address = Address())

        val holderPubKey = holderKey?.toPublicJWK()

        val credentialGen = createCredential(claims, issuerSigner, holderPubKey, discloseStructure)

        println("====================== Issuer ======================")
        println("Generated credential: $credentialGen")

        val releaseClaims = IdCredential(
            iss = "",
            givenName = "",
            email = "",
            address = Address(streetAddress = "", zipCode = 0),
            secretClubMembership = ""
        )

        val presentationGen = createPresentation(credentialGen, releaseClaims, verifier, nonce, holderSigner)

        println("====================== Wallet ======================")
        println("Generated presentation: $presentationGen")

        val verifiedCredentialGen =
            verifyPresentation<IdCredential>(presentationGen, TrustedIssuersSdJwtVerifier(trustedIssuers), nonce, verifier, true)

        println("===================== Verifier =====================")
        println("Verified credential: $verifiedCredentialGen\n")
    }


    @Serializable
    private data class SimpleTestCredential(
        val iss: String,
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null,
        val b: Boolean? = null,
        val age: Int? = null
    )

    @Test
    fun minimal() {
        val claims = SimpleTestCredential(iss = issuer, "Alice", "Wonderland", "alice@example.com", false, 21)
        val discloseStructure = SimpleTestCredential(iss = "")
        val credential = createCredential(claims, issuerSigner, discloseStructure = discloseStructure)

        println("====================== Issuer ======================")
        println("Credential: $credential")

        val releaseClaims =
            SimpleTestCredential(iss = "", givenName = "", email = "", age = 0) // Non-null claims will be revealed
        val presentation = createPresentation(credential, releaseClaims)

        println("====================== Wallet ======================")
        println("Presentation: $presentation")

        val verifiedSimpleTestCredential =
            verifyPresentation<SimpleTestCredential>(presentation, TrustedIssuersSdJwtVerifier(trustedIssuers), verifyHolderBinding = false)

        println("===================== Verifier =====================")
        println("Verified credential: $verifiedSimpleTestCredential\n")
    }

    @Serializable
    data class CredentialSubject(
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null
    )

    @Serializable
    data class EmailCredential(
        val type: String,
        val iat: Long,
        val exp: Long,
        val iss: String,
        @SerialName(HIDE_NAME + "credentialSubject") val credentialSubject: CredentialSubject? = null
    )

    @Test
    fun nextcloudLoginCredential() {
        val issuerKey = ECKeyGenerator(Curve.P_256)
            .keyID("Issuer")
            .generate()

        val header = SdJwtHeader(JOSEObjectType("vc+sd-jwt"), "credential-claims-set+json")
        val signer = KeyBasedSdJwtSigner(issuerKey, sdJwtHeader = header)

        val holderKey = ECKeyGenerator(Curve.P_256)
            .keyID("Holder")
            .generate()

        val issuer = "did:jwk:${b64Encoder(issuerKey.toPublicJWK().toJSONString())}"

        val trustedIssuers = mapOf<String, String>(issuer to issuerKey.toPublicJWK().toJSONString())

        val userClaims = EmailCredential(
            type = "VerifiedEMail",
            iat = Date.from(Instant.now()).time / 1000,
            exp = Date.from(Instant.now().plusSeconds(3600 * 48)).time / 1000,
            iss = issuer,
            credentialSubject = CredentialSubject(
                givenName = "Alice",
                familyName = "Wonderland",
                email = "alice@example.com"
            )
        )

        val discloseStructure =
            EmailCredential(type = "", iat = 0, exp = 0, iss = "", credentialSubject = CredentialSubject())

        val credential = createCredential(userClaims, signer, holderKey.toPublicJWK(), discloseStructure)

        println("Credential: $credential")
        println()

        val releaseClaims = EmailCredential(type = "", iat = 0, exp = 0, iss = "", credentialSubject = CredentialSubject(email = "", givenName = "", familyName = ""))
        val holderSignerNextcloud = KeyBasedSdJwtSigner(holderKey)
        val presentation =
            createPresentation(credential, releaseClaims, "https://nextcloud.example.com", "1234", holderSignerNextcloud)
        println("Presentation: $presentation")
        println()

        val verifiedEmailCredential = verifyPresentation<EmailCredential>(
            presentation,
            TrustedIssuersSdJwtVerifier(trustedIssuers),
            "1234",
            "https://nextcloud.example.com",
            true
        )
        println(verifiedEmailCredential)
    }
}