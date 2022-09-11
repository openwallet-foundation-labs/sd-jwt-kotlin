package org.sd_jwt

import com.nimbusds.jose.jwk.OctetKeyPair
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.junit.jupiter.api.Test

internal class Debugging {
    private val verifier = "http://verifier.example.com"
    private val issuer = "http://issuer.example.com"

    private val issuerKeyJson =
        """{"kty":"OKP","d":"Pp1foKt6rJAvx0igrBEfOgrT0dgMVQDHmgJZbm2h518","crv":"Ed25519","kid":"IssuerKey","x":"1NYF4EFS2Ov9hqt35fVt2J-dktLV29hs8UFjxbOXnho"}"""
    private val issuerKey = OctetKeyPair.parse(issuerKeyJson)
    private val holderKeyJson =
        """{"kty":"OKP","d":"8G6whDz1owU1k7-TqtP3xEMasdI3t3j2AvpvXVwwrHQ","crv":"Ed25519","kid":"HolderKey","x":"s6gVLINLcCGhGEDTf_v1zMluLZcXj4GOXAfQlOWZM9Q"}"""
    private val holderKey = OctetKeyPair.parse(holderKeyJson)

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
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null,
        val birthday: String? = null,
        val nicknames: Set<String>? = null,
        val address: Address? = null,
        @SerialName("secret_club_membership") val secretClubMembership: String? = null
    )

    @Test
    fun debugging() {
        val claims = IdCredential(
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

        val discloseStructure = IdCredential(address = Address())

        val holderPubKey = holderKey?.toPublicJWK()

        val credentialGen = createCredential(claims, holderPubKey, issuer, issuerKey, discloseStructure)

        println("====================== Issuer ======================")
        println("Generated credential: $credentialGen")

        val releaseClaims = IdCredential(givenName = "", email = "", address = Address(streetAddress = "", zipCode = 0), secretClubMembership = "")

        val presentationGen = createPresentation(credentialGen, releaseClaims, verifier, nonce, holderKey)

        println("====================== Wallet ======================")
        println("Generated presentation: $presentationGen")

        val verifiedCredentialGen = verifyPresentation<IdCredential>(presentationGen, trustedIssuers, nonce, verifier)

        println("===================== Verifier =====================")
        println("Verified credential: $verifiedCredentialGen\n")
    }


}