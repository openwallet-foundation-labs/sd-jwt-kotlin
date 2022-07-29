package org.sd_jwt

import com.nimbusds.jose.jwk.OctetKeyPair
import kotlinx.serialization.Serializable
import org.junit.jupiter.api.Test

internal class SdJwtKtTest {

    @Serializable
    private data class LoginCredential(
        val given_name: String? = null,
        val family_name: String? = null,
        val email: String? = null,
        val b: Boolean? = null,
        val age: Int? = null
    )
    @Serializable
    private data class Address(val street_address: String? = null, val locality: String? = null, val region: String? = null, val country: String? = null)
    @Serializable
    private data class IdCredential(val given_name: String? = null, val family_name: String? = null, val email: String? = null, val birthday: String? = null, val nicknames: Set<String>? = null, val address: Address? = null)

    private val verifier = "http://verifier.example.com"
    private val issuer = "http://issuer.example.com"

    private val issuerKeyJson = """{"kty":"OKP","d":"Pp1foKt6rJAvx0igrBEfOgrT0dgMVQDHmgJZbm2h518","crv":"Ed25519","kid":"IssuerKey","x":"1NYF4EFS2Ov9hqt35fVt2J-dktLV29hs8UFjxbOXnho"}"""
    private val issuerKey = OctetKeyPair.parse(issuerKeyJson)
    private val holderKeyJson = """{"kty":"OKP","d":"8G6whDz1owU1k7-TqtP3xEMasdI3t3j2AvpvXVwwrHQ","crv":"Ed25519","kid":"HolderKey","x":"s6gVLINLcCGhGEDTf_v1zMluLZcXj4GOXAfQlOWZM9Q"}"""
    private val holderKey = OctetKeyPair.parse(holderKeyJson)
    private val holderPublicKey = holderKey.toPublicJWK()

    private val trustedIssuers = mutableMapOf<String, String>(issuer to issuerKey.toPublicJWK().toJSONString())

    @Test
    fun testSimpleCredential() {
        println("====================================================")
        println("                     Issuer                         ")
        println("====================================================")
        val claims0 = LoginCredential("Alice", "Wonderland", "alice@example.com", false, 21)
        println("Claims for credential0: $claims0\n")

        val credential0 = createCredential(claims0, null, issuer, issuerKey)
        println("Credential0: $credential0\n")

        println("====================================================")
        println("                     Wallet                         ")
        println("====================================================")
        val releaseClaims0 = LoginCredential(given_name = "",  email = "", age = 0)
        val presentation0 = createPresentation(credential0, releaseClaims0, verifier, "12345", null)
        println("Presentation0: $presentation0\n")

        println("====================================================")
        println("                     Verifier                       ")
        println("====================================================")
        val verifiedLoginCredential = verifyPresentation<LoginCredential>(presentation0, trustedIssuers,"12345", verifier)
        println("Verified Login Credential: $verifiedLoginCredential\n")
    }

    @Test
    fun testAdvancedCredential0() {
        println("====================================================")
        println("                     Issuer                         ")
        println("====================================================")
        val claims1 = IdCredential("Alice", "Wonderland", "alice@example.com", "1940-01-01", setOf("A", "B"), Address("123 Main St", "Anytown", "Anystate", "US"))
        println("Claims for credential1: $claims1\n")

        val credential1 = createCredential(claims1, holderPublicKey, issuer, issuerKey, 0)
        println("Credential1: $credential1\n")

        println("====================================================")
        println("                     Wallet                         ")
        println("====================================================")
        val releaseClaims1 = IdCredential(given_name = "", family_name = "", nicknames = setOf(), address = Address())
        val presentation1 = createPresentation(credential1, releaseClaims1, verifier, "12345", holderKey)
        println("Presentation1: $presentation1\n")

        println("====================================================")
        println("                     Verifier                       ")
        println("====================================================")
        val verifiedIdCredential = verifyPresentation<IdCredential>(presentation1, trustedIssuers,"12345", verifier)
        println("Verified Id Credential: $verifiedIdCredential")
    }

    @Test
    fun testAdvancedCredential1() {
        println("====================================================")
        println("                     Issuer                         ")
        println("====================================================")
        val claims1 = IdCredential("Alice", "Wonderland", "alice@example.com", "1940-01-01", setOf("A", "B"), Address("123 Main St", "Anytown", "Anystate", "US"))
        println("Claims for credential1: $claims1\n")

        val credential1 = createCredential(claims1, holderPublicKey, issuer, issuerKey, 1)
        println("Credential1: $credential1\n")

        println("====================================================")
        println("                     Wallet                         ")
        println("====================================================")
        val releaseClaims1 = IdCredential(given_name = "", family_name = "", nicknames = setOf(), address = Address(street_address = "", locality = ""))
        val presentation1 = createPresentation(credential1, releaseClaims1, verifier, "12345", holderKey)
        println("Presentation1: $presentation1\n")

        println("====================================================")
        println("                     Verifier                       ")
        println("====================================================")
        val verifiedIdCredential = verifyPresentation<IdCredential>(presentation1, trustedIssuers,"12345", verifier)
        println("Verified Id Credential: $verifiedIdCredential")
    }

}