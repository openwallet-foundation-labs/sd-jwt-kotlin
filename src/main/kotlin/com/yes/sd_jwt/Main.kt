package com.yes.sd_jwt

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import kotlinx.serialization.Serializable

@Serializable
data class LoginCredential(val given_name: String = "", val family_name: String = "", val email: String = "")
@Serializable
data class Address(val street_address: String = "", val locality: String = "", val region: String = "", val country: String = "")
@Serializable
data class IdCredential(val given_name: String = "", val family_name: String = "", val email: String = "", val birthday: String = "", val address: Address = Address())


fun main(args: Array<String>) {
    val issuerKey = OctetKeyPairGenerator(Curve.Ed25519)
        .keyID("IssuerKey")
        .generate()
    val holderKey = OctetKeyPairGenerator(Curve.Ed25519)
        .keyID("HolderKey")
        .generate()
    val holderPublicKey = holderKey.toPublicJWK()

    val claims0 = LoginCredential("Alice", "Wonderland", "alice@example.com")
    val credential0 = createCredential(claims0, holderPublicKey, "http://issuer.example.com", issuerKey)

    val releaseClaims0 = LoginCredential("disclose", "", "disclose")
    val presentation0 = createPresentation(credential0, releaseClaims0, "http://verifier.example.com", "12345", holderKey)
    println("Presentation0: $presentation0")

    val verifiedLoginCredential = verifyPresentation<LoginCredential>(presentation0, "12345")
    println("Verified Login Credential: $verifiedLoginCredential")

    val claims1 = IdCredential("Alice", "Wonderland", "alice@example.com", "1940-01-01", Address("123 Main St", "Anytown", "Anystate", "US"))
    val credential1 = createCredential(claims1, holderPublicKey, "http://issuer.example.com", issuerKey, 1)

    val releaseClaims1 = IdCredential("disclose", "disclose", "", "", Address("disclose", "disclose", "", ""))
    val presentation1 = createPresentation(credential1, releaseClaims1, "http://verifier.example.com", "12345", holderKey)
    println("Presentation1: $presentation1")

    val verifiedIdCredential = verifyPresentation<IdCredential>(presentation1, "12345")
    println("Verified Id Credential: $verifiedIdCredential")
}