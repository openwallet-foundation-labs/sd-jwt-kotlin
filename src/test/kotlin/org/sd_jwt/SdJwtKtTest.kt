package org.sd_jwt

import com.nimbusds.jose.jwk.OctetKeyPair
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.*

internal class SdJwtKtTest {

    @Serializable
    private data class SimpleTestCredential(
        @SerialName("given_name") val givenName: String? = null,
        @SerialName("family_name") val familyName: String? = null,
        val email: String? = null,
        val b: Boolean? = null,
        val age: Int? = null
    )

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

    @Test
    fun testSimpleCredential() {
        val testConfig = TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, null, "Simple Credential")

        val expectedCredential =
            "eyJraWQiOiJJc3N1ZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJzZF9oYXNoX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiZXhwIjoxNjYxNTIxMjE3LCJpYXQiOjE2NjE0MzQ4MTcsInNkX2RpZ2VzdHMiOnsiYiI6IjhXMjVTZTNFa0RPYlFsdUJnWWRLQk90Qkh2TExJVDJvU2lrZDdHaDFfbXMiLCJnaXZlbl9uYW1lIjoiVG5Mb2F0bW1HUnUxSTlqbjN3ZUI0eVNNNXBQd3N3dXp2bFZkQzc4bDVRcyIsImZhbWlseV9uYW1lIjoibmtMdWo3TFNsTWRXRFVPNl81YUc3SzNyNkV4eEN0cURsdXpnU1Q3cG8tYyIsImVtYWlsIjoiUFdfVzFxckExZjhEa0tTbG8wTDk4aUtReHVfNW1FYnUwZmhVSE9jamgwYyIsImFnZSI6ImQxV2ZTSlNhUWlxaWJqVG9KUWFPNEduaEo1RjZuMDRFZC1GbGNfa25JdHMifX0.IkWYy2G79AEFaI7bHQpGuFCxgKPgYJWz5r1PbTAmxX3J7ej8lvI0RfNG76ULu1oGy7ooVJX7B4QzH84b7Gf4Dw.eyJzZF9yZWxlYXNlIjp7ImIiOiJbXCJjRW9BYWYzN21QSFYzUjlLVGJyajd3XCIsZmFsc2VdIiwiZ2l2ZW5fbmFtZSI6IltcIi10aThjWTlJSlBoSkppVjAzYjdjYUFcIixcIkFsaWNlXCJdIiwiZmFtaWx5X25hbWUiOiJbXCJqaVVETUhub0dXeDd2SGoxVnB6Mk5BXCIsXCJXb25kZXJsYW5kXCJdIiwiZW1haWwiOiJbXCJ3QUg0WFRud0t5bkFDNzZ3dy1pZXN3XCIsXCJhbGljZUBleGFtcGxlLmNvbVwiXSIsImFnZSI6IltcInJFZmlfYXNhNEh6d0tubktHbjRXYVFcIiwyMV0ifX0"
        val expectedPresentation =
            "eyJraWQiOiJJc3N1ZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJzZF9oYXNoX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiZXhwIjoxNjYxNjA1NjIxLCJpYXQiOjE2NjE1MTkyMjEsInNkX2RpZ2VzdHMiOnsiYiI6IlAzektnc1FQa1c2ZGRVTDBmMDNQLVRxa2p4aU81cFhMZFhEWXQ0NWhZRzQiLCJnaXZlbl9uYW1lIjoiTnozZHdpSGFjSWlSRUxaRnhyd2NtSm9ncEhTTFNNU3luaXdVdFNBd2p0SSIsImZhbWlseV9uYW1lIjoicmh6Q0VET0cwQVNKc09pWmRWbVFSZEhnRTNIZUpqaGl4U25SU2dPeVNTayIsImVtYWlsIjoidjc3Y2RUY1pCTWZlaTVfVEVENW1VUEFDTHpjWFI2UTBJZUpraVdpZk9OVSIsImFnZSI6Iko0VkM4Ti0tb0ZybFhySmlSdXRTXzBIWXFUdHZqTkFwcEVxRGRRdkpIU0EifX0.cVwk7mets4E6I6aQ8waP1acyBkvPtqer7Wz3IrBupocVYY17NAo0rNK33H57Ii9A9ybumC_T_52L_xw2Bd-oBA.eyJhbGciOiJub25lIn0.eyJzZF9yZWxlYXNlIjp7ImdpdmVuX25hbWUiOiJbXCJ6Q1RIMFp0MkE3Y2hWMXNuVGtIdG5nXCIsXCJBbGljZVwiXSIsImVtYWlsIjoiW1wiRTAydnFjd2UxekJ2OWVBc1gzNFlYZ1wiLFwiYWxpY2VAZXhhbXBsZS5jb21cIl0iLCJhZ2UiOiJbXCIzdDdNaWtqUWFsX3l4VnFSelgyNV93XCIsMjFdIn0sImF1ZCI6Imh0dHA6Ly92ZXJpZmllci5leGFtcGxlLmNvbSIsIm5vbmNlIjoiMTIzNDUifQ."
        val claims = SimpleTestCredential("Alice", "Wonderland", "alice@example.com", false, 21)
        val releaseClaims = SimpleTestCredential(givenName = "", email = "", age = 0)
        val expectedClaims = SimpleTestCredential(givenName = "Alice", email = "alice@example.com", age = 21)

        testRoutine(expectedCredential, expectedPresentation, expectedClaims, claims, null, releaseClaims, testConfig)
    }

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
        val address: Address? = null
    )

    @Test
    fun testAdvancedCredential() {
        val testConfig =
            TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, holderKey, "Advanced Credential")

        val expectedCredential =
            "eyJraWQiOiJJc3N1ZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJzZF9oYXNoX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiY25mIjp7IngiOiJzNmdWTElOTGNDR2hHRURUZl92MXpNbHVMWmNYajRHT1hBZlFsT1daTTlRIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkhvbGRlcktleSJ9LCJleHAiOjE2NjE2MDc3MDUsImlhdCI6MTY2MTUyMTMwNSwic2RfZGlnZXN0cyI6eyJiaXJ0aGRheSI6IjBrSGgyMVhwRDF1OXBELW9qel9lVzhqaEcyM1JmcXNneXZreUpCdmdubGsiLCJhZGRyZXNzIjoiN0NrU085QzV2SzJ3c2JMTjJMTVRKQXI4RjFCRXBQMnNIZTdyTjBfRXBPUSIsIm5pY2tuYW1lcyI6ImIyWTlaUkFUMUFUck5aaE4xeGtxRElwcmdVVWREaldHOEo3TUtKYmVkV3ciLCJnaXZlbl9uYW1lIjoibU5oSW9JaUZDR2ZRSWJCeG1wY0hlU2lKZHRMRTItS3oxRUh3dHRwcmxkNCIsImZhbWlseV9uYW1lIjoick90NkxEcFJhU25fdG9CeHM4dXJsd21vUmlTeXAyWjlBM04zWmtTMGxscyIsImVtYWlsIjoiVzJxa1ZWZFdGX3BWTHc5RDVKNWJLVEN6VHl1ZllPalU4aUx0RFJ4OHdPWSJ9fQ.hvY39dsHUp2BaubN4mU4oBh6fH-jLhuHmTtGrjt-bQr4v0C8xO1uVRzT6pRkS77DKl1GT0WA69lOhiX7lh8bDw.eyJzZF9yZWxlYXNlIjp7ImJpcnRoZGF5IjoiW1wibGNoYXJPT2theFhsNDJ5Q09PYlNqd1wiLFwiMTk0MC0wMS0wMVwiXSIsImFkZHJlc3MiOiJbXCJDaWd4NGt0ZnU5ZHJtcVBaaGJod1JRXCIse1wic3RyZWV0X2FkZHJlc3NcIjpcIjEyMyBNYWluIFN0XCIsXCJjb3VudHJ5XCI6XCJVU1wiLFwibG9jYWxpdHlcIjpcIkFueXRvd25cIixcInJlZ2lvblwiOlwiQW55c3RhdGVcIixcInppcF9jb2RlXCI6MTIzNDU2fV0iLCJuaWNrbmFtZXMiOiJbXCJiYTBIUlNVRGg0UzNtWnlSYzlZSi1BXCIsW1wiQVwiLFwiQlwiXV0iLCJnaXZlbl9uYW1lIjoiW1wiNlNobWRJcTBuOFF4TlZEdXJ3UDkyZ1wiLFwiQWxpY2VcIl0iLCJmYW1pbHlfbmFtZSI6IltcIldXbTBKTFkzbXM5TnB2ZnAxckRSTmdcIixcIldvbmRlcmxhbmRcIl0iLCJlbWFpbCI6IltcIkRWNTVEWW53TkNSR2x5TTFxQVI4TGdcIixcImFsaWNlQGV4YW1wbGUuY29tXCJdIn19"
        val expectedPresentation =
            "eyJraWQiOiJJc3N1ZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJzZF9oYXNoX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiY25mIjp7IngiOiJzNmdWTElOTGNDR2hHRURUZl92MXpNbHVMWmNYajRHT1hBZlFsT1daTTlRIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkhvbGRlcktleSJ9LCJleHAiOjE2NjE2MDc3MDUsImlhdCI6MTY2MTUyMTMwNSwic2RfZGlnZXN0cyI6eyJiaXJ0aGRheSI6IjBrSGgyMVhwRDF1OXBELW9qel9lVzhqaEcyM1JmcXNneXZreUpCdmdubGsiLCJhZGRyZXNzIjoiN0NrU085QzV2SzJ3c2JMTjJMTVRKQXI4RjFCRXBQMnNIZTdyTjBfRXBPUSIsIm5pY2tuYW1lcyI6ImIyWTlaUkFUMUFUck5aaE4xeGtxRElwcmdVVWREaldHOEo3TUtKYmVkV3ciLCJnaXZlbl9uYW1lIjoibU5oSW9JaUZDR2ZRSWJCeG1wY0hlU2lKZHRMRTItS3oxRUh3dHRwcmxkNCIsImZhbWlseV9uYW1lIjoick90NkxEcFJhU25fdG9CeHM4dXJsd21vUmlTeXAyWjlBM04zWmtTMGxscyIsImVtYWlsIjoiVzJxa1ZWZFdGX3BWTHc5RDVKNWJLVEN6VHl1ZllPalU4aUx0RFJ4OHdPWSJ9fQ.hvY39dsHUp2BaubN4mU4oBh6fH-jLhuHmTtGrjt-bQr4v0C8xO1uVRzT6pRkS77DKl1GT0WA69lOhiX7lh8bDw.eyJraWQiOiJIb2xkZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJzZF9yZWxlYXNlIjp7ImFkZHJlc3MiOiJbXCJDaWd4NGt0ZnU5ZHJtcVBaaGJod1JRXCIse1wic3RyZWV0X2FkZHJlc3NcIjpcIjEyMyBNYWluIFN0XCIsXCJjb3VudHJ5XCI6XCJVU1wiLFwibG9jYWxpdHlcIjpcIkFueXRvd25cIixcInJlZ2lvblwiOlwiQW55c3RhdGVcIixcInppcF9jb2RlXCI6MTIzNDU2fV0iLCJuaWNrbmFtZXMiOiJbXCJiYTBIUlNVRGg0UzNtWnlSYzlZSi1BXCIsW1wiQVwiLFwiQlwiXV0iLCJnaXZlbl9uYW1lIjoiW1wiNlNobWRJcTBuOFF4TlZEdXJ3UDkyZ1wiLFwiQWxpY2VcIl0iLCJmYW1pbHlfbmFtZSI6IltcIldXbTBKTFkzbXM5TnB2ZnAxckRSTmdcIixcIldvbmRlcmxhbmRcIl0ifSwiYXVkIjoiaHR0cDovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIiwibm9uY2UiOiIxMjM0NSJ9.-pj_KrrjL4WzSyTA53dIf8wOnd26qBSzwXZzzt9emb7mj1iBK3N7OIB9mXp2K0cHtvvCwohI2ciJDWIuEG8DCA"
        val claims = IdCredential(
            "Alice",
            "Wonderland",
            "alice@example.com",
            "1940-01-01",
            setOf("A", "B"),
            Address("123 Main St", "Anytown", "Anystate", "US", 123456)
        )
        val releaseClaims = IdCredential(givenName = "", familyName = "", nicknames = setOf(), address = Address())
        val expectedClaims = IdCredential(
            givenName = "Alice",
            familyName = "Wonderland",
            nicknames = setOf("A", "B"),
            address = Address("123 Main St", "Anytown", "Anystate", "US", 123456)
        )

        testRoutine(expectedCredential, expectedPresentation, expectedClaims, claims, null, releaseClaims, testConfig)
    }

    @Test
    fun testAdvancedCredentialStructured() {
        val testConfig =
            TestConfig(trustedIssuers, issuerKey, issuer, verifier, nonce, holderKey, "Advanced Credential Structured")
        val expectedCredential = "eyJraWQiOiJJc3N1ZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJzZF9oYXNoX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiY25mIjp7IngiOiJzNmdWTElOTGNDR2hHRURUZl92MXpNbHVMWmNYajRHT1hBZlFsT1daTTlRIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkhvbGRlcktleSJ9LCJleHAiOjE2NjE2MTIyNDMsImlhdCI6MTY2MTUyNTg0Mywic2RfZGlnZXN0cyI6eyJiaXJ0aGRheSI6Inc2LV9jbUppeXE5bHFVMl9iTE1iMjV4YXVpRlE4Z2pzM2NUNEpTcXMtblEiLCJhZGRyZXNzIjp7InN0cmVldF9hZGRyZXNzIjoiSVg5MmpTRHdIMWhQS2JQN3JGa1p6QXpibDRBSFpWakZYYnVtY0dTS04zayIsImNvdW50cnkiOiJHOGo1LWMzWVo5LWhDcExYLVA2QVdKZzYtcGdjb1RaUnE4ekdJb2RQb1Q4IiwibG9jYWxpdHkiOiJoYklGWnpaX1BKT1FST1R5M2dyR3V3dDB0MHhqRHpCMExFTnFDb3ZlQnhJIiwicmVnaW9uIjoiaktnQzF4THZWZ2ZvSFFTakFmWUI0eE9qT0NOV2NyM2JtaEppSXdoVVZoWSIsInppcF9jb2RlIjoiTDRIR3pGaW1CMUxtR01SQTlULUF0MjFWZkd4aW1uVXZCbnEtb3lCZk5UayJ9LCJuaWNrbmFtZXMiOiJ0cElDdnNCdlpDSUNuZ1gwaGZkY0loeHlqTV9kYWdhRzJmV1JVaV9GaXg0IiwiZ2l2ZW5fbmFtZSI6ImlzOXI3aFJSRDBtZjlOUGJCRVhWMWF2cEFoSVN4cjNyc2YwN2JpWlNMWVUiLCJmYW1pbHlfbmFtZSI6IjhzNVBxUnAzU1lPcGV4UHFiSkxYVXZpd2lpNENld04zTVJWRk5vb19tNlkiLCJlbWFpbCI6IkQ0ZjI3SmVtem1CU1VzTEwyemZOZ3Y3SHJXZGRkV3lOVV9ZLWdXX3hza3cifX0.y2xmqi2ayZhCMq2aVEaZgLHlwirHvBfifJmkRVGq2u0qHbsqhrWCvZpAj8meZ5MDNh3JmWlvc4PGTDpJxLWMAA.eyJzZF9yZWxlYXNlIjp7ImJpcnRoZGF5IjoiW1wiaW4xTlE3bHhUTU9LZzJvaGt3bkNKZ1wiLFwiMTk0MC0wMS0wMVwiXSIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiJbXCI3UFZKaXR2UWktamVDM2U4U2YxRlhBXCIsXCIxMjMgTWFpbiBTdFwiXSIsImNvdW50cnkiOiJbXCIxUnE5UWtYVk9RYXdZSXBEX2NVRk93XCIsXCJVU1wiXSIsImxvY2FsaXR5IjoiW1wid2kwYm5kWjN6ZzA2QUt5UGJ6WUJXQVwiLFwiQW55dG93blwiXSIsInJlZ2lvbiI6IltcIlJ3VzVia25kbHl5RXo3VjFmeGxOa2dcIixcIkFueXN0YXRlXCJdIiwiemlwX2NvZGUiOiJbXCJZMWNSajRja2lIaktFSXA2bmhocmJnXCIsMTIzNDU2XSJ9LCJuaWNrbmFtZXMiOiJbXCI5Zk9oc3poVWp6MHhjOGpxUEEyUnJ3XCIsW1wiQVwiLFwiQlwiXV0iLCJnaXZlbl9uYW1lIjoiW1wic0p1X2I3SlgtRnZEbHJ6dmlnTlhDZ1wiLFwiQWxpY2VcIl0iLCJmYW1pbHlfbmFtZSI6IltcImVNcXQwWkpzaFVUNGJHYjJUYjNtbUFcIixcIldvbmRlcmxhbmRcIl0iLCJlbWFpbCI6IltcInNhSmZtWUxvTjc3aHZ0NW1QS3lvREFcIixcImFsaWNlQGV4YW1wbGUuY29tXCJdIn19"
        val expectedPresentation = "eyJraWQiOiJJc3N1ZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJzZF9oYXNoX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiY25mIjp7IngiOiJzNmdWTElOTGNDR2hHRURUZl92MXpNbHVMWmNYajRHT1hBZlFsT1daTTlRIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkhvbGRlcktleSJ9LCJleHAiOjE2NjE2MTIzMTEsImlhdCI6MTY2MTUyNTkxMSwic2RfZGlnZXN0cyI6eyJiaXJ0aGRheSI6IlEyTzRMOHJyY0tkZmRyWUE2aTllWGlYOGVqa0hTdHQ4U3ZOaUEzbHBoRVUiLCJhZGRyZXNzIjp7InN0cmVldF9hZGRyZXNzIjoiYXhoaGRtRkFDdzdZOF8zSTU4UlZRcDdYTUxZcWJvREtzcmcySGlhQUlOVSIsImNvdW50cnkiOiJTZnB5VURfaU5wQmtsbzZyOHNUbWlpZC1hZXFxd0FHX0VYbFkxYzVxekxvIiwibG9jYWxpdHkiOiJ0eE1EcUlQLXlXcmFPYUMyaURxVGREY0tCam1oWFRScEx2WVpPbkZ0ek5FIiwicmVnaW9uIjoiQzQ4YWtFa3ZmYllVTm5GTlNzZGZYSFVSdFc1Sm5IVmJ5RWROUHhmQjFtQSIsInppcF9jb2RlIjoicm9kcDhkbDRqcE01a21CYW1vTlFTZXpMbW1CLUlHU1RBOUtucmZmNmhEYyJ9LCJuaWNrbmFtZXMiOiI5cnR0dkIyZzFZMURyQ0V6dlZEU1BDNlJKRzh3QkdqSHg4QkF0aUkxamI0IiwiZ2l2ZW5fbmFtZSI6IjliZnljUjQyWXNkU1RYb0NmdWlGa0lfWmt0TjNqY19LbmYzM3B1dVZoeDgiLCJmYW1pbHlfbmFtZSI6ImJjbE51Z3laOWRPU3FGdUI5VWxZU0w4Ym1Ka2RhVnRTR0tGaVZxQzhiaGsiLCJlbWFpbCI6IlcyMFpDZXRybzI4YlVON0VXMVJSUDVnWVk1MkliaG5xUGFGODR1NlM4UEEifX0.kdtem7EUss9W61aVSOKr2gdpGjY1S5cDjt4QbUDEh9tm9OsPE8jD9ISLNrpYsavQYyCKGCJmdESLcnN3S3xCAg.eyJraWQiOiJIb2xkZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJzZF9yZWxlYXNlIjp7ImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiJbXCJhRUJ0RVpoZGxnMGl4UnV5Qmg1LVdRXCIsXCIxMjMgTWFpbiBTdFwiXSIsImxvY2FsaXR5IjoiW1wic0RwbGl2bmNDODJvenk2SnZhWnE4UVwiLFwiQW55dG93blwiXSIsInppcF9jb2RlIjoiW1wiNzFrWkJfdU41QzJLMzRJeWZ5Q1l5d1wiLDEyMzQ1Nl0ifSwibmlja25hbWVzIjoiW1wiRUNTUW9mSlduSVowcXU0LXN1b0NJd1wiLFtcIkFcIixcIkJcIl1dIiwiZ2l2ZW5fbmFtZSI6IltcIk5zOG83blg2RWJhVlhkRzlrUzNwandcIixcIkFsaWNlXCJdIiwiZmFtaWx5X25hbWUiOiJbXCJGWGRZcTZuaHRiRkVKLUxROUdhMG5nXCIsXCJXb25kZXJsYW5kXCJdIn0sImF1ZCI6Imh0dHA6Ly92ZXJpZmllci5leGFtcGxlLmNvbSIsIm5vbmNlIjoiMTIzNDUifQ.c2qf6Q1eHjWE-qK486XjaBZ-IpX6r_6EyhNt3eHhk2p7c1rLHZINmBtxN7yHWhkcaS9m31tF0bpJaXkqRAPMAQ"
        val claims = IdCredential(
            "Alice",
            "Wonderland",
            "alice@example.com",
            "1940-01-01",
            setOf("A", "B"),
            Address("123 Main St", "Anytown", "Anystate", "US", 123456)
        )
        val discloseStructure = IdCredential(address = Address())
        val releaseClaims = IdCredential(
            givenName = "",
            familyName = "",
            nicknames = setOf(),
            address = Address(streetAddress = "", locality = "", zipCode = 0)
        )
        val expectedClaims = IdCredential(
            givenName = "Alice",
            familyName = "Wonderland",
            nicknames = setOf("A", "B"),
            address = Address(streetAddress = "123 Main St", locality = "Anytown", zipCode = 123456)
        )

        testRoutine(
            expectedCredential,
            expectedPresentation,
            expectedClaims,
            claims,
            discloseStructure,
            releaseClaims,
            testConfig
        )
    }

    @Test
    fun noneHeader() {
        // eyJhbGciOiAibm9uZSJ9. => {"alg": "none"}
        val noneHeaderPresentation =
            "eyJhbGciOiAibm9uZSJ9.eyJzZF9oYXNoX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiY25mIjp7IngiOiJzNmdWTElOTGNDR2hHRURUZl92MXpNbHVMWmNYajRHT1hBZlFsT1daTTlRIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkhvbGRlcktleSJ9LCJleHAiOjE2NjEwMzg3NzEsImlhdCI6MTY2MDk1MjM3MSwic2RfZGlnZXN0cyI6eyJiaXJ0aGRheSI6ImVjeWc1SGEzRVA4ZHloSXhXRXJJNFVVVUJtbEZFXzU4UFBHbnVJWThDaVkiLCJhZGRyZXNzIjoiYUFjZUlzN0lDTDk0c0d0UUtqLVZ3b04tLXo0R1lXcUNvNHdFOW1XOUlGUSIsIm5pY2tuYW1lcyI6Il9wckJJeS1RZ2VpMXFFRHVpcDRtSlJRTmQ0U1BjRVRMUWZPRlBaMW9fRTAiLCJnaXZlbl9uYW1lIjoieFlzQUpSOGtockJtUEhIYUtWOVRibXl4VTN4NEdJVUZOMm5wR3g5aHYwUSIsImZhbWlseV9uYW1lIjoiSGR0MWJMdWZsMXk3d1JPUkFGM2p1czBXWTNXLVFZdnRIR3RhWVpKNUl1SSIsImVtYWlsIjoiUVpvaEtmUzFqdFJuZFVJakFndi0tdGxPUnQ2dFhuM3U5YWFfeG8tNWxuWSJ9fQ.e5ygxCyVZZe1kt1S1bcK383EYZn3GebiQ0aL9a_hqSFQbxei408OQUnRtYCQFDIxHtE24eY6RteUtAWZTwi0AA.eyJhbGciOiAibm9uZSJ9.eyJzZF9yZWxlYXNlIjp7ImFkZHJlc3MiOiJbXCJwU3ZBZFZzS09VUkJnaGFyRlprXzV3XCIse1wic3RyZWV0X2FkZHJlc3NcIjpcIjEyMyBNYWluIFN0XCIsXCJjb3VudHJ5XCI6XCJVU1wiLFwibG9jYWxpdHlcIjpcIkFueXRvd25cIixcInJlZ2lvblwiOlwiQW55c3RhdGVcIixcInppcF9jb2RlXCI6MTIzNDU2fV0iLCJuaWNrbmFtZXMiOiJbXCJwcFNwdXo1d0tmY2ZYZ1pfV2RPYmxRXCIsW1wiQVwiLFwiQlwiXV0iLCJnaXZlbl9uYW1lIjoiW1wiV3dtZ3BiTzVvNTJiWnhjMjJJYmV0Z1wiLFwiQWxpY2VcIl0iLCJmYW1pbHlfbmFtZSI6IltcImdGYldfR2ZjbFdId3ppYnNWQU93SXdcIixcIldvbmRlcmxhbmRcIl0ifSwiYXVkIjoiaHR0cDovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIiwibm9uY2UiOiIxMjM0NSJ9.POOBnye2FDNE2YLhvmy-knlE1CX3vN2VA5uEebHB4WxEt5PhDCPRJAVh2WG97rfLvA8JCuYZXpD7ACeV-MuKCA"
        assertThrows<Exception> {
            verifyPresentation<IdCredential>(noneHeaderPresentation, trustedIssuers, "12345", verifier, true)
        }

        val noneHeaderSDJWTRPresentation =
            "eyJraWQiOiJJc3N1ZXJLZXkiLCJhbGciOiJFZERTQSJ9.eyJzZF9oYXNoX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJodHRwOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwiY25mIjp7IngiOiJzNmdWTElOTGNDR2hHRURUZl92MXpNbHVMWmNYajRHT1hBZlFsT1daTTlRIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImtpZCI6IkhvbGRlcktleSJ9LCJleHAiOjE2NjEwNDE1MjQsImlhdCI6MTY2MDk1NTEyNCwic2RfZGlnZXN0cyI6eyJiaXJ0aGRheSI6Ik81eTd4TFA3SUFia0J5RlVSZW5zZ3dXa0JNd1AxRVN5ZHBZUDFJTnVBQlEiLCJhZGRyZXNzIjoiODY3d2t5WVExZFM1S1N4aUZZOEFpcmZWMkQyc29UUXpVbXBVZWg3c25tbyIsIm5pY2tuYW1lcyI6IkwxTEpTVWJxTk1aMnJRdkdSdF9EWUFybU1DNld5SHF0bEpUWmM1ZWcxdmciLCJnaXZlbl9uYW1lIjoiMU84X29nQ1NiRzNxWm1NU0FPbUN4a1pzc0FMcjh1N09ad3h0czl1eWdsayIsImZhbWlseV9uYW1lIjoiZWlxbEp5UHNNdUdYeUc3OUo3cFNkNkcxWUdYdF9LdXFWeEstaG9GejJkUSIsImVtYWlsIjoiWFlUNWowMWtudVJqcG0ycnpzMktldThVQnNuWE1LeGxiZmxxSEFDR0pWZyJ9fQ.qUPdx5eU3P_0mMudJ3SNPpckTklUzFyMz5a3mhu59k6NaUNLC22znYprZSX-9rUKXeL5rKudmBCm2LjmL_YwDQ.eyJhbGciOiAibm9uZSJ9.eyJzZF9yZWxlYXNlIjp7ImFkZHJlc3MiOiJbXCJHS1pZNDU3MF8yalZtZnhHUXR3WUNBXCIse1wic3RyZWV0X2FkZHJlc3NcIjpcIjEyMyBNYWluIFN0XCIsXCJjb3VudHJ5XCI6XCJVU1wiLFwibG9jYWxpdHlcIjpcIkFueXRvd25cIixcInJlZ2lvblwiOlwiQW55c3RhdGVcIixcInppcF9jb2RlXCI6MTIzNDU2fV0iLCJuaWNrbmFtZXMiOiJbXCJ1blRRVlVfb2NhdzdyazUxaFFkSkZ3XCIsW1wiQVwiLFwiQlwiXV0iLCJnaXZlbl9uYW1lIjoiW1wieGJvZy1kekN6ZGwxMWJwdE1udjlEUVwiLFwiQWxpY2VcIl0iLCJmYW1pbHlfbmFtZSI6IltcImtEVTh2MVpPTjRxRTh5MnZDekJuMmdcIixcIldvbmRlcmxhbmRcIl0ifSwiYXVkIjoiaHR0cDovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIiwibm9uY2UiOiIxMjM0NSJ9.csQ42IpP6Wjk6A0Yobn6HoV7ADfW-5365BKMLbtWQVh3WyEvWMGKXpE3xcB1k3NijekYLcX_oSMKXMIuc8-YCA"
        assertThrows<Exception> {
            verifyPresentation<IdCredential>(noneHeaderSDJWTRPresentation, trustedIssuers, "12345", verifier, true)
        }
    }
}