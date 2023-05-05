// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoKit
import CryptoSwift
import Foundation

public extension JWE {
    /// Decrypts a JWE-serialized message using a single recipient key.
    ///
    /// This method is a convenience wrapper around the `decrypt` method that takes an array of recipient keys.
    /// It follows the decryption process described in Section 5.2 of
    /// [RFC7516 - JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516#section-5.2).
    ///
    /// - Parameters:
    ///   - serialization: The JWE-serialized message to decrypt.
    ///   - recipientKey: The `JWK` containing the recipient's key.
    ///   - senderKey: An optional `JWK` containing the sender's key (required for ECDH-1PU). Default value is `nil`.
    ///   - sharedSymmetricKey: An optional `Data` object containing a shared symmetric key. Default value is `nil`.
    /// - Returns: The decrypted message as `Data`.
    /// - Throws: An error if the decryption process fails.
    static func decrypt(
        serialization: String,
        using recipientKey: JWK,
        from senderKey: JWK? = nil,
        sharedSymmetricKey: Data? = nil
    ) throws -> Data {
        return try decrypt(
            serialization: serialization,
            using: [recipientKey],
            from: senderKey,
            sharedSymmetricKey: sharedSymmetricKey
        )
    }

    /// Decrypts a JWE-serialized message using multiple recipient keys.
    ///
    /// This method follows the decryption process described in Section 5.2 of
    /// [RFC7516 - JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516#section-5.2).
    ///
    /// - Parameters:
    ///   - serialization: The JWE-serialized message to decrypt.
    ///   - recipientKeys: An array of `JWK` containing the recipient's keys.
    ///   - senderKey: An optional `JWK` containing the sender's key (required for ECDH-1PU). Default value is `nil`.
    ///   - sharedSymmetricKey: An optional `Data` object containing a shared symmetric key. Default value is `nil`.
    /// - Returns: The decrypted message as `Data`.
    /// - Throws: An error if the decryption process fails.
    static func decrypt(
        serialization: String,
        using recipientKeys: [JWK],
        from senderKey: JWK? = nil,
        sharedSymmetricKey: Data? = nil
    ) throws -> Data {
        let jwe: JWE
        do {
            jwe = try .init(compactSerialization: serialization)
        } catch {
            jwe = try .init(jsonSerialization: serialization)
        }
        return try jwe.decrypt(
            using: recipientKeys,
            from: senderKey,
            sharedSymmetricKey: sharedSymmetricKey
        )
    }

    /// Decrypts a JWE message using a single recipient key.
    ///
    /// This method is a convenience wrapper around the `decrypt` method that takes an array of recipient keys.
    /// It follows the decryption process described in Section 5.2 of
    /// [RFC7516 - JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516#section-5.2).
    ///
    /// - Parameters:
    ///   - recipientKey: The `JWK` containing the recipient's key.
    ///   - senderKey: An optional `JWK` containing the sender's key (required for ECDH-1PU). Default value is `nil`.
    ///   - sharedSymmetricKey: An optional `Data` object containing a shared symmetric key. Default value is `nil`.
    /// - Returns: The decrypted message as `Data`.
    /// - Throws: An error if the decryption process fails.
    func decrypt(
        using recipientKey: JWK,
        from senderKey: JWK? = nil,
        sharedSymmetricKey: Data? = nil
    ) throws -> Data {
        return try decrypt(
            using: [recipientKey],
            from: senderKey,
            sharedSymmetricKey: sharedSymmetricKey
        )
    }

    /// Decrypts a JWE message using multiple recipient keys.
    ///
    /// This method follows the decryption process described in Section 5.2 of
    /// [RFC7516 - JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516#section-5.2).
    ///
    /// - Parameters:
    ///   - recipientKeys: An array of `JWK` containing the recipient's keys.
    ///   - senderKey: An optional `JWK` containing the sender's key (required for ECDH-1PU). Default value is `nil`.
    ///   - sharedSymmetricKey: An optional `Data` object containing a shared symmetric key. Default value is `nil`.
    /// - Returns: The decrypted message as `Data`.
    /// - Throws: An error if the decryption process fails.
    func decrypt(
        using recipientKeys: [JWK],
        from senderKey: JWK? = nil,
        sharedSymmetricKey: Data? = nil
    ) throws -> Data {
        let jwe = self
        var contentEncryptionKeyForRecipient = [Recipient: Data]()

        for recipient in jwe.recipients ?? [] {
            // 4. Compute JOSE header
            let joseHeader = JWE.computeJOSEHeader(from: [
                recipient.header ?? .init(),
                jwe.sharedUnprotectedHeader ?? .init(),
                jwe.protectedHeader ?? .init(),
            ])

            // 6. Determine the Key Management Mode employed by the algorithm specified by the "alg" (algorithm) Header Parameter.
            guard let keyManagementAlgorithm = joseHeader.algorithm else {
                throw JWE.Error.missingKeyManagementAlgorithm
            }

            // 7. Verify that the JWE uses a key known to the recipient.
            guard let recipientKey = recipientKeys.first(where: { $0.keyID == joseHeader.keyID }) else {
                throw JWE.Error.recipientNotFound
            }

            var contentEncryptionKey = Data()

            // 8. When Direct Key Agreement or Key Agreement with Key Wrapping are employed, use the key agreement algorithm to compute the value of the agreed upon key.

            var agreedUponKey: Data?

            if keyManagementAlgorithm.mode == .directKeyAgreement ||
                keyManagementAlgorithm.mode == .keyAgreementWithKeyWrapping
            {
                agreedUponKey = try JWE.recipientComputeAgreedUponKey(
                    to: recipientKey,
                    from: senderKey,
                    joseHeader: joseHeader
                )

                // When Direct Key Agreement is employed, let the CEK be the agreed upon key.
                if keyManagementAlgorithm.mode == .directKeyAgreement {
                    contentEncryptionKey = agreedUponKey.unsafelyUnwrapped
                }
            }

            // 9. When Key Wrapping, Key Encryption, or Key Agreement with Key Wrapping are employed, decrypt the JWE Encrypted Key to produce the CEK.
            if keyManagementAlgorithm.mode == .keyWrapping ||
                keyManagementAlgorithm.mode == .keyEncryption ||
                keyManagementAlgorithm.mode == .keyAgreementWithKeyWrapping
            {
                // When Key Agreement with Key Wrapping is employed, the agreed upon key will be used to decrypt the JWE Encrypted Key.
                let keyEncryptionKey: JWK?
                if let agreedUponKey {
                    keyEncryptionKey = .init(keyType: .octetSequence, key: agreedUponKey)
                } else {
                    keyEncryptionKey = recipientKey
                }
                contentEncryptionKey = try JWE.decryptEncryptedKey(
                    recipient.encryptedKey,
                    using: keyEncryptionKey,
                    joseHeader: joseHeader
                )
            }

            // 10. When Direct Key Agreement or Direct Encryption are employed, verify that the JWE Encrypted Key value is an empty octet sequence.
            if keyManagementAlgorithm.mode == .directKeyAgreement ||
                keyManagementAlgorithm.mode == .directEncryption
            {
                guard
                    recipient.encryptedKey == nil || (recipient.encryptedKey?.isEmpty ?? true)
                else {
                    throw JWE.Error.invalidEncryptedKey
                }
            }

            // 11. When Direct Encryption is employed, let the CEK be the shared symmetric key.
            if keyManagementAlgorithm.mode == .directEncryption {
                guard let sharedSymmetricKey = sharedSymmetricKey else {
                    throw JWE.Error.missingSharedSymmetricKey
                }
                contentEncryptionKey = sharedSymmetricKey
            }

            // The CEK MUST have a length equal to that required for the content encryption algorithm.
            guard let encryptionAlgorithm = joseHeader.encryptionAlgorithm else {
                throw JWE.Error.missingKeyManagementAlgorithm
            }
            guard contentEncryptionKey.count * 8 == encryptionAlgorithm.keySizeInBits else {
                throw Error.invalidContentEncryptionKeyBitCount(
                    contentEncryptionKey.count * 8,
                    expected: encryptionAlgorithm.keySizeInBits
                )
            }

            // 12. Record whether the CEK could be successfully determined for this recipient or not.
            contentEncryptionKeyForRecipient[recipient] = contentEncryptionKey
        }

        // 14. Compute the Encoded Protected Header value BASE64URL(UTF8(JWE Protected Header)).  If the JWE Protected Header is not present (which can only happen when using the JWE JSON Serialization and no "protected" member is present), let this value be the empty string.
        var encodedProtectedHeader = jwe.encodedProtectedHeader
        if encodedProtectedHeader == nil {
            if let protectedHeader = jwe.protectedHeader {
                let encoder = JSONEncoder()
                encoder.outputFormatting = .withoutEscapingSlashes
                encodedProtectedHeader = try Base64URL.encode(encoder.encode(protectedHeader))
            } else {
                encodedProtectedHeader = ""
            }
        }

        // 15. Let the Additional Authenticated Data encryption parameter be ASCII(Encoded Protected Header).  However, if a JWE AAD value is present (which can only be the case when using the JWE JSON Serialization), instead let the Additional Authenticated Data encryption parameter be ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD)).
        let aadEncryptionParameter: Data
        if let additionalAuthenticatedData = jwe.additionalAuthenticatedData {
            aadEncryptionParameter = [
                encodedProtectedHeader ?? .init(),
                Base64URL.encode(additionalAuthenticatedData),
            ].joined(separator: ".").data(using: .ascii) ?? .init()
        } else {
            aadEncryptionParameter = encodedProtectedHeader?.data(using: .ascii) ?? .init()
        }

        // 16. Decrypt the JWE Ciphertext using the CEK, the JWE Initialization Vector, the Additional Authenticated Data value, and the JWE Authentication Tag (which is the Authentication Tag input to the calculation) using the specified content encryption algorithm, returning the decrypted plaintext and validating the JWE Authentication Tag in the manner specified for the algorithm, rejecting the input without emitting any decrypted output if the JWE Authentication Tag is incorrect.

        for recipient in jwe.recipients ?? [] {
            guard let contentEncryptionKey = contentEncryptionKeyForRecipient[recipient] else {
                continue
            }
            guard let ciphertext = jwe.ciphertext else {
                throw JWE.Error.missingCiphertext
            }
            guard let initializationVector = jwe.initializationVector else {
                throw JWE.Error.missingInitializationVector
            }
            guard let authenticationTag = jwe.authenticationTag else {
                throw JWE.Error.missingAuthenticationTag
            }

            // 4. Compute JOSE header
            let joseHeader = JWE.computeJOSEHeader(from: [
                recipient.header ?? .init(),
                jwe.sharedUnprotectedHeader ?? .init(),
                jwe.protectedHeader ?? .init(),
            ])

            guard let contentEncryptionAlgorithm = joseHeader.encryptionAlgorithm else {
                throw JWE.Error.missingContentEncryptionAlgorithm
            }

            var plaintext = try JWE.decrypt(
                ciphertext: ciphertext,
                using: contentEncryptionKey,
                initializationVector: initializationVector,
                additionalAuthenticatedData: aadEncryptionParameter,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                authenticationTag: authenticationTag
            )

            // 17. If a "zip" parameter was included, uncompress the decrypted plaintext using the specified compression algorithm.
            if joseHeader.compressionAlgorithm == .deflate {
                plaintext = try (plaintext as NSData).decompressed(using: .zlib) as Data
            }

            // Stop and return the first successfully decrypted plaintext.
            return plaintext
        }

        throw JWE.Error.decryptionFailed
    }

    /// Computes the agreed-upon key using the specified recipient and sender keys, as well as the JOSE header.
    ///
    /// - Parameters:
    ///   - recipientKey: The recipient's `JWK` key.
    ///   - senderKey: An optional `JWK` containing the sender's key (required for ECDH-1PU). Default value is `nil`.
    ///   - joseHeader: The `JOSEHeader` object containing all JOSE header parameters.
    /// - Returns: The agreed-upon key as `Data`.
    /// - Throws: An error if the key agreement process fails, such as missing key management algorithm, missing ephemeral key, missing sender key, or an algorithm is not supported.
    internal static func recipientComputeAgreedUponKey(
        to recipientKey: JWK,
        from senderKey: JWK? = nil,
        joseHeader: JOSEHeader
    ) throws -> Data {
        guard let alg = joseHeader.algorithm else {
            throw JWE.Error.missingKeyManagementAlgorithm
        }
        guard let ephemeralPublicKey = joseHeader.ephemeralPublicKey else {
            throw JWE.Error.missingEphemeralKey
        }
        var sharedSecret: Data
        switch alg {
        case .ecdh1PU, .ecdh1PUA128KW, .ecdh1PUA192KW, .ecdh1PUA256KW:
            guard let senderKey else {
                throw JWE.Error.missingSenderKey
            }
            let ze = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
            let zs = try recipientKey.sharedSecretFromKeyAgreement(with: senderKey)
            sharedSecret = ze + zs
        case .ecdhES, .ecdhESA128KW, .ecdhESA192KW, .ecdhESA256KW:
            sharedSecret = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        default:
            throw JWE.Error.notSupported
        }

        let agreedUponKey = try JWE.deriveKey(from: sharedSecret, joseHeader: joseHeader)

        return agreedUponKey
    }

    /// Decrypts the encrypted key.
    ///
    /// - Parameters:
    ///   - encryptedKey: A `Data` object containing the encrypted key.
    ///   - jwk: An optional `JWK` object containing the key encryption key.
    ///   - joseHeader: The `JOSEHeader` object containing the necessary JOSE header parameters.
    /// - Returns: The decrypted key as `Data`.
    /// - Throws: An error if the decryption process fails, such as missing encrypted content encryption key, missing key management algorithm, missing key encryption key, incompatible keys, or an algorithm is not supported.
    internal static func decryptEncryptedKey(
        _ encryptedKey: Data?,
        using jwk: JWK?,
        joseHeader: JOSEHeader
    ) throws -> Data {
        guard let encryptedKey = encryptedKey else {
            throw JWE.Error.missingEncryptedContentEncryptionKey
        }
        guard let algorithm = joseHeader.algorithm else {
            throw JWE.Error.missingKeyManagementAlgorithm
        }
        guard let jwk else {
            throw JWE.Error.missingKeyEncryptionKey
        }

        let contentEncryptionKey: Data

        if algorithm.usesAESKeyWrapping && !algorithm.usesPBES2KeyEncryption {
            guard let keyEncryptionKey = jwk.key else {
                throw JWE.Error.missingKeyEncryptionKey
            }
            contentEncryptionKey = try AES.KeyWrap.unwrap(
                encryptedKey,
                using: .init(data: keyEncryptionKey)
            ).withUnsafeBytes { Data($0) }
        } else if algorithm.usesAESGCMKeyWrapping {
            // See https://www.rfc-editor.org/rfc/rfc7518#section-4.7
            guard let keyEncryptionKey = jwk.key else {
                throw JWE.Error.missingKeyEncryptionKey
            }
            guard let initializationVector = joseHeader.initializationVector else {
                throw JWE.Error.missingInitializationVector
            }
            guard let authenticationTag = joseHeader.authenticationTag else {
                throw JWE.Error.missingAuthenticationTag
            }
            contentEncryptionKey = try AES.GCM.open(
                .init(
                    nonce: .init(data: initializationVector),
                    ciphertext: encryptedKey,
                    tag: authenticationTag
                ),
                using: .init(data: keyEncryptionKey),
                authenticating: Data()
            )
        } else if algorithm.usesRSAKeyEncryption {
            guard jwk.keyType == .rsa else {
                throw JWE.Error.incompatibleKeys
            }
            guard let n = jwk.n else {
                throw JWK.Error.missingNComponent
            }
            guard let e = jwk.e else {
                throw JWK.Error.missingEComponent
            }
            guard let d = jwk.d else {
                throw JWK.Error.missingDComponent
            }
            guard let p = jwk.p, let q = jwk.q else {
                throw JWK.Error.missingPrimesComponent
            }
            let rsaPrivateKey = CryptoSwift.RSA(
                n: BigUInteger(n),
                e: BigUInteger(e),
                d: BigUInteger(d),
                p: BigUInteger(p),
                q: BigUInteger(q)
            )
            let derEncodedRSAPrivateKey = try rsaPrivateKey.externalRepresentation()
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: n.count * 8,
                kSecAttrIsPermanent as String: false,
            ]
            var error: Unmanaged<CFError>?
            guard let rsaSecKey = SecKeyCreateWithData(
                derEncodedRSAPrivateKey as CFData,
                attributes as CFDictionary,
                &error
            ) else {
                throw JWE.Error.incompatibleKeys
            }
            var secKeyAlgorithm: SecKeyAlgorithm
            switch joseHeader.algorithm {
            case .rsa1_5:
                secKeyAlgorithm = .rsaEncryptionPKCS1
            case .rsaOAEP:
                secKeyAlgorithm = .rsaEncryptionOAEPSHA1
            case .rsaOAEP256:
                secKeyAlgorithm = .rsaEncryptionOAEPSHA256
            default:
                throw JWE.Error.notSupported
            }
            var decryptionError: Unmanaged<CFError>?
            guard
                let plaintext = SecKeyCreateDecryptedData(
                    rsaSecKey,
                    secKeyAlgorithm,
                    encryptedKey as CFData,
                    &decryptionError
                )
            else {
                throw JWE.Error.rsaEncryptionFailure
            }
            contentEncryptionKey = plaintext as Data
        } else if algorithm.usesPBES2KeyEncryption {
            // See https://www.rfc-editor.org/rfc/rfc7518#section-4.8
            guard let keyEncryptionKey = jwk.key else {
                throw JWE.Error.missingKeyEncryptionKey
            }
            guard let saltInput = joseHeader.pbes2SaltInput else {
                throw JWE.Error.missingPBES2SaltInput
            }
            guard let count = joseHeader.pbes2Count else {
                throw JWE.Error.missingPBES2Count
            }
            let keyLength: Int
            let hmacVariant: CryptoSwift.HMAC.Variant
            switch algorithm {
            case .pbes2HS256A128KW:
                keyLength = 16
                hmacVariant = .sha2(.sha256)
            case .pbes2HS384A192KW:
                keyLength = 24
                hmacVariant = .sha2(.sha384)
            case .pbes2HS512A256KW:
                keyLength = 32
                hmacVariant = .sha2(.sha512)
            default:
                throw JWE.Error.notSupported
            }
            let derivedKey = try Data(PKCS5.PBKDF2(
                password: Array(keyEncryptionKey),
                salt: Array(algorithm.rawValue.data(using: .utf8) ?? .init()) + [0x00] + saltInput,
                iterations: count,
                keyLength: keyLength,
                variant: hmacVariant
            ).calculate())
            contentEncryptionKey = try AES.KeyWrap.unwrap(
                encryptedKey,
                using: .init(data: derivedKey)
            ).withUnsafeBytes { Data($0) }
        } else {
            throw JWE.Error.notSupported
        }

        return contentEncryptionKey
    }

    /// Decrypts the ciphertext using the provided parameters.
    ///
    /// - Parameters:
    ///   - ciphertext: A `Data` object containing the ciphertext to be decrypted.
    ///   - contentEncryptionKey: A `Data` object containing the content encryption key.
    ///   - initializationVector: A `Data` object containing the initialization vector.
    ///   - additionalAuthenticatedData: A `Data` object containing the additional authenticated data.
    ///   - contentEncryptionAlgorithm: The `JOSEHeader.ContentEncryptionAlgorithm` used for encryption.
    ///   - authenticationTag: A `Data` object containing the authentication tag.
    /// - Returns: The decrypted plaintext as `Data`.
    /// - Throws: An error if the decryption process fails, such as authentication failure.
    internal static func decrypt(
        ciphertext: Data,
        using contentEncryptionKey: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data,
        contentEncryptionAlgorithm: JOSEHeader.ContentEncryptionAlgorithm,
        authenticationTag: Data
    ) throws -> Data {
        let plaintext: Data

        switch contentEncryptionAlgorithm {
        case .a128CBCHS256, .a192CBCHS384, .a256CBCHS512:
            // See https://www.rfc-editor.org/rfc/rfc7518#section-5.2.2.2
            let contentEncryptionKeyHalfLength = contentEncryptionKey.count / 2
            let macKey = contentEncryptionKey.prefix(contentEncryptionKeyHalfLength)
            let encKey = contentEncryptionKey.suffix(contentEncryptionKeyHalfLength)

            let al = UInt64(additionalAuthenticatedData.count * 8).bigEndian.dataRepresentation
            let dataToAuthenticate = additionalAuthenticatedData + initializationVector + ciphertext + al

            let authenticationTagLength: Int
            let hmacVariant: CryptoSwift.HMAC.Variant
            switch contentEncryptionAlgorithm {
            case .a128CBCHS256:
                authenticationTagLength = 16
                hmacVariant = .sha2(.sha256)
            case .a192CBCHS384:
                authenticationTagLength = 24
                hmacVariant = .sha2(.sha384)
            case .a256CBCHS512:
                authenticationTagLength = 32
                hmacVariant = .sha2(.sha512)
            default:
                throw JWE.Error.notSupported
            }

            let computedFullAuthenticationTag = try HMAC(
                key: Array(macKey),
                variant: hmacVariant
            ).authenticate(Array(dataToAuthenticate))

            let computedAuthenticationTag = computedFullAuthenticationTag.prefix(authenticationTagLength)

            guard authenticationTag == Data(computedAuthenticationTag) else {
                throw JWE.Error.authenticationFailure
            }

            plaintext = try Data(AES(
                key: encKey.bytes,
                blockMode: CBC(iv: initializationVector.bytes),
                padding: .pkcs7
            ).decrypt(Array(ciphertext)))

        case .a128GCM, .a192GCM, .a256GCM:
            plaintext = try AES.GCM.open(
                .init(
                    nonce: .init(data: initializationVector),
                    ciphertext: ciphertext,
                    tag: authenticationTag
                ),
                using: .init(data: contentEncryptionKey),
                authenticating: additionalAuthenticatedData
            )
        }

        return plaintext
    }
}
