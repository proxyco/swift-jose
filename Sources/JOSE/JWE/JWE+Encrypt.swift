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
    /// Encrypts a plaintext message to one recipient using the specified parameters.
    ///
    /// This method follows the encryption process described in Section 5.1 of
    /// [RFC7516 - JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516#section-5.1)
    ///
    /// - Parameters:
    ///   - plaintext: A `Data` object containing the plaintext to be encrypted.
    ///   - recipientKey: A `JWK` object containing the recipient's key.
    ///   - senderKey: An optional `JWK` object containing the sender's key (required for ECDH-1PU).
    ///   - protectedHeader: An optional `JOSEHeader` object containing the protected header.
    ///   - encodedProtectedHeader: An optional `String` containing the encoded protected header.
    ///   - sharedUnprotectedHeader: An optional `JOSEHeader` object containing the shared unprotected header.
    ///   - sharedSymmetricKey: An optional `Data` object containing a shared symmetric key.
    ///   - initializationVector: An optional `Data` object containing the initialization vector.
    ///   - additionalAuthenticatedData: An optional `Data` object containing the additional authenticated data.
    ///   - jsonEncoder: An optional `JSONEncoder` object to customize JSON encoding.
    /// - Returns: The encrypted JWE message as a `String`.
    /// - Throws: An error if the encryption process fails.
    static func encrypt(
        plaintext: Data,
        to recipientKey: JWK,
        from senderKey: JWK? = nil,
        protectedHeader: JOSEHeader? = nil,
        encodedProtectedHeader: String? = nil,
        sharedUnprotectedHeader: JOSEHeader? = nil,
        contentEncryptionKey sharedSymmetricKey: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticatedData: Data? = nil,
        jsonEncoder: JSONEncoder? = nil
    ) throws -> String {
        return try encrypt(
            plaintext: plaintext,
            to: [recipientKey],
            from: senderKey,
            protectedHeader: protectedHeader,
            encodedProtectedHeader: encodedProtectedHeader,
            sharedUnprotectedHeader: sharedUnprotectedHeader,
            contentEncryptionKey: sharedSymmetricKey,
            initializationVector: initializationVector,
            additionalAuthenticatedData: additionalAuthenticatedData,
            jsonEncoder: jsonEncoder
        )
    }

    /// Encrypts a plaintext message to one or multiple recipients using the specified parameters.
    ///
    /// This method follows the encryption process described in Section 5.1 of
    /// [RFC7516 - JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516#section-5.1)
    /// - Parameters:
    ///   - plaintext: A `Data` object containing the plaintext to be encrypted.
    ///   - recipientKeys: An array of `JWK` objects containing the recipients' keys.
    ///   - senderKey: An optional `JWK` object containing the sender's key (required for ECDH-1PU).
    ///   - protectedHeader: An optional `JOSEHeader` object containing the protected header.
    ///   - encodedProtectedHeader: An optional `String` containing the encoded protected header.
    ///   - sharedUnprotectedHeader: An optional `JOSEHeader` object containing the shared unprotected header.
    ///   - sharedSymmetricKey: An optional `Data` object containing a shared symmetric key.
    ///   - initializationVector: An optional `Data` object containing the initialization vector.
    ///   - additionalAuthenticatedData: An optional `Data` object containing the additional authenticated data.
    ///   - jsonEncoder: An optional `JSONEncoder` object to customize JSON encoding.
    /// - Returns: The encrypted JWE message as a `String`.
    /// - Throws: An error if the encryption process fails.
    static func encrypt(
        plaintext: Data,
        to recipientKeys: [JWK],
        from senderKey: JWK? = nil,
        protectedHeader: JOSEHeader? = nil,
        encodedProtectedHeader: String? = nil,
        sharedUnprotectedHeader: JOSEHeader? = nil,
        contentEncryptionKey sharedSymmetricKey: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticatedData: Data? = nil,
        jsonEncoder: JSONEncoder? = nil
    ) throws -> String {
        var jwe = try JWE(
            protectedHeader: protectedHeader,
            encodedProtectedHeader: encodedProtectedHeader,
            sharedUnprotectedHeader: sharedUnprotectedHeader,
            recipients: recipientKeys.map { .init(jwk: $0) },
            contentEncryptionKey: sharedSymmetricKey,
            initializationVector: initializationVector,
            additionalAuthenticatedData: additionalAuthenticatedData
        )
        return try jwe.encrypt(
            plaintext: plaintext,
            from: senderKey,
            jsonEncoder: jsonEncoder
        )
    }

    /// Encrypts a plaintext message to one or multiple recipients using the specified parameters.
    ///
    /// This method follows the encryption process described in Section 5.1 of
    /// [RFC7516 - JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516#section-5.1)
    ///
    /// - Parameters:
    ///   - plaintext: The data to be encrypted.
    ///   - recipients: The list of recipients for the encrypted message.
    ///   - senderKey: The sender's key used in key agreement algorithms.
    ///   - protectedHeader: The JWE protected header.
    ///   - encodedProtectedHeader: The Base64URL-encoded protected header.
    ///   - sharedUnprotectedHeader: The JWE shared unprotected header.
    ///   - sharedSymmetricKey: The shared symmetric key used in direct encryption.
    ///   - initializationVector: The initialization vector used for content encryption.
    ///   - additionalAuthenticatedData: Additional data to be authenticated with the message.
    ///   - jsonEncoder: A custom JSON encoder for encoding the JWE.
    /// - Returns: A JWE serialized string in compact or JSON format.
    static func encrypt(
        plaintext: Data,
        to recipients: [Recipient],
        from senderKey: JWK? = nil,
        protectedHeader: JOSEHeader?,
        encodedProtectedHeader: String? = nil,
        sharedUnprotectedHeader: JOSEHeader? = nil,
        contentEncryptionKey sharedSymmetricKey: Data? = nil,
        initializationVector: Data? = nil,
        additionalAuthenticatedData: Data? = nil,
        jsonEncoder: JSONEncoder? = nil
    ) throws -> String {
        var jwe = try JWE(
            protectedHeader: protectedHeader,
            encodedProtectedHeader: encodedProtectedHeader,
            sharedUnprotectedHeader: sharedUnprotectedHeader,
            recipients: recipients,
            contentEncryptionKey: sharedSymmetricKey,
            initializationVector: initializationVector,
            additionalAuthenticatedData: additionalAuthenticatedData
        )
        let serialization = try jwe.encrypt(
            plaintext: plaintext,
            from: senderKey,
            jsonEncoder: jsonEncoder
        )
        return serialization
    }

    /// Encrypts a plaintext message to one or multiple recipients using the specified parameters.
    ///
    /// This method follows the encryption process described in Section 5.1 of
    /// [RFC7516 - JSON Web Encryption (JWE)](https://www.rfc-editor.org/rfc/rfc7516#section-5.1)
    ///
    /// - Parameters:
    ///   - plaintext: The data to be encrypted.
    ///   - senderKey: The sender's key used in key agreement algorithms.
    ///   - jsonEncoder: A custom JSON encoder for encoding the JWE.
    /// - Returns: A JWE serialized string in compact or JSON format.
    mutating func encrypt(
        plaintext: Data,
        from senderKey: JWK? = nil,
        jsonEncoder: JSONEncoder? = nil
    ) throws -> String {
        var contentEncryptionKey = self.contentEncryptionKey

        // 2-6. Determine the Content Encryption Key (CEK) and encrypted CEK for each recipient
        recipients = try recipients?.map {
            var recipient = $0

            // 12. Create the JSON object(s) containing the desired set of Header Parameters, which together comprise the JOSE Header: one or more of the JWE Protected Header, the JWE Shared Unprotected Header, and the JWE Per-Recipient Unprotected Header.
            let joseHeader = JWE.computeJOSEHeader(from: [
                recipient.header ?? .init(),
                sharedUnprotectedHeader ?? .init(),
                protectedHeader ?? .init(),
            ])

            guard let keyManagementAlgorithm = joseHeader.algorithm else {
                throw JWE.Error.missingKeyManagementAlgorithm
            }

            guard let contentEncryptionAlgorithm = joseHeader.encryptionAlgorithm else {
                throw JWE.Error.missingContentEncryptionAlgorithm
            }

            // 2. When Key Wrapping, Key Encryption, or Key Agreement with Key Wrapping are employed, generate a random CEK value.
            if keyManagementAlgorithm.mode == .keyWrapping ||
                keyManagementAlgorithm.mode == .keyEncryption ||
                keyManagementAlgorithm.mode == .keyAgreementWithKeyWrapping
            {
                // Only generate CEK if needed.
                if contentEncryptionKey == nil {
                    contentEncryptionKey = .random(count: contentEncryptionAlgorithm.keySizeInBits / 8)
                }
            }

            // 3. When Direct Key Agreement or Key Agreement with Key Wrapping are employed, use the key agreement algorithm to compute the value of the agreed upon key.
            var agreedUponKey: Data?
            if keyManagementAlgorithm.mode == .directKeyAgreement ||
                keyManagementAlgorithm.mode == .keyAgreementWithKeyWrapping
            {
                guard let recipientKey = recipient.jwk else {
                    throw JWE.Error.missingRecipientKey
                }
                agreedUponKey = try JWE.senderComputeAgreedUponKey(
                    to: recipientKey,
                    from: senderKey,
                    protectedHeader: &self.protectedHeader,
                    joseHeader: joseHeader
                )
                // When Direct Key Agreement is employed, let the CEK be the agreed upon key.
                if keyManagementAlgorithm.mode == .directKeyAgreement {
                    contentEncryptionKey = agreedUponKey
                }
            }

            // 4. When Key Wrapping, Key Encryption, or Key Agreement with Key Wrapping are employed, encrypt the CEK to the recipient and let the result be the JWE Encrypted Key.
            if keyManagementAlgorithm.mode == .keyWrapping ||
                keyManagementAlgorithm.mode == .keyEncryption ||
                keyManagementAlgorithm.mode == .keyAgreementWithKeyWrapping
            {
                let keyEncryptionKey: JWK?
                if let agreedUponKey {
                    keyEncryptionKey = .init(keyType: .octetSequence, key: agreedUponKey)
                } else {
                    keyEncryptionKey = recipient.jwk
                }
                recipient.encryptedKey = try JWE.encryptContentEncryptionKey(
                    contentEncryptionKey,
                    using: keyEncryptionKey,
                    protectedHeader: &self.protectedHeader,
                    joseHeader: joseHeader
                )
            }

            // 5. When Direct Key Agreement or Direct Encryption are employed, let the JWE Encrypted Key be the empty octet sequence.
            if keyManagementAlgorithm.mode == .directKeyAgreement ||
                keyManagementAlgorithm.mode == .directEncryption
            {
                recipient.encryptedKey = nil
            }

            // 6. When Direct Encryption is employed, let the CEK be the shared symmetric key.
            if keyManagementAlgorithm.mode == .directEncryption {
                contentEncryptionKey = self.contentEncryptionKey
            }

            // The CEK MUST have a length equal to that required for the content encryption algorithm.
            if let contentEncryptionKey = contentEncryptionKey {
                guard contentEncryptionKey.count * 8 == contentEncryptionAlgorithm.keySizeInBits else {
                    throw Error.invalidContentEncryptionKeyBitCount(
                        contentEncryptionKey.count * 8,
                        expected: contentEncryptionAlgorithm.keySizeInBits
                    )
                }
            }

            return recipient
        }

        let joseHeader = JWE.computeJOSEHeader(from: [
            recipients?.first?.header ?? .init(),
            sharedUnprotectedHeader ?? .init(),
            protectedHeader ?? .init(),
        ])
        guard let contentEncryptionAlgorithm = joseHeader.encryptionAlgorithm else {
            throw JWE.Error.missingContentEncryptionAlgorithm
        }

        // 9. Generate a random JWE Initialization Vector of the correct size for the content encryption algorithm (if required for the algorithm); otherwise, let the JWE Initialization Vector be the empty octet sequence.
        // Generate initialization vector, if needed
        var initializationVector = initializationVector
        if initializationVector == nil {
            initializationVector = .random(count: contentEncryptionAlgorithm.initializationVectorSizeInBits / 8)
        }

        // 11. If a "zip" parameter was included, compress the plaintext using the specified compression algorithm and let M be the octet sequence representing the compressed plaintext; otherwise, let M be the octet sequence representing the plaintext.
        var m = plaintext
        if protectedHeader?.compressionAlgorithm == .deflate {
            m = try (m as NSData).compressed(using: .zlib) as Data
        }

        // 14. Let the Additional Authenticated Data encryption parameter be ASCII(Encoded Protected Header).  However, if a JWE AAD value is present (which can only be the case when using the JWE JSON Serialization), instead let the Additional Authenticated Data encryption parameter be ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD)).

        var encodedProtectedHeader = encodedProtectedHeader
        if encodedProtectedHeader == nil && protectedHeader != nil {
            // Ensure private part of ephemeral key is not present
            let publicKey = protectedHeader?.ephemeralPublicKey?.publicKey
            protectedHeader?.ephemeralPublicKey = publicKey
            let encoder = JSONEncoder()
            encoder.outputFormatting = .withoutEscapingSlashes
            encodedProtectedHeader = try Base64URL.encode(encoder.encode(protectedHeader))
        }
        let aadEncryptionParameter: Data
        if let additionalAuthenticatedData = additionalAuthenticatedData {
            aadEncryptionParameter = [
                encodedProtectedHeader ?? .init(),
                Base64URL.encode(additionalAuthenticatedData),
            ].joined(separator: ".").data(using: .ascii) ?? .init()
        } else {
            aadEncryptionParameter = encodedProtectedHeader?.data(using: .ascii) ?? .init()
        }

        // 15. Encrypt M using the CEK, the JWE Initialization Vector, and the Additional Authenticated Data value using the specified content encryption algorithm to create the JWE Ciphertext value and the JWE Authentication Tag (which is the Authentication Tag output from the encryption operation).

        guard let contentEncryptionKey else {
            throw JWE.Error.missingContentEncryptionKey
        }
        guard let initializationVector else {
            throw JWE.Error.missingInitializationVector
        }

        let (ciphertext, authenticationTag) = try JWE.encrypt(
            m: m,
            using: contentEncryptionKey,
            initializationVector: initializationVector,
            additionalAuthenticatedData: aadEncryptionParameter,
            contentEncryptionAlgorithm: contentEncryptionAlgorithm
        )

        let jwe = try JWE(
            protectedHeader: protectedHeader,
            encodedProtectedHeader: encodedProtectedHeader,
            sharedUnprotectedHeader: sharedUnprotectedHeader,
            recipients: recipients,
            contentEncryptionKey: contentEncryptionKey,
            initializationVector: initializationVector,
            ciphertext: ciphertext,
            authenticationTag: authenticationTag,
            additionalAuthenticatedData: additionalAuthenticatedData
        )

        if let jsonEncoder {
            return try jwe.jsonSerialization(jsonEncoder)
        } else {
            return try jwe.compactSerialization()
        }
    }

    /// Computes the agreed-upon key using the specified recipient and sender keys, as well as the JWE protected header.
    ///
    /// The protectedHeader parameter is marked as inout because it may be updated
    /// inside the function, for instance when generating an ephemeral key.
    ///
    /// - Parameters:
    ///   - recipientKey: The recipient's `JWK` key.
    ///   - senderKey: An optional `JWK` containing the sender's key (required for ECDH-1PU).
    ///   - protectedHeader: The JWE protected header parameters, which may be updated inside the function.
    ///   - joseHeader: The `JOSEHeader` object containing all JOSE header parameters.
    /// - Returns: The agreed-upon key as `Data`.
    /// - Throws: An error if the key agreement process fails.
    internal static func senderComputeAgreedUponKey(
        to recipientKey: JWK,
        from senderKey: JWK? = nil,
        protectedHeader: inout JOSEHeader?,
        joseHeader: JOSEHeader
    ) throws -> Data {
        guard let keyManagementAlgorithm = joseHeader.algorithm else {
            throw JWE.Error.missingKeyManagementAlgorithm
        }
        // Generate ephemeral key, if needed
        var ephemeralKey = joseHeader.ephemeralPublicKey
        if ephemeralKey == nil {
            ephemeralKey = try JWE.generateEphemeralKey(to: recipientKey)
            // Although the ephemeral key contains the private part at this point,
            // during serialization we will remove it.
            protectedHeader?.ephemeralPublicKey = ephemeralKey
        }
        guard let ephemeralKey else {
            throw JWE.Error.missingEphemeralKey
        }
        var sharedSecret: Data
        switch keyManagementAlgorithm {
        case .ecdh1PU, .ecdh1PUA128KW, .ecdh1PUA192KW, .ecdh1PUA256KW:
            guard let senderKey else {
                throw JWE.Error.missingSenderKey
            }
            let ze = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipientKey)
            let zs = try senderKey.sharedSecretFromKeyAgreement(with: recipientKey)
            sharedSecret = ze + zs
        case .ecdhES, .ecdhESA128KW, .ecdhESA192KW, .ecdhESA256KW:
            sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipientKey)
        default:
            throw JWE.Error.notSupported
        }

        let agreedUponKey = try JWE.deriveKey(from: sharedSecret, joseHeader: joseHeader)

        return agreedUponKey
    }

    /// Encrypts the given content encryption key using the specified JSON Web Key (JWK) and updates the protected header with necessary values.
    /// - Parameters:
    ///   - contentEncryptionKey: The content encryption key to be encrypted.
    ///   - jwk: The JSON Web Key used for encryption.
    ///   - protectedHeader: The protected header to be updated with necessary values.
    ///   - joseHeader: The JOSE header containing necessary information for encryption.
    /// - Throws: An error if encryption fails or required information is missing.
    /// - Returns: The encrypted content encryption key as Data.
    internal static func encryptContentEncryptionKey(
        _ contentEncryptionKey: Data?,
        using jwk: JWK?,
        protectedHeader: inout JOSEHeader?,
        joseHeader: JOSEHeader
    ) throws -> Data? {
        guard let contentEncryptionKey = contentEncryptionKey else {
            throw JWE.Error.missingEncryptedContentEncryptionKey
        }
        guard let algorithm = joseHeader.algorithm else {
            throw JWE.Error.missingKeyManagementAlgorithm
        }
        guard let jwk = jwk else {
            throw JWE.Error.missingKeyEncryptionKey
        }

        let encryptedKey: Data

        if algorithm.usesAESKeyWrapping, !algorithm.usesPBES2KeyEncryption {
            guard let keyEncryptionKey = jwk.key else {
                throw JWE.Error.missingKeyEncryptionKey
            }
            encryptedKey = try AES.KeyWrap.wrap(
                .init(data: contentEncryptionKey),
                using: .init(data: keyEncryptionKey)
            )
        } else if algorithm.usesAESGCMKeyWrapping {
            // See https://www.rfc-editor.org/rfc/rfc7518#section-4.7
            guard let keyEncryptionKey = jwk.key else {
                throw JWE.Error.missingKeyEncryptionKey
            }
            var initializationVector = joseHeader.initializationVector
            let initializationVectorSizeInBits = 96
            if initializationVector == nil {
                initializationVector = .random(count: initializationVectorSizeInBits)
                protectedHeader?.initializationVector = initializationVector
            }
            guard let initializationVector = initializationVector else {
                throw JWE.Error.missingInitializationVector
            }
            guard initializationVector.count * 8 == initializationVectorSizeInBits else {
                throw JWE.Error.invalidInitializationVectorBitCount(
                    initializationVector.count * 8,
                    expected: initializationVectorSizeInBits
                )
            }
            let sealedBox = try AES.GCM.seal(
                contentEncryptionKey,
                using: .init(data: keyEncryptionKey),
                nonce: .init(data: initializationVector),
                authenticating: Data()
            )
            protectedHeader?.authenticationTag = sealedBox.tag
            encryptedKey = sealedBox.ciphertext
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
            let rsaPublicKey = CryptoSwift.RSA(n: BigUInteger(n), e: BigUInteger(e))
            let derEncodedRSAPublicKey = try rsaPublicKey.publicKeyExternalRepresentation()
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: n.count * 8,
                kSecAttrIsPermanent as String: false,
            ]
            var error: Unmanaged<CFError>?
            guard let rsaSecKey = SecKeyCreateWithData(
                derEncodedRSAPublicKey as CFData,
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
            var encryptionError: Unmanaged<CFError>?
            guard
                let ciphertext = SecKeyCreateEncryptedData(
                    rsaSecKey,
                    secKeyAlgorithm,
                    contentEncryptionKey as CFData,
                    &encryptionError
                )
            else {
                throw JWE.Error.rsaEncryptionFailure
            }
            encryptedKey = ciphertext as Data
        } else if algorithm.usesPBES2KeyEncryption {
            // See https://www.rfc-editor.org/rfc/rfc7518#section-4.8
            guard let keyEncryptionKey = jwk.key else {
                throw JWE.Error.missingKeyEncryptionKey
            }
            var saltInput = joseHeader.pbes2SaltInput
            if saltInput == nil {
                saltInput = .random(count: 8)
                protectedHeader?.pbes2SaltInput = saltInput
            }
            guard let saltInput else {
                throw JWE.Error.missingPBES2SaltInput
            }
            var count = joseHeader.pbes2Count
            if count == nil {
                count = 1000
                protectedHeader?.pbes2Count = count
            }
            guard let count else {
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
            let salt = Array(algorithm.rawValue.data(using: .utf8) ?? .init()) + [0x00] + saltInput
            let derivedKey = try Data(PKCS5.PBKDF2(
                password: Array(keyEncryptionKey),
                salt: salt,
                iterations: count,
                keyLength: keyLength,
                variant: hmacVariant
            ).calculate())
            encryptedKey = try AES.KeyWrap.wrap(
                .init(data: contentEncryptionKey),
                using: .init(data: derivedKey)
            )
        } else {
            throw JWE.Error.notSupported
        }

        return encryptedKey
    }

    /// Encrypts the given data using the specified content encryption key, initialization vector, additional authenticated data, and content encryption algorithm.
    ///
    /// - Parameters:
    ///   - m: The `Data` object to encrypt.
    ///   - contentEncryptionKey: The content encryption key as `Data`.
    ///   - initializationVector: The initialization vector as `Data`.
    ///   - additionalAuthenticatedData: The additional authenticated data as `Data`.
    ///   - contentEncryptionAlgorithm: The `JOSEHeader.ContentEncryptionAlgorithm` to use for encryption.
    /// - Returns: A tuple containing the encrypted data and authentication tag as `Data`.
    /// - Throws: An error if the encryption process fails.
    internal static func encrypt(
        m: Data,
        using contentEncryptionKey: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data,
        contentEncryptionAlgorithm: JOSEHeader.ContentEncryptionAlgorithm
    ) throws -> (Data, Data) {
        guard initializationVector.count * 8 == contentEncryptionAlgorithm.initializationVectorSizeInBits else {
            throw JWE.Error.invalidInitializationVectorBitCount(
                initializationVector.count * 8,
                expected: contentEncryptionAlgorithm.initializationVectorSizeInBits
            )
        }

        let resultCiphertext: Data
        let resultAuthenticationTag: Data

        switch contentEncryptionAlgorithm {
        case .a128CBCHS256, .a192CBCHS384, .a256CBCHS512:
            // See https://www.rfc-editor.org/rfc/rfc7518#section-5.2.2.1
            let contentEncryptionKeyHalfLength = contentEncryptionKey.count / 2
            let macKey = contentEncryptionKey.prefix(contentEncryptionKeyHalfLength)
            let encKey = contentEncryptionKey.suffix(contentEncryptionKeyHalfLength)

            let ciphertext = try AES(
                key: encKey.bytes,
                blockMode: CBC(iv: initializationVector.bytes),
                padding: .pkcs7
            ).encrypt(Array(m))

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

            let fullAuthenticationTag = try HMAC(
                key: macKey.bytes,
                variant: hmacVariant
            ).authenticate([UInt8](dataToAuthenticate))
            let authenticationTag = fullAuthenticationTag.prefix(authenticationTagLength)

            resultCiphertext = Data(ciphertext)
            resultAuthenticationTag = Data(authenticationTag)

        case .a128GCM, .a192GCM, .a256GCM:
            // See https://www.rfc-editor.org/rfc/rfc7518#section-5.3
            let sealedBox = try AES.GCM.seal(
                m,
                using: .init(data: contentEncryptionKey),
                nonce: .init(data: initializationVector),
                authenticating: additionalAuthenticatedData
            )

            resultCiphertext = sealedBox.ciphertext
            resultAuthenticationTag = sealedBox.tag
        }

        return (resultCiphertext, resultAuthenticationTag)
    }
}
