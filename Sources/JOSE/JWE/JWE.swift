// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoKit
import Foundation

/// A JSON Web Encryption as defined by [RFC7516](https://www.rfc-editor.org/rfc/rfc7516)
public struct JWE {
    /// The protected header
    public var protectedHeader: JOSEHeader?

    /// The Base64URL-encoded protected header
    var encodedProtectedHeader: String?

    /// The shared unprotected header, when JSON serialization is used
    public var sharedUnprotectedHeader: JOSEHeader?

    /// The recipients, when JSON serialization is used
    public var recipients: [Recipient]?

    /// The content encryption key (CEK), when compact serialization is used
    public var contentEncryptionKey: Data?

    /// The encrypted content encryption key, when compact serialization is used
    public var encryptedKey: Data?

    /// The initialization vector
    public var initializationVector: Data?

    /// The ciphertext
    public var ciphertext: Data?

    /// The authentication tag
    public var authenticationTag: Data?

    /// The additional authenticated data (AAD), when JSON serialization is used
    public var additionalAuthenticatedData: Data?

    // MARK: - Init

    /// Initializes a new JWE object with the specified properties.
    ///
    /// - Parameters:
    ///   - protectedHeader: The JWE protected header.
    ///   - encodedProtectedHeader: The Base64URL-encoded string of the JWE protected header. Default value is `nil`.
    ///   - sharedUnprotectedHeader: The shared JWE unprotected header. Default value is `nil`.
    ///   - recipients: An array of `JWE.Recipient` objects. Default value is `nil`.
    ///   - contentEncryptionKey: The content encryption key (CEK). Default value is `nil`.
    ///   - encryptedKey: The encrypted content encryption key. Default value is `nil`.
    ///   - initializationVector: The initialization vector. Default value is `nil`.
    ///   - ciphertext: The ciphertext. Default value is `nil`.
    ///   - authenticationTag: The authentication tag. Default value is `nil`.
    ///   - additionalAuthenticatedData: The additional authenticated data (AAD). Default value is `nil`.
    /// - Throws:
    ///   `DecodingError` if the protected header could not be decoded using `JSONDecoder`, or `Base64URLError` if the protected header is not a valid Base64URL-encoded string when `encodedProtectedHeader` is used.
    public init(
        protectedHeader: JOSEHeader? = nil,
        encodedProtectedHeader: String? = nil,
        sharedUnprotectedHeader: JOSEHeader? = nil,
        recipients: [Recipient]? = nil,
        contentEncryptionKey: Data? = nil,
        encryptedKey: Data? = nil,
        initializationVector: Data? = nil,
        ciphertext: Data? = nil,
        authenticationTag: Data? = nil,
        additionalAuthenticatedData: Data? = nil
    ) throws {
        self.encodedProtectedHeader = encodedProtectedHeader
        if let encodedHeader = encodedProtectedHeader, protectedHeader == nil {
            self.protectedHeader = try JSONDecoder().decode(
                JOSEHeader.self,
                from: Base64URL.decode(encodedHeader)
            )
        } else {
            self.protectedHeader = protectedHeader
        }
        self.sharedUnprotectedHeader = sharedUnprotectedHeader
        self.recipients = recipients ?? [.init(encryptedKey: encryptedKey)]
        self.contentEncryptionKey = contentEncryptionKey
        self.encryptedKey = encryptedKey
        self.initializationVector = initializationVector
        self.ciphertext = ciphertext
        self.authenticationTag = authenticationTag
        self.additionalAuthenticatedData = additionalAuthenticatedData
    }
}
