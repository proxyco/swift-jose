// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

extension JWE {
    /// Computes the JOSE header by merging an array of `JOSEHeader` objects in the given order.
    /// The order of headers is important as values from later headers in the array
    /// will overwrite those from earlier headers if they exist.
    ///
    /// - Parameter headers: An array of `JOSEHeader` objects.
    /// - Returns: A single merged `JOSEHeader` object.
    static func computeJOSEHeader(from headers: [JOSEHeader]) -> JOSEHeader {
        var mergedHeader = JOSEHeader()

        for header in headers {
            if let algorithm = header.algorithm {
                mergedHeader.algorithm = algorithm
            }

            if let encryptionAlgorithm = header.encryptionAlgorithm {
                mergedHeader.encryptionAlgorithm = encryptionAlgorithm
            }

            if let compressionAlgorithm = header.compressionAlgorithm {
                mergedHeader.compressionAlgorithm = compressionAlgorithm
            }

            if let jwkSetURL = header.jwkSetURL {
                mergedHeader.jwkSetURL = jwkSetURL
            }

            if let jwk = header.jwk {
                mergedHeader.jwk = jwk
            }

            if let keyID = header.keyID {
                mergedHeader.keyID = keyID
            }

            if let x509URL = header.x509URL {
                mergedHeader.x509URL = x509URL
            }

            if let x509CertificateChain = header.x509CertificateChain {
                mergedHeader.x509CertificateChain = x509CertificateChain
            }

            if let x509CertificateSHA1Thumbprint = header.x509CertificateSHA1Thumbprint {
                mergedHeader.x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint
            }

            if let x509CertificateSHA256Thumbprint = header.x509CertificateSHA256Thumbprint {
                mergedHeader.x509CertificateSHA256Thumbprint = x509CertificateSHA256Thumbprint
            }

            if let type = header.type {
                mergedHeader.type = type
            }

            if let contentType = header.contentType {
                mergedHeader.contentType = contentType
            }

            if let critical = header.critical {
                mergedHeader.critical = critical
            }

            if let initializationVector = header.initializationVector {
                mergedHeader.initializationVector = initializationVector
            }

            if let authenticationTag = header.authenticationTag {
                mergedHeader.authenticationTag = authenticationTag
            }

            if let ephemeralPublicKey = header.ephemeralPublicKey {
                mergedHeader.ephemeralPublicKey = ephemeralPublicKey
            }

            if let agreementPartyUInfo = header.agreementPartyUInfo {
                mergedHeader.agreementPartyUInfo = agreementPartyUInfo
            }

            if let agreementPartyVInfo = header.agreementPartyVInfo {
                mergedHeader.agreementPartyVInfo = agreementPartyVInfo
            }

            if let pbes2SaltInput = header.pbes2SaltInput {
                mergedHeader.pbes2SaltInput = pbes2SaltInput
            }

            if let pbes2Count = header.pbes2Count {
                mergedHeader.pbes2Count = pbes2Count
            }

            if let senderKeyID = header.senderKeyID {
                mergedHeader.senderKeyID = senderKeyID
            }
        }

        return mergedHeader
    }

    /// Returns the Base64URL-encoded protected header.
    ///
    /// If the `encodedProtectedHeader` property is already set, this function returns its value.
    /// Otherwise, it creates a modified protected header with the private part of the ephemeral key removed
    /// (if present), encodes the modified protected header as JSON, and returns the Base64URL-encoded representation.
    ///
    /// - Returns: The Base64URL-encoded protected header as a String.
    /// - Throws: `EncodingError` if the protected header could not be encoded using `JSONEncoder`.
    func getEncodedProtectedHeader() throws -> String? {
        if let encodedProtectedHeader = encodedProtectedHeader {
            return encodedProtectedHeader
        }
        guard let protectedHeader else {
            return nil
        }

        // Ensure private part of ephemeral key is not present in serialization
        var modifiedProtectedHeader = protectedHeader
        modifiedProtectedHeader.ephemeralPublicKey = protectedHeader.ephemeralPublicKey?.publicKey

        let encoder = JSONEncoder()
        encoder.outputFormatting = .withoutEscapingSlashes
        let encodedHeader = try Base64URL.encode(encoder.encode(modifiedProtectedHeader))

        return encodedHeader
    }
}
