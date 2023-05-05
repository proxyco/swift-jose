// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

public extension JWE {
    /// An enumeration of possible errors that can be thrown when performing JWE operations.
    enum Error: Swift.Error, Equatable {
        /// The operation is not supported.
        case notSupported

        /// The authentication tag is incorrect.
        case authenticationFailure

        /// The encryption using the RSA algorithm failed.
        case rsaEncryptionFailure

        /// The decryption of content failed.
        case decryptionFailed

        /// The number of segments in the JWE compact serialization is invalid.
        ///
        /// - Parameter numberOfSegments: The number of segments.
        case invalidNumberOfSegments(_: Int)

        /// The encrypted key is invalid.
        case invalidEncryptedKey

        /// The content encryption key bit count is invalid.
        case invalidContentEncryptionKeyBitCount(_: Int, expected: Int)

        /// The recipient was not found.
        case recipientNotFound

        /// The JWE protected header is missing.
        case missingProtectedHeader

        /// The key management algorithm is missing.
        case missingKeyManagementAlgorithm

        /// The content encryption algorithm is missing.
        case missingContentEncryptionAlgorithm

        /// The ephemeral key is missing.
        case missingEphemeralKey

        /// The shared symmetric key is missing.
        case missingSharedSymmetricKey

        /// The content encryption key is missing.
        case missingContentEncryptionKey

        /// The encrypted content encryption key is missing.
        case missingEncryptedContentEncryptionKey

        /// The key encryption key is missing.
        case missingKeyEncryptionKey

        /// The initialization vector is missing.
        case missingInitializationVector

        /// The initialization vector bit count is invalid.
        case invalidInitializationVectorBitCount(_: Int, expected: Int)

        /// The ciphertext is missing.
        case missingCiphertext

        /// The authentication tag is missing.
        case missingAuthenticationTag

        /// The recipient key is missing.
        case missingRecipientKey

        /// The PBES2 salt input is missing.
        case missingPBES2SaltInput

        /// The PBES2 count is missing.
        case missingPBES2Count

        /// The sender key is missing.
        case missingSenderKey

        /// The keys used in the JWE are incompatible.
        case incompatibleKeys
    }
}
