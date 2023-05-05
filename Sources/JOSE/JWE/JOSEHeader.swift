// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

/// A struct representing the JOSE header.
public struct JOSEHeader: Equatable, Hashable {
    public var algorithm: KeyManagementAlgorithm?
    public var encryptionAlgorithm: ContentEncryptionAlgorithm?
    public var compressionAlgorithm: CompressionAlgorithm?
    public var jwkSetURL: String?
    public var jwk: JWK?
    public var keyID: String?
    public var x509URL: String?
    public var x509CertificateChain: String?
    public var x509CertificateSHA1Thumbprint: String?
    public var x509CertificateSHA256Thumbprint: String?
    public var type: String?
    public var contentType: String?
    public var critical: String?
    // Header parameters used for `AxxxGCMKW` algorithms
    public var initializationVector: Data?
    public var authenticationTag: Data?
    // Header parameters used for key agreement algorithms
    public var ephemeralPublicKey: JWK?
    public var agreementPartyUInfo: Data?
    public var agreementPartyVInfo: Data?
    // Header Parameters used for PBES2 key encryption
    public var pbes2SaltInput: Data?
    public var pbes2Count: Int?
    // Header parameter used for the `ECDH-1PU` key agreement algorithm
    public var senderKeyID: String?

    public init(
        algorithm: KeyManagementAlgorithm? = nil,
        encryptionAlgorithm: ContentEncryptionAlgorithm? = nil,
        compressionAlgorithm: CompressionAlgorithm? = nil,
        jwkSetURL: String? = nil,
        jwk: JWK? = nil,
        keyID: String? = nil,
        x509URL: String? = nil,
        x509CertificateChain: String? = nil,
        x509CertificateSHA1Thumbprint: String? = nil,
        x509CertificateSHA256Thumbprint: String? = nil,
        type: String? = nil,
        contentType: String? = nil,
        critical: String? = nil,
        initializationVector: Data? = nil,
        authenticationTag: Data? = nil,
        ephemeralPublicKey: JWK? = nil,
        agreementPartyUInfo: Data? = nil,
        agreementPartyVInfo: Data? = nil,
        pbes2SaltInput: Data? = nil,
        pbes2Count: Int? = nil,
        senderKeyID: String? = nil
    ) {
        self.algorithm = algorithm
        self.encryptionAlgorithm = encryptionAlgorithm
        self.compressionAlgorithm = compressionAlgorithm
        self.jwkSetURL = jwkSetURL
        self.jwk = jwk
        self.keyID = keyID
        self.x509URL = x509URL
        self.x509CertificateChain = x509CertificateChain
        self.x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint
        self.x509CertificateSHA256Thumbprint = x509CertificateSHA256Thumbprint
        self.type = type
        self.contentType = contentType
        self.critical = critical
        self.initializationVector = initializationVector
        self.authenticationTag = authenticationTag
        self.ephemeralPublicKey = ephemeralPublicKey
        self.agreementPartyUInfo = agreementPartyUInfo
        self.agreementPartyVInfo = agreementPartyVInfo
        self.pbes2SaltInput = pbes2SaltInput
        self.pbes2Count = pbes2Count
        self.senderKeyID = senderKeyID
    }
}
