// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import Foundation

extension JOSEHeader: Codable {
    enum CodingKeys: String, CodingKey {
        case algorithm = "alg"
        case encryptionAlgorithm = "enc"
        case compressionAlgorithm = "zip"
        case jwkSetURL = "jku"
        case jwk
        case keyID = "kid"
        case x509URL = "x5u"
        case x509CertificateChain = "x5c"
        case x509CertificateSHA1Thumbprint = "x5t"
        case x509CertificateSHA256Thumbprint = "x5t#S256"
        case type = "typ"
        case contentType = "cty"
        case critical = "crit"
        case initializationVector = "iv"
        case authenticationTag = "tag"
        case ephemeralPublicKey = "epk"
        case agreementPartyUInfo = "apu"
        case agreementPartyVInfo = "apv"
        case pbes2SaltInput = "p2s"
        case pbes2Count = "p2c"
        case senderKeyID = "skid"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(algorithm, forKey: .algorithm)
        try container.encodeIfPresent(encryptionAlgorithm, forKey: .encryptionAlgorithm)
        try container.encodeIfPresent(compressionAlgorithm, forKey: .compressionAlgorithm)
        try container.encodeIfPresent(jwkSetURL, forKey: .jwkSetURL)
        try container.encodeIfPresent(jwk, forKey: .jwk)
        try container.encodeIfPresent(keyID, forKey: .keyID)
        try container.encodeIfPresent(x509URL, forKey: .x509URL)
        try container.encodeIfPresent(x509CertificateChain, forKey: .x509CertificateChain)
        try container.encodeIfPresent(x509CertificateSHA1Thumbprint, forKey: .x509CertificateSHA1Thumbprint)
        try container.encodeIfPresent(x509CertificateSHA256Thumbprint, forKey: .x509CertificateSHA256Thumbprint)
        try container.encodeIfPresent(type, forKey: .type)
        try container.encodeIfPresent(contentType, forKey: .contentType)
        try container.encodeIfPresent(critical, forKey: .critical)
        if let value = initializationVector {
            try container.encode(Base64URL.encode(value), forKey: .initializationVector)
        }
        if let value = authenticationTag {
            try container.encode(Base64URL.encode(value), forKey: .authenticationTag)
        }
        try container.encodeIfPresent(ephemeralPublicKey, forKey: .ephemeralPublicKey)
        if let value = agreementPartyUInfo {
            try container.encode(Base64URL.encode(value), forKey: .agreementPartyUInfo)
        }
        if let value = agreementPartyVInfo {
            try container.encode(Base64URL.encode(value), forKey: .agreementPartyVInfo)
        }
        if let value = pbes2SaltInput {
            try container.encode(Base64URL.encode(value), forKey: .pbes2SaltInput)
        }
        try container.encodeIfPresent(pbes2Count, forKey: .pbes2Count)
        try container.encodeIfPresent(senderKeyID, forKey: .senderKeyID)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        algorithm = try container.decodeIfPresent(JOSEHeader.KeyManagementAlgorithm.self, forKey: .algorithm)
        encryptionAlgorithm = try container.decodeIfPresent(JOSEHeader.ContentEncryptionAlgorithm.self, forKey: .encryptionAlgorithm)
        compressionAlgorithm = try container.decodeIfPresent(CompressionAlgorithm.self, forKey: .compressionAlgorithm)
        jwkSetURL = try container.decodeIfPresent(String.self, forKey: .jwkSetURL)
        jwk = try container.decodeIfPresent(JWK.self, forKey: .jwk)
        keyID = try container.decodeIfPresent(String.self, forKey: .keyID)
        x509URL = try container.decodeIfPresent(String.self, forKey: .x509URL)
        x509CertificateChain = try container.decodeIfPresent(String.self, forKey: .x509CertificateChain)
        x509CertificateSHA1Thumbprint = try container.decodeIfPresent(String.self, forKey: .x509CertificateSHA1Thumbprint)
        x509CertificateSHA256Thumbprint = try container.decodeIfPresent(String.self, forKey: .x509CertificateSHA256Thumbprint)
        type = try container.decodeIfPresent(String.self, forKey: .type)
        contentType = try container.decodeIfPresent(String.self, forKey: .contentType)
        critical = try container.decodeIfPresent(String.self, forKey: .critical)
        if let value = try container.decodeIfPresent(String.self, forKey: .initializationVector) {
            initializationVector = try Base64URL.decode(value)
        }
        if let value = try container.decodeIfPresent(String.self, forKey: .authenticationTag) {
            authenticationTag = try Base64URL.decode(value)
        }
        ephemeralPublicKey = try container.decodeIfPresent(JWK.self, forKey: .ephemeralPublicKey)
        if let value = try container.decodeIfPresent(String.self, forKey: .agreementPartyUInfo) {
            agreementPartyUInfo = try Base64URL.decode(value)
        }
        if let value = try container.decodeIfPresent(String.self, forKey: .agreementPartyVInfo) {
            agreementPartyVInfo = try Base64URL.decode(value)
        }
        if let value = try container.decodeIfPresent(String.self, forKey: .pbes2SaltInput) {
            pbes2SaltInput = try Base64URL.decode(value)
        }
        pbes2Count = try container.decodeIfPresent(Int.self, forKey: .pbes2Count)
        senderKeyID = try container.decodeIfPresent(String.self, forKey: .senderKeyID)
    }
}
