// Copyright © 2023 Proxy, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import CryptoKit
import Foundation
import secp256k1

extension JWE {
    /// Generates an ephemeral key for a given recipient's JWK.
    ///
    /// - Parameter to: A `JWK` object representing the recipient's key.
    /// - Returns: A `JWK` object representing the generated ephemeral key.
    /// - Throws: `JWK.Error.notSupported` if the key type or curve is not supported.
    static func generateEphemeralKey(to: JWK) throws -> JWK {
        var ephemeralJWK: JWK!
        switch to.keyType {
        case .ellipticCurve:
            switch to.curve {
            case .p256:
                ephemeralJWK = P256.KeyAgreement.PrivateKey().jwkRepresentation
            case .p384:
                ephemeralJWK = P384.KeyAgreement.PrivateKey().jwkRepresentation
            case .p521:
                ephemeralJWK = P521.KeyAgreement.PrivateKey().jwkRepresentation
            case .secp256k1:
                ephemeralJWK = try secp256k1.KeyAgreement.PrivateKey(format: .uncompressed).jwkRepresentation
            default:
                throw JWK.Error.notSupported
            }
        case .octetKeyPair:
            switch to.curve {
            case .x25519:
                ephemeralJWK = Curve25519.KeyAgreement.PrivateKey().jwkRepresentation
            case .x448:
                ephemeralJWK = Curve448.KeyAgreement.PrivateKey().jwkRepresentation
            default:
                throw JWK.Error.notSupported
            }
        default:
            throw JWK.Error.notSupported
        }
        return ephemeralJWK
    }

    /// Derives a symmetric key from the shared secret using Concatenation Key Derivation Function (KDF).
    ///
    /// This function takes a shared secret and a JOSE header as input parameters and returns a derived symmetric key.
    ///
    /// See https://www.rfc-editor.org/rfc/rfc7518#section-4.6.2
    ///
    /// - Parameters:
    ///  - sharedSecret: The shared secret used to derive the symmetric key.
    ///  - joseHeader: The JOSE header.
    /// - Returns: The derived symmetric key.
    /// - Throws: An error of type `JWE.Error` if an error occurs during key derivation.
    static func deriveKey(
        from sharedSecret: Data,
        joseHeader: JOSEHeader
    ) throws -> Data {
        guard let encryptionAlgorithm = joseHeader.encryptionAlgorithm else {
            throw JWE.Error.missingContentEncryptionAlgorithm
        }
        guard let algorithm = joseHeader.algorithm else {
            throw JWE.Error.missingKeyManagementAlgorithm
        }
        let keyDataLen = encryptionAlgorithm.keySizeInBits
        // The AlgorithmID value is of the form Datalen || Data, where Data
        // is a variable-length string of zero or more octets, and Datalen is
        // a fixed-length, big-endian 32-bit counter that indicates the
        // length (in octets) of Data.  In the Direct Key Agreement case,
        // Data is set to the octets of the ASCII representation of the "enc"
        // Header Parameter value.  In the Key Agreement with Key Wrapping
        // case, Data is set to the octets of the ASCII representation of the
        // "alg" (algorithm) Header Parameter value.
        let algorithmID: Data
        if algorithm.mode == .directKeyAgreement {
            algorithmID = encryptionAlgorithm.rawValue.data(using: .ascii) ?? .init()
        } else {
            algorithmID = algorithm.rawValue.data(using: .ascii) ?? .init()
        }
        let algorithmIDData = UInt32(algorithmID.count).bigEndian.dataRepresentation + algorithmID

        let partyUInfo = joseHeader.agreementPartyUInfo ?? .init()
        let partyUInfoData = UInt32(partyUInfo.count).bigEndian.dataRepresentation + partyUInfo

        let partyVInfo = joseHeader.agreementPartyVInfo ?? .init()
        let partyVInfoData = UInt32(partyVInfo.count).bigEndian.dataRepresentation + partyVInfo

        let suppPubInfoData = UInt32(keyDataLen).bigEndian.dataRepresentation
        let suppPrivInfoData = Data()

        let derivedKey = try ConcatKDF<CryptoKit.SHA256>.deriveKey(
            z: sharedSecret,
            keyDataLen: keyDataLen,
            algorithmID: algorithmIDData,
            partyUInfo: partyUInfoData,
            partyVInfo: partyVInfoData,
            suppPubInfo: suppPubInfoData,
            suppPrivInfo: suppPrivInfoData
        )

        return derivedKey
    }
}
