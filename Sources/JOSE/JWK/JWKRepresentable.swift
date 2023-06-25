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

/// A protocol for types that can be represented as a JWK.
///
/// Types conforming to this protocol can be represented as a JWK by providing a `jwkRepresentation` property.
public protocol JWKRepresentable {
    /// Returns the JWK representation of the conforming type.
    var jwkRepresentation: JWK { get }
}

extension JWK: JWKRepresentable {
    /// Returns the JWK representation of a `JWK` instance.
    public var jwkRepresentation: JWK {
        self
    }
}

public extension JWKRepresentable where Self == JWK {
    /// Returns the public key of a `JWK` instance.
    var publicKey: JWK {
        var copy = self
        copy.d = nil
        return copy
    }
}

extension P256.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `P256.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = publicKey.rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            keyType: .ellipticCurve,
            curve: .p256,
            x: x,
            y: y,
            d: rawRepresentation
        )
    }
}

extension P384.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `P384.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = publicKey.rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            keyType: .ellipticCurve,
            curve: .p384,
            x: x,
            y: y,
            d: rawRepresentation
        )
    }
}

extension P521.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `P521.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = publicKey.rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            keyType: .ellipticCurve,
            curve: .p521,
            x: x,
            y: y,
            d: rawRepresentation
        )
    }
}

extension Curve25519.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `Curve25519.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        JWK(
            keyType: .octetKeyPair,
            curve: .x25519,
            x: publicKey.rawRepresentation,
            d: rawRepresentation
        )
    }
}

extension Curve448.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `Curve448.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        JWK(
            keyType: .octetKeyPair,
            curve: .x448,
            x: publicKey.rawRepresentation,
            d: rawRepresentation
        )
    }
}

extension secp256k1.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `secp256k1.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        // The uncompressed public key is 65 bytes long: a single byte prefix (0x04) followed by the two 32-byte coordinates.
        let publicKeyRawRepresentation = publicKey.dataRepresentation.dropFirst(1)
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            keyType: .ellipticCurve,
            curve: .secp256k1,
            x: x,
            y: y,
            d: rawRepresentation
        )
    }
}

extension P256.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `P256.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            keyType: .ellipticCurve,
            curve: .p256,
            x: x,
            y: y
        )
    }
}

extension P384.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `P384.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            keyType: .ellipticCurve,
            curve: .p384,
            x: x,
            y: y
        )
    }
}

extension P521.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `P521.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            keyType: .ellipticCurve,
            curve: .p521,
            x: x,
            y: y
        )
    }
}

extension Curve25519.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `Curve25519.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        JWK(
            keyType: .octetKeyPair,
            curve: .x25519,
            x: rawRepresentation
        )
    }
}

extension Curve448.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `Curve448.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        JWK(
            keyType: .octetKeyPair,
            curve: .x448,
            x: rawRepresentation
        )
    }
}

extension secp256k1.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `secp256k1.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        // The uncompressed public key is 65 bytes long: a single byte prefix (0x04) followed by the two 32-byte coordinates.
        let publicKeyRawRepresentation = dataRepresentation.dropFirst(1)
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            keyType: .ellipticCurve,
            curve: .secp256k1,
            x: x,
            y: y
        )
    }
}
