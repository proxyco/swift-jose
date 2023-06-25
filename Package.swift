// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JOSE",
    platforms: [
        .macOS(.v12), .iOS(.v15),
    ],
    products: [
        .library(
            name: "swift-jose",
            targets: ["JOSE"]
        ),
    ],
    dependencies: [
        // For `X448` support
        .package(url: "https://github.com/krzyzanowskim/OpenSSL.git", .upToNextMinor(from: "1.1.180")),
        // For `secp256k1` support
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", .upToNextMinor(from: "0.12.2")),
        // For `AES_CBC_HMAC_SHA2`, `PBES2` and RSA DER encoding support
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.7.2")),
    ],
    targets: [
        .target(
            name: "JOSE",
            dependencies: [
                "OpenSSL",
                .product(name: "secp256k1", package: "secp256k1.swift"),
                "CryptoSwift",
            ]
        ),
        .testTarget(
            name: "JOSETests",
            dependencies: ["JOSE"]
        ),
    ]
)
