// swift-tools-version: 6.0
// DFOS Protocol — Independent verification in Swift

import PackageDescription

let package = Package(
    name: "dfos-protocol-verify",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .testTarget(
            name: "VerifyProtocolTests",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
    ]
)
