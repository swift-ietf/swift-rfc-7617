// swift-tools-version: 6.4

import PackageDescription

extension String {
    static let rfc7617: Self = "RFC 7617"
}

extension Target.Dependency {
    static var rfc7617: Self { .target(name: .rfc7617) }
}

let package = Package(
    name: "swift-rfc-7617",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
    ],
    products: [
        .library(name: "RFC 7617", targets: ["RFC 7617"])
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-molecules/swift-ascii-serializer.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-binary-serializer.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-molecules/swift-ascii-parser.git",
            branch: "main"
        ),
        .package(url: "https://github.com/swift-incits/swift-incits-4-1986.git", branch: "main"),
        .package(
            url: "https://github.com/swift-molecules/swift-binary.git",
            branch: "main"
        ),
        .package(url: "https://github.com/swift-ietf/swift-rfc-4648.git", branch: "main"),
        .package(
            url: "https://github.com/swift-molecules/swift-parser.git",
            branch: "main"
        ),
    ],
    targets: [
        .target(
            name: "RFC 7617",
            dependencies: [
                .product(
                    name: "ASCII Serializer",
                    package: "swift-ascii-serializer"
                ),
                .product(
                    name: "Binary Serializable",
                    package: "swift-binary-serializer"
                ),
                .product(
                    name: "Parseable ASCII",
                    package: "swift-ascii-parser"
                ),
                .product(name: "INCITS 4 1986", package: "swift-incits-4-1986"),
                .product(name: "Binary", package: "swift-binary"),
                .product(name: "RFC 4648", package: "swift-rfc-4648"),
                .product(name: "Parser", package: "swift-parser"),
            ]
        ),
        .testTarget(
            name: "RFC 7617 Tests",
            dependencies: [
                "RFC 7617"
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

extension String {
    var tests: Self { self + " Tests" }
    var foundation: Self { self + " Foundation" }
}

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    let ecosystem: [SwiftSetting] = [
        .strictMemorySafety(),
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility"),
        .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
        .enableExperimentalFeature("Lifetimes"),
    ]

    let package: [SwiftSetting] = []

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem + package
}
