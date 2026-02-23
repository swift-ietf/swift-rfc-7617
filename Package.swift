// swift-tools-version:6.2

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
        .macOS(.v26),
        .iOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26)
    ],
    products: [
        .library(name: "RFC 7617", targets: ["RFC 7617"])
    ],
    dependencies: [
        .package(path: "../../swift-foundations/swift-ascii"),
        .package(path: "../../swift-primitives/swift-binary-primitives"),
        .package(path: "../swift-rfc-4648")
    ],
    targets: [
        .target(
            name: "RFC 7617",
            dependencies: [
                .product(name: "ASCII", package: "swift-ascii"),
                .product(name: "Binary Primitives", package: "swift-binary-primitives"),
                .product(name: "RFC 4648", package: "swift-rfc-4648")
            ]
        )
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
        .enableExperimentalFeature("Lifetimes"),
        .enableExperimentalFeature("SuppressedAssociatedTypes"),
        .enableExperimentalFeature("SuppressedAssociatedTypesWithDefaults"),
    ]

    let package: [SwiftSetting] = []

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem + package
}
