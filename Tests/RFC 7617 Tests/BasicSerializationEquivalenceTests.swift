// ===----------------------------------------------------------------------===//
//
// This source file is part of the swift-rfc-7617 open source project
//
// Copyright (c) 2025 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//
//
// [FAM-012] composite re-cut guard. The `RFC_7617.Basic` `ASCII.Serializable`
// verb (direct same-format composition) MUST emit byte-identical output to the
// `Binary.Serializable` witness (`serializeBytes`) for the Base64-encode path.
// Asserts the refactor invariant directly (ASCII output == Binary output), so
// no expected string is hand-derived.
//

import RFC_7617
import Binary_Serializable_Primitives
import Testing

@Suite("Basic Serialization Equivalence")
struct BasicSerializationEquivalenceTests {

    @Test
    func `ASCII verb output equals Binary witness output for the Base64 encode path`() throws {
        // Credentials whose user-pass contains multi-byte UTF-8 (non-trivial
        // bytes) exercise the Base64 leaf both verbs share.
        let basic = try RFC_7617.Basic(userID: "Aladdin", password: "öpen sésame")

        // ASCII.Serializable verb output, projected to bytes.
        let viaASCII: [Byte] = basic.serialized

        // Binary.Serializable witness output.
        var viaBinary: [Byte] = []
        RFC_7617.Basic.serialize(basic, into: &viaBinary)

        #expect(viaASCII == viaBinary)
    }
}
