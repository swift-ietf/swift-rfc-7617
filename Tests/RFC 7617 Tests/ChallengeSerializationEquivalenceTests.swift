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
// [FAM-012] composite re-cut guard. The `RFC_7617.Basic.Challenge`
// `ASCII.Serializable` verb (direct same-format composition) MUST emit
// byte-identical output to the `Binary.Serializable` witness (`serializeBytes`)
// for the realm quoted-string escape path. Asserts the refactor invariant
// directly (ASCII output == Binary output), so no expected string is
// hand-derived.
//

import Binary_Serializable_Primitives
import RFC_7617
import Testing

extension RFC_7617.Basic.Challenge {
    @Suite("Challenge Serialization Equivalence")
    struct Test {

        @Test
        func `ASCII verb output equals Binary witness output for the realm quote-escape path`()
            throws
        {
            // A realm containing both `"` and `\` forces the backslash-escape branch
            // shared by both verbs; `charset` exercises the optional parameter path.
            let challenge = try RFC_7617.Basic.Challenge(realm: #"a"b\c"#, charset: "UTF-8")

            // ASCII.Serializable verb output, projected to bytes.
            let viaASCII: [Byte] = challenge.serialized

            // Binary.Serializable witness output.
            var viaBinary: [Byte] = []
            RFC_7617.Basic.Challenge.serialize(challenge, into: &viaBinary)

            #expect(viaASCII == viaBinary)
        }
    }
}
