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

import Binary_Serializable_Primitives
import Testing

@testable import RFC_7617

extension RFC_7617.Test {

    @Test
    func `Basic authorizationHeaderValue equals serialization`() throws {
        // Per RFC 7617 Section 2: "Aladdin:open sesame" -> "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        let basic = try RFC_7617.Basic(userID: "Aladdin", password: "open sesame")
        #expect(basic.authorizationHeaderValue() == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")

        // The named accessor is identical to the type's ASCII serialization.
        #expect(basic.authorizationHeaderValue() == String(basic))
    }
}
