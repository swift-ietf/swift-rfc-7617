import Binary_Serializable_Primitives
import Testing

@testable import RFC_7617

extension RFC_7617.Test {

    @Test
    func `Basic authorizationHeaderValue equals serialization`() throws {

        let basic = try RFC_7617.Basic(userID: "Aladdin", password: "open sesame")
        #expect(basic.authorizationHeaderValue() == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")

        #expect(basic.authorizationHeaderValue() == String(basic))
    }
}
