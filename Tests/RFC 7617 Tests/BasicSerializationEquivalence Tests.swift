import Binary
import RFC_7617
import Testing

enum `RFC_7617.Basic Tests` {}

extension `RFC_7617.Basic Tests` {
    @Suite
    struct Test {

        @Test
        func `ASCII verb output equals Binary witness output for the Base64 encode path`() throws {

            let basic = try RFC_7617.Basic(userID: "Aladdin", password: "öpen sésame")

            let viaASCII: [Byte] = basic.serialized

            var viaBinary: [Byte] = []
            RFC_7617.Basic.serialize(basic, into: &viaBinary)

            #expect(viaASCII == viaBinary)
        }
    }
}
