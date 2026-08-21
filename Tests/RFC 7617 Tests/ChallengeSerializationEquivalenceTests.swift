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

            let challenge = try RFC_7617.Basic.Challenge(realm: #"a"b\c"#, charset: "UTF-8")

            let viaASCII: [Byte] = challenge.serialized

            var viaBinary: [Byte] = []
            RFC_7617.Basic.Challenge.serialize(challenge, into: &viaBinary)

            #expect(viaASCII == viaBinary)
        }
    }
}
