module Example exposing (..)

import Expect exposing (Expectation)
import Fuzz exposing (Fuzzer, int, list, string)
import Proto.Pwt
import Protobuf.Token
import Test exposing (..)
import Time


suite : Test
suite =
    describe "token"
        [ test "works with rust token" <|
            \_ ->
                Protobuf.Token.decode Proto.Pwt.decodeSimple
                    "CgsImpnrqQYQzMKlCRIPEg10ZXN0IGNvbnRlbnRz.gNAqudBxRzCSbwjIYGhvVgWuhUk17BBoXgZk-uqKNVXRfXQZ2qDvG-4I-BRDkxJTKYlwgEATeEplbv7idBVFBA"
                    |> Expect.equal (Ok { validUntil = Time.millisToPosix 1698352282019, claims = { someClaim = "test contents" } })
        ]
