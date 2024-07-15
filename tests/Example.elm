module Example exposing (..)

import Expect
import Proto.Test
import Protobuf.Token
import Test exposing (..)
import Time


suite : Test
suite =
    describe "token"
        [ test "works with rust token" <|
            \_ ->
                Protobuf.Token.decode Proto.Test.decodeSimple
                    "CgsImpnrqQYQzMKlCRIPEg10ZXN0IGNvbnRlbnRz.gNAqudBxRzCSbwjIYGhvVgWuhUk17BBoXgZk-uqKNVXRfXQZ2qDvG-4I-BRDkxJTKYlwgEATeEplbv7idBVFBA"
                    |> Expect.equal (Ok { validUntil = Time.millisToPosix 1698352282019, claims = { someClaim = "test contents" } })
        , test "works with rust token 2" <|
            \_ ->
                Protobuf.Token.decode Proto.Test.decodeSimple
                    "CgwI-I6QqgYQ_MeB_AESChIIdGVzdGFiY2Q.Cn9hMA7wCI3Qg8kmOgBlkZVzDXJ5LIh3oh66l83RqbrYxV9bYn4Nu-ETHulxdQthaKEQ0qNJJEcFradHl2_tCQ"
                    |> Expect.equal (Ok { validUntil = Time.millisToPosix 1698957176528, claims = { someClaim = "testabcd" } })
        ]
