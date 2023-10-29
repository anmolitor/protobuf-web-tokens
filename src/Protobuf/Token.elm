module Protobuf.Token exposing
    ( TokenData
    , decode
    , Error(..)
    )

{-| Decode Protobuf Web Tokens (PWT)

@docs TokenData
@docs decode
@docs Error

-}

import Base64
import Proto.Pwt
import Protobuf.Decode
import Protobuf.Types.Int64
import Time


{-| The ways a token decoding can fail
-}
type Error
    = InvalidFormat
    | InvalidBase64
    | InvalidBytes
    | NoValidUntilField


{-| Claims encoded in the token and some metadata
-}
type alias TokenData t =
    { validUntil : Time.Posix
    , claims : t
    }


{-| Decodes a Protobuf Web Token using the given decoder.
-}
decode : Protobuf.Decode.Decoder t -> String -> Result Error (TokenData t)
decode decoder token =
    let
        toBytes =
            Base64.toBytes >> Result.fromMaybe InvalidBase64

        decodePwt =
            Protobuf.Decode.decode Proto.Pwt.decodeToken
                >> Result.fromMaybe InvalidBytes

        decodeValidUntil validUntil =
            case validUntil of
                Just { nanos, seconds } ->
                    let
                        millis =
                            int64ToInt53 seconds * 1000 + (nanos // 1000000)
                    in
                    Ok <| Time.millisToPosix millis

                Nothing ->
                    Err NoValidUntilField

        decodeClaims =
            Protobuf.Decode.decode decoder
                >> Result.fromMaybe InvalidBytes
    in
    case String.split "." token of
        [ data, _ ] ->
            toBytes data
                |> Result.andThen decodePwt
                |> Result.andThen
                    (\{ validUntil, claims } ->
                        Result.map2 TokenData
                            (decodeValidUntil validUntil)
                            (decodeClaims claims)
                    )

        _ ->
            Err InvalidFormat


int64ToInt53 : Protobuf.Types.Int64.Int64 -> Int
int64ToInt53 int64 =
    let
        ( higher, lower ) =
            Protobuf.Types.Int64.toInts int64
    in
    higher * 2 ^ 32 + lower
