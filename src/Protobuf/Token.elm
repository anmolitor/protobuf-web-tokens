module Protobuf.Token exposing
    ( TokenData
    , decode, decodeBytes
    , Error(..), errorToString
    )

{-| Decode Protobuf Web Tokens (PWT)

@docs TokenData
@docs decode, decodeBytes
@docs Error, errorToString

-}

import Base64UrlSafe
import Bytes exposing (Bytes)
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
            Base64UrlSafe.toBytes >> Result.fromMaybe InvalidBase64
    in
    case String.split "." token of
        [ data, _ ] ->
            toBytes data
                |> Result.andThen decodePwt
                |> Result.andThen (decodeClaims decoder)

        _ ->
            Err InvalidFormat


{-| Decodes a Protobuf Web Token from the compact byte format using the given decoder.
-}
decodeBytes : Protobuf.Decode.Decoder t -> Bytes -> Result Error (TokenData t)
decodeBytes decoder bytes =
    Protobuf.Decode.decode Proto.Pwt.decodeSignedToken bytes
        |> Result.fromMaybe InvalidBytes
        |> Result.andThen
            (\{ data } ->
                decodePwt data
                    |> Result.andThen (decodeClaims decoder)
            )


decodePwt : Bytes -> Result Error Proto.Pwt.Token
decodePwt =
    Protobuf.Decode.decode Proto.Pwt.decodeToken
        >> Result.fromMaybe InvalidBytes


decodeValidUntil : Maybe { a | nanos : Int, seconds : Protobuf.Types.Int64.Int64 } -> Result Error Time.Posix
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


decodeClaims : Protobuf.Decode.Decoder a -> Proto.Pwt.Token -> Result Error (TokenData a)
decodeClaims decoder { validUntil, claims } =
    Result.map2 TokenData
        (decodeValidUntil validUntil)
        (Protobuf.Decode.decode decoder claims
            |> Result.fromMaybe InvalidBytes
        )


int64ToInt53 : Protobuf.Types.Int64.Int64 -> Int
int64ToInt53 int64 =
    let
        ( higher, lower ) =
            Protobuf.Types.Int64.toInts int64
    in
    higher * 2 ^ 32 + lower


{-| Converts an `Error` to a string representation for debugging or error reporting.
-}
errorToString : Error -> String
errorToString error =
    case error of
        InvalidFormat ->
            "Invalid Format. Expected {data}.{signature}"

        InvalidBase64 ->
            "Invalid Base64. Expected UrlSafeNoPad encoding"

        InvalidBytes ->
            "Invalid Bytes when trying to decode Protobuf message"

        NoValidUntilField ->
            "Timestamp is a required field, but was not set"
