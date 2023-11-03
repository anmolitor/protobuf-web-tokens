module Base64UrlSafe exposing (toBytes)

{-| Note: Code and comments are mostly copied from
<https://github.com/danfishgold/base64-bytes/blob/1.1.0/src/Encode.elm>

We need a different base64 encoding (\_ and - instead of + and ) and we do not want to pay the performance
cost to first replace all characters accordingly to then use the lib.

-}

import Bitwise
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Encode as Encode exposing (Encoder)


toBytes : String -> Maybe Bytes
toBytes string =
    Maybe.map Encode.encode (encoder string)


encoder : String -> Maybe Encode.Encoder
encoder string =
    encodeChunks string []
        |> Maybe.map (List.reverse >> Encode.sequence)


{-| Big picture:

  - read 4 base64 characters
  - convert them to 3 bytes (24 bits)
  - encode these bytes

-}
encodeChunks : String -> List Encoder -> Maybe (List Encoder)
encodeChunks input accum =
    {- Performance Note

       slice and toList is just as fast as (possibly a little faster than) repeated `String.uncons`,
       but this code is much more readable
    -}
    case String.toList (String.left 4 input) of
        [] ->
            Just accum

        [ a, b, c, d ] ->
            encodeCharacters a b c d
                |> Maybe.andThen (\enc -> encodeChunks (String.dropLeft 4 input) (enc :: accum))

        [ a, b, c ] ->
            encode3Characters a b c
                |> Maybe.map (\enc -> enc :: accum)

        [ a, b ] ->
            encode2Characters a b
                |> Maybe.map (\enc -> enc :: accum)

        _ ->
            Nothing


encode2Characters : Char -> Char -> Maybe Encoder
encode2Characters a b =
    if isValidChar a && isValidChar b then
        let
            n1 =
                unsafeConvertChar a

            n2 =
                unsafeConvertChar b

            n =
                Bitwise.or
                    (Bitwise.shiftLeftBy 18 n1)
                    (Bitwise.shiftLeftBy 12 n2)

            b1 =
                -- masking higher bits is not needed, Encode.unsignedInt8 ignores higher bits
                Bitwise.shiftRightBy 16 n
        in
        Just (Encode.unsignedInt8 b1)

    else
        Nothing


encode3Characters : Char -> Char -> Char -> Maybe Encoder
encode3Characters a b c =
    if isValidChar a && isValidChar b && isValidChar c then
        let
            n1 =
                unsafeConvertChar a

            n2 =
                unsafeConvertChar b

            n3 =
                unsafeConvertChar c

            n =
                Bitwise.or
                    (Bitwise.or (Bitwise.shiftLeftBy 18 n1) (Bitwise.shiftLeftBy 12 n2))
                    (Bitwise.shiftLeftBy 6 n3)

            combined =
                Bitwise.shiftRightBy 8 n
        in
        Just (Encode.unsignedInt16 BE combined)

    else
        Nothing


{-| Convert 4 characters to 24 bits (as an Encoder)
-}
encodeCharacters : Char -> Char -> Char -> Char -> Maybe Encoder
encodeCharacters a b c d =
    if isValidChar a && isValidChar b && isValidChar c && isValidChar d then
        let
            n1 =
                unsafeConvertChar a

            n2 =
                unsafeConvertChar b

            n3 =
                unsafeConvertChar c

            n4 =
                unsafeConvertChar d

            n =
                Bitwise.or
                    (Bitwise.or (Bitwise.shiftLeftBy 18 n1) (Bitwise.shiftLeftBy 12 n2))
                    (Bitwise.or (Bitwise.shiftLeftBy 6 n3) n4)

            b3 =
                -- Masking the higher bits is not needed: Encode.unsignedInt8 ignores higher bits
                n

            combined =
                Bitwise.shiftRightBy 8 n
        in
        Just
            (Encode.sequence
                [ Encode.unsignedInt16 BE combined
                , Encode.unsignedInt8 b3
                ]
            )

    else
        Nothing


{-| is the character a base64 digit?

The base16 digits are: A-Z, a-z, 0-1, '\_' and '-'

-}
isValidChar : Char -> Bool
isValidChar c =
    if Char.isAlphaNum c then
        True

    else
        case c of
            '-' ->
                True

            '_' ->
                True

            _ ->
                False


{-| Convert a base64 character/digit to its index

See also [Wikipedia](https://en.wikipedia.org/wiki/Base64#Base64_table)

-}
unsafeConvertChar : Char -> Int
unsafeConvertChar char =
    {- Performance Note

       Working with the key directly is faster than using e.g. `Char.isAlpha` and `Char.isUpper`
    -}
    let
        key =
            Char.toCode char
    in
    if key >= 65 && key <= 90 then
        -- A-Z
        key - 65

    else if key >= 97 && key <= 122 then
        -- a-z
        (key - 97) + 26

    else if key >= 48 && key <= 57 then
        -- 0-9
        (key - 48) + 26 + 26

    else
        case char of
            '-' ->
                62

            '_' ->
                63

            _ ->
                -1
