{- !!! DO NOT EDIT THIS FILE MANUALLY !!! -}

module Proto.Google.Protobuf.Internals_ exposing (..)

{-| 
This file was automatically generated by
- [`protoc-gen-elm`](https://www.npmjs.com/package/protoc-gen-elm) 3.2.0
- `protoc` 3.19.0
- the following specification files: `google/protobuf/timestamp.proto`

To run it, add a dependency via `elm install` on [`elm-protocol-buffers`](https://package.elm-lang.org/packages/eriktim/elm-protocol-buffers/1.2.0) version latest or higher.


-}

import Protobuf.Decode
import Protobuf.Encode
import Protobuf.Types.Int64


{-| The field numbers for the fields of `Proto__Google__Protobuf__Timestamp`. This is mostly useful for internals, like documentation generation.


-}
fieldNumbersProto__Google__Protobuf__Timestamp : { seconds : Int, nanos : Int }
fieldNumbersProto__Google__Protobuf__Timestamp =
    { seconds = 1, nanos = 2 }


{-| Default for Proto__Google__Protobuf__Timestamp. Should only be used for 'required' decoders as an initial value.


-}
defaultProto__Google__Protobuf__Timestamp : Proto__Google__Protobuf__Timestamp
defaultProto__Google__Protobuf__Timestamp =
    { seconds = Protobuf.Types.Int64.fromInts 0 0, nanos = 0 }


{-| Declares how to decode a `Proto__Google__Protobuf__Timestamp` from Bytes. To actually perform the conversion from Bytes, you need to use Protobuf.Decode.decode from eriktim/elm-protocol-buffers.


-}
decodeProto__Google__Protobuf__Timestamp : Protobuf.Decode.Decoder Proto__Google__Protobuf__Timestamp
decodeProto__Google__Protobuf__Timestamp =
    Protobuf.Decode.message
        defaultProto__Google__Protobuf__Timestamp
        [ Protobuf.Decode.optional 1 Protobuf.Decode.int64 (\a r -> { r | seconds = a })
        , Protobuf.Decode.optional 2 Protobuf.Decode.int32 (\a r -> { r | nanos = a })
        ]


{-| Declares how to encode a `Proto__Google__Protobuf__Timestamp` to Bytes. To actually perform the conversion to Bytes, you need to use Protobuf.Encode.encode from eriktim/elm-protocol-buffers.


-}
encodeProto__Google__Protobuf__Timestamp : Proto__Google__Protobuf__Timestamp -> Protobuf.Encode.Encoder
encodeProto__Google__Protobuf__Timestamp value =
    Protobuf.Encode.message [ ( 1, Protobuf.Encode.int64 value.seconds ), ( 2, Protobuf.Encode.int32 value.nanos ) ]


{-| `Proto__Google__Protobuf__Timestamp` message


-}
type alias Proto__Google__Protobuf__Timestamp =
    { seconds : Protobuf.Types.Int64.Int64, nanos : Int }
