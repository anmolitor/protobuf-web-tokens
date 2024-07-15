import fs from "fs";

const tests = JSON.parse(fs.readFileSync("fuzz/rust.json"));

const testCode = tests
  .flatMap(({ input, output, output_binary, timestamp }, i) => {
    return [
      `test "string ${i}" <| \\_ ->
    Protobuf.Token.decode Proto.Test.decodeSimple "${output}"
      |> Expect.all [
        Result.map .claims >> Expect.equal (Ok { someClaim = "${input}" }),
        Result.map (.validUntil >> Time.posixToMillis >> (\\millis -> millis // 1000)) >> Expect.equal (Ok ${timestamp}) 
      ]`,
      `test "binary ${i}" <| \\_ ->
    Protobuf.Token.decodeBytes Proto.Test.decodeSimple (encodeToBytes [${output_binary.join(', ')}])
      |> Expect.all [
        Result.map .claims >> Expect.equal (Ok { someClaim = "${input}" }),
        Result.map (.validUntil >> Time.posixToMillis >> (\\millis -> millis // 1000)) >> Expect.equal (Ok ${timestamp}) 
      ]`,
    ];
  })
  .join("\n  , ");

const fileContents = `module Generated.FuzzTest exposing (..)

import Bytes exposing (Bytes)
import Bytes.Encode as Encode
import Expect
import Proto.Test
import Protobuf.Token
import Test exposing (..)
import Time

suite : Test
suite = describe "rust fuzz test"
  [ ${testCode}
  ]

encodeToBytes : List Int -> Bytes
encodeToBytes ints =
    ints
        |> List.map Encode.unsignedInt8
        |> Encode.sequence
        |> Encode.encode  
`;

fs.mkdirSync("tests/Generated", { recursive: true });
fs.writeFileSync("tests/Generated/FuzzTest.elm", fileContents);
