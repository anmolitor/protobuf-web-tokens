import fs from "fs";

const tests = JSON.parse(fs.readFileSync("fuzz/rust.json"));

const testCode = tests
  .map(({ input, output, timestamp }, i) => {
    return `test "${i}" <| \\_ ->
    Protobuf.Token.decode Proto.Pwt.decodeSimple "${output}"
      |> Expect.all [
        Result.map .claims >> Expect.equal (Ok { someClaim = "${input}" }),
        Result.map (.validUntil >> Time.posixToMillis >> (\\millis -> millis // 1000)) >> Expect.equal (Ok ${timestamp}) 
      ]`;
  })
  .join("\n  , ");

const fileContents = `module Generated.FuzzTest exposing (..)

import Test exposing (..)
import Expect
import Proto.Pwt
import Protobuf.Token
import Time

suite : Test
suite = describe "rust fuzz test"
  [ ${testCode}
  ]
`;

fs.mkdirSync("tests/Generated", { recursive: true });
fs.writeFileSync("tests/Generated/FuzzTest.elm", fileContents);
