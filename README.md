# Protobuf Web Token (PWT)

Collection of libraries for different languages to implement signing/verification/decoding of tokens.
The approach is similar to the one used in [JWT](https://jwt.io/introduction) (Json Web Token).
The rest of this README assumes that you are familiar what JWTs are used for.

## What is suboptimal with JWTs

The JSON format is rather inefficient to transfer data with in comparison to a compact binary encoding such as [Protocol Buffers](https://protobuf.dev/).
It is in most cases both larger in size and takes longer to encode and decode.
However, the advantages of JSON include its human-readability and its typeless nature -
the client does not need to know all keys/all value types the server sends in a response.
But in a scenario where you have both authorization server and application in your hands this seems like a disadvantage instead:
There is a possibility for errors since there is an implicit dependency that will not be caught at compile time.

## Protobuf to the rescue

So assuming we have both authorization server and application in our control we can do "better" (there are still coupling tradeoffs here of course).

We introduce a `.proto` file which contains the data we wish to put in the token.
Examples:
- The users id
- The users name
- The users email
- A list of roles or permissions
- ...

The token will also include standardized metadata which right now is just one field:
- `valid_until`, a unix timestamp of the time where the token should expire

We generate the bindings for the languages using libraries or protoc plugins. For the currently supported languages these are:
- [prost](https://github.com/tokio-rs/prost) for Rust
- [protoc-gen-elm](https://github.com/anmolitor/protoc-gen-elm) for Elm

Then the authorization server can use the `sign` method to sign an object which precisely matches the shape you defined in your `.proto` file and the client or other servers can use `verify` or `decode` to read the contents.

## Supported Encryption Algorithms

Right now we only support Ed25519.
Therefore, the token does not need to include information which verification algorithm needs to be used, which also helps to reduce the size a bit more.
