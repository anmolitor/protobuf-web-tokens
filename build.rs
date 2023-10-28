fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(&["pwt.proto"], &["."])?;
    prost_build::compile_protos(&["test_resources/test.proto"], &["."])?;
    Ok(())
}
