module Runner exposing (..)

import Benchmark.Runner exposing (BenchmarkProgram, program)
import DecodeBenchmark


main : BenchmarkProgram
main =
    program DecodeBenchmark.suite
