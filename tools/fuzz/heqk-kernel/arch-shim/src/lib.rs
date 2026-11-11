//! Host stand-in for the two `arch_aarch64` items the fuzzed kernel files reference from their self-tests
//! (`_print`). The self-tests are not run by the fuzz targets; this only lets the SAME source files compile.
pub fn _print(_: core::fmt::Arguments) {}
