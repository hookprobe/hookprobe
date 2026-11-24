// SPDX-License-Identifier: AGPL-3.0-only
//! Print a GGUF file's metadata and tensor table, read through `neuro_gguf` (build host).
use neuro_gguf::{Gguf, Value};

fn main() {
    let path = std::env::args().nth(1).expect("usage: gguf-info FILE");
    let bytes = std::fs::read(&path).expect("read");
    let t0 = std::time::Instant::now();
    let g = Gguf::open(&bytes).expect("open");
    println!("{path}: {} bytes, {} keys, {} tensors, alignment {}, validated in {:?}", bytes.len(), g.kv_count(), g.tensor_count(), g.alignment, t0.elapsed());
    g.for_each_kv(|k, v| {
        let k = String::from_utf8_lossy(k);
        match v {
            Value::Str(s) if s.len() > 120 => println!("  {k} = <string, {} bytes>", s.len()),
            Value::Str(s) => println!("  {k} = {:?}", String::from_utf8_lossy(s)),
            Value::Single(b) => println!("  {k} = {} (binary32)", f32::from_bits(b)),
            Value::Array(a) => println!("  {k} = <array of type {}, {} items>", a.elem, a.len),
            v => println!("  {k} = {v:?}"),
        }
    });
    let mut types = std::collections::BTreeMap::new();
    g.for_each_tensor(|t| {
        *types.entry(t.ty).or_insert(0usize) += 1;
        let n = String::from_utf8_lossy(t.name);
        if n.starts_with("blk.0.") || !n.starts_with("blk.") {
            println!("  tensor {n}: type {} dims {:?}", t.ty, &t.dims[..t.n_dims]);
        }
    });
    println!("  tensor types (type: count): {types:?}");
}
