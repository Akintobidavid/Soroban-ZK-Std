//! Criterion benchmark comparing the Montgomery `mul_mod` engine (issue #360)
//! against the pre-optimization reference (`mul_mod_legacy`).
//!
//! Montgomery reduction replaces the shift-and-add / Karatsuba reduction with
//! cheap shifts and additions, so each field multiplication executes far fewer
//! CPU instructions. This bench measures wall-clock time as a proxy for the
//! Soroban CPU-instruction cost documented in `instruction_cost.rs`.
//!
//! # Reproducibility
//! Run with:
//!   cargo bench -p soroban-zk-core --bench montgomery_ops
//!
//! For the true Soroban CPU-instruction figure, see
//! `crates/soroban-zk-std/benches/instruction_cost.rs`
//! (`bench_fr_mul_montgomery_vs_legacy`).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ethnum::u256;
use soroban_zk_core::Bn254;

fn bench_montgomery_vs_legacy(c: &mut Criterion) {
    // Representative scalar-field operands.
    let a = u256::from_words(
        0x1234_5678_9abc_def0_1234_5678_9abc_def0_u128,
        0xfedc_ba09_8765_4321_fedc_ba09_8765_4321_u128,
    );
    let b = u256::from_words(
        0x0f1e_2d3c_4b5a_6978_0f1e_2d3c_4b5a_6978_u128,
        0x8070_6050_4030_2010_8070_6050_4030_2010_u128,
    );

    let mut group = c.benchmark_group("fr_mul");

    group.bench_function("montgomery", |bench| {
        bench.iter(|| black_box(Bn254::mul(black_box(a), black_box(b))))
    });

    group.bench_function("legacy", |bench| {
        bench.iter(|| black_box(Bn254::mul_mod_legacy(black_box(a), black_box(b))))
    });

    group.finish();
}

criterion_group!(benches, bench_montgomery_vs_legacy);
criterion_main!(benches);
