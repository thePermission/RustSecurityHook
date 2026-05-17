use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rsh::run_check;

fn bench_harmless(c: &mut Criterion) {
    let _ = c;
}

fn bench_blocked_k8s(c: &mut Criterion) {
    let _ = c;
}

fn bench_blocked_helm(c: &mut Criterion) {
    let _ = c;
}

fn bench_edge(c: &mut Criterion) {
    let _ = c;
}

criterion_group!(benches, bench_harmless, bench_blocked_k8s, bench_blocked_helm, bench_edge);
criterion_main!(benches);
