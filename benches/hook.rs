use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use rsh::run_check;

fn bench_harmless(c: &mut Criterion) {
    let commands = [
        "ls -la",
        "git status",
        "cargo build --release",
        "echo hello",
        "cat /tmp/file",
    ];
    let mut group = c.benchmark_group("harmless");
    for cmd in commands {
        group.bench_with_input(BenchmarkId::from_parameter(cmd), cmd, |b, cmd| {
            b.iter(|| black_box(run_check(black_box(cmd))));
        });
    }
    group.finish();
}

fn bench_blocked_k8s(c: &mut Criterion) {
    let commands = [
        "kubectl delete ns production",
        "kubectl delete --all -n default",
        "kubectl delete crd mykind",
    ];
    let mut group = c.benchmark_group("blocked_k8s");
    for cmd in commands {
        group.bench_with_input(BenchmarkId::from_parameter(cmd), cmd, |b, cmd| {
            b.iter(|| black_box(run_check(black_box(cmd))));
        });
    }
    group.finish();
}

fn bench_blocked_helm(c: &mut Criterion) {
    let commands = ["helm uninstall my-release", "helm rollback my-release 0"];
    let mut group = c.benchmark_group("blocked_helm");
    for cmd in commands {
        group.bench_with_input(BenchmarkId::from_parameter(cmd), cmd, |b, cmd| {
            b.iter(|| black_box(run_check(black_box(cmd))));
        });
    }
    group.finish();
}

fn bench_edge(c: &mut Criterion) {
    let long_cmd = "x".repeat(10_000);
    let mut group = c.benchmark_group("edge");
    group.bench_function("empty", |b| {
        b.iter(|| black_box(run_check(black_box(""))));
    });
    group.bench_function("10k_chars", |b| {
        b.iter(|| black_box(run_check(black_box(long_cmd.as_str()))));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_harmless,
    bench_blocked_k8s,
    bench_blocked_helm,
    bench_edge
);
criterion_main!(benches);
