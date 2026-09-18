use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use velociredactor::{Allow, FormatHint, Redactor};

const SECRET: &str = "sk-ant-api03-xK9mZ2vL8nQ5rT1wY4bC7dF0gH3jE6pA";

/// A transcript-like JSONL document of roughly `lines` lines.
fn transcript(lines: usize) -> String {
    let mut out = String::new();
    for i in 0..lines {
        let text = if i % 50 == 0 {
            format!("here is the key {SECRET} for service {i}")
        } else {
            format!(
                "Reading file /tmp/project/src/module_{i}.rs and applying the requested change to line {i}"
            )
        };
        out.push_str(&format!(
            "{{\"type\":\"assistant\",\"uuid\":\"msg_{i:08x}\",\"message\":{{\"role\":\"assistant\",\"content\":[{{\"type\":\"text\",\"text\":\"{text}\"}}]}},\"cwd\":\"/tmp/project\"}}\n"
        ));
    }
    out
}

fn bench(c: &mut Criterion) {
    let redactor = Redactor::builder().build();
    let input = transcript(10_000);
    let mut group = c.benchmark_group("jsonl");
    group.throughput(Throughput::Bytes(input.len() as u64));
    group.sample_size(10);
    group.bench_function("redact_and_render", |b| {
        b.iter(|| {
            let redaction = redactor
                .redact(input.as_bytes(), FormatHint::Name("jsonl"))
                .unwrap();
            redaction.render(&Allow::none()).unwrap()
        })
    });
    group.finish();

    let text = transcript(10_000);
    let mut group = c.benchmark_group("text");
    group.throughput(Throughput::Bytes(text.len() as u64));
    group.sample_size(10);
    group.bench_function("redact_and_render", |b| {
        b.iter(|| {
            let redaction = redactor
                .redact(text.as_bytes(), FormatHint::Name("text"))
                .unwrap();
            redaction.render(&Allow::none()).unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
