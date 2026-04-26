# SSDLB Benchmarks

## Running the Load Test

Install locust:
```bash
pip install locust
```

Run against a local SSDLB instance:
```bash
cd components/ssdlb/benchmarks
locust -f locustfile.py --host=http://localhost:8082 \
       --headless -u 50 -r 5 --run-time 60s \
       --csv=results/ssdlb_benchmark
```

Results are written to `results/ssdlb_benchmark_*.csv`.

## SLO Targets

| Metric | Target |
|--------|--------|
| p95 auto-route latency | < 200ms |
| p99 auto-route latency | < 500ms |
| p95 trend-debug latency | < 50ms |
| Error rate | < 0.1% |

## Interpreting Results

- `ok` status: normal single-mode routing
- `cooldown` status: guardrail active (expected under sustained load)
- `no-metrics`: Prometheus unreachable (expected in isolated benchmark)
- `predictive-spread`: spreading due to detected traffic spike
