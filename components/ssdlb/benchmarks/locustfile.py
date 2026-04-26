"""
SSDLB Load Test Benchmark — Locust-based performance testing.

Measures p95/p99 latency for SSDLB routing decisions and validates
that trend detection and spread-mode transitions work under load.

Usage:
    pip install locust
    locust -f locustfile.py --host=http://localhost:8082 --headless \
           -u 50 -r 5 --run-time 60s --csv=results/ssdlb_benchmark

Targets:
    - p95 auto-route latency < 200ms
    - p99 auto-route latency < 500ms
    - trend-debug < 50ms
    - state < 10ms
"""
from locust import HttpUser, task, between, events
from locust.runners import MasterRunner
import json
import time
import csv
import os


class SSDLBUser(HttpUser):
    """Simulates a controller calling SSDLB endpoints under normal load."""
    wait_time = between(0.5, 2.0)

    @task(5)
    def auto_route(self):
        """Most common operation: request auto-routing decision."""
        with self.client.post("/auto-route", catch_response=True) as resp:
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status", "unknown")
                # All valid statuses are acceptable
                valid = {"ok", "cooldown", "warming-up", "no-metrics",
                         "predictive-spread", "spread-hold", "spread-continue",
                         "recovered-to-single", "low-traffic", "no-switch",
                         "icap-health-spread"}
                if status in valid:
                    resp.success()
                else:
                    resp.failure(f"Unexpected status: {status}")
            else:
                resp.failure(f"HTTP {resp.status_code}")

    @task(3)
    def trend_debug(self):
        """Check traffic trend data."""
        with self.client.get("/trend-debug", catch_response=True) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}")

    @task(2)
    def get_state(self):
        """Poll controller state."""
        with self.client.get("/state", catch_response=True) as resp:
            if resp.status_code == 200:
                data = resp.json()
                if "mode" in data:
                    resp.success()
                else:
                    resp.failure("Missing 'mode' in state response")
            else:
                resp.failure(f"HTTP {resp.status_code}")

    @task(1)
    def queue_depth(self):
        """Check queue depth (Prometheus may be unreachable in test — that's OK)."""
        with self.client.get("/queue-depth", catch_response=True) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}")

    @task(1)
    def get_registry(self):
        """Check service registry."""
        with self.client.get("/registry", catch_response=True) as resp:
            if resp.status_code == 200 and "registry" in resp.json():
                resp.success()
            else:
                resp.failure("Bad registry response")


class SSDLBRegistrationUser(HttpUser):
    """Simulates dynamic service registration traffic."""
    wait_time = between(5.0, 15.0)

    @task
    def register_and_deregister(self):
        """Register a temporary version then deregister it."""
        version = f"bench-{int(time.time() * 1000) % 10000}"
        reg_resp = self.client.post(
            f"/register/{version}",
            json={"version": version, "healthy": True, "weight": 1},
        )
        if reg_resp.status_code == 200:
            time.sleep(0.1)
            self.client.delete(f"/register/{version}")

    @task
    def generate_dr(self):
        """Generate a DestinationRule manifest dynamically."""
        with self.client.get("/generate-dr/a", catch_response=True) as resp:
            if resp.status_code == 200 and "yaml" in resp.json():
                resp.success()
            else:
                resp.failure("Bad DR generation response")


# ── Result summary hook ────────────────────────────────────────────────────────

@events.quitting.add_listener
def on_locust_quitting(environment, **kwargs):
    """Print p95/p99 summary when test finishes."""
    stats = environment.stats
    print("\n" + "="*60)
    print("SSDLB BENCHMARK RESULTS")
    print("="*60)
    for name, entry in stats.entries.items():
        if entry.num_requests == 0:
            continue
        print(f"\n{name[1]} {name[0]}")
        print(f"  Requests:    {entry.num_requests}")
        print(f"  Failures:    {entry.num_failures} ({entry.fail_ratio*100:.1f}%)")
        print(f"  Median (ms): {entry.median_response_time}")
        print(f"  p95 (ms):    {entry.get_response_time_percentile(0.95)}")
        print(f"  p99 (ms):    {entry.get_response_time_percentile(0.99)}")
        print(f"  Max (ms):    {entry.max_response_time}")

    total = stats.total
    p95 = total.get_response_time_percentile(0.95)
    p99 = total.get_response_time_percentile(0.99)

    print(f"\n{'='*60}")
    print(f"OVERALL  p95={p95}ms  p99={p99}ms")
    if p95 and p95 < 200:
        print("✓ p95 latency target met (<200ms)")
    elif p95:
        print(f"✗ p95 latency target MISSED (target <200ms, actual {p95}ms)")
    if p99 and p99 < 500:
        print("✓ p99 latency target met (<500ms)")
    elif p99:
        print(f"✗ p99 latency target MISSED (target <500ms, actual {p99}ms)")
    print("="*60)
