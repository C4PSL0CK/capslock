# SSDLB — Smarter Service Discovery & Load Balancing

**Component 3 of CAPSLOCK** | Go | Port 8082

## Overview

SSDLB provides ICAP-health-aware traffic routing for CAPSLOCK. Unlike traditional load balancers that only consider request rates, SSDLB continuously queries the ICAP Operator's health scores and factors them into routing decisions. A degraded ICAP instance receives inflated effective load, pushing traffic away before it becomes a bottleneck.

It also detects traffic spikes predictively and spreads load across all ICAP instances before saturation occurs.

## Features

- **ICAP-health-weighted routing** — effective load = actual rate × health penalty
- **Predictive spread mode** — enters multi-instance mode on early traffic growth signal
- **Automatic recovery** — collapses back to single-instance routing when traffic stabilises
- **Force-spread guardrail** — if aggregate ICAP health drops below 70, all instances receive traffic regardless of load distribution
- **Cooldown protection** — 60s lock after any routing decision to prevent flapping
- **Minimum improvement threshold** — routing only switches if the new instance is at least 20% better

## Routing Decision Logic

```
Every tick:
  1. If seconds_since_switch < 60s → no_change (cooldown)
  2. If aggregate_icap_health < 70  → force_spread (health guardrail)
  3. If mode == spread:
       If traffic_growth <= 3%      → collapse_to_single (recovered)
       Else                         → no_change (spread_continue)
  4. If mode == single:
       If traffic_growth >= 8%      → enter_spread (spike detected)
       Else compare weighted rates  → route to best or no_change
```

## Health Penalty Formula

```
effective_load(v) = actual_rate(v)
    if health(v) >= 60 (healthy floor)

effective_load(v) = actual_rate(v) × (1 + 3.0 × (60 − health(v)) / 60)
    if health(v) < 60
```

Unhealthy instances attract up to 4x their actual load in penalty, making the router prefer their healthier peers.

## Routing Thresholds

| Parameter | Value | Description |
|-----------|-------|-------------|
| Spread entry | 8% growth | 1-min rate vs 5-min average |
| Spread exit | 3% growth | Threshold to collapse back to single |
| Force-spread | health < 70 | Aggregate ICAP health trigger |
| Healthy floor | 60 | Below this, health penalty applies |
| Min improvement | 20% | Required gain before switching instance |
| Cooldown | 60s | Lock after any routing change |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service health check |
| GET | `/api/routing/decision` | Current routing mode and selected instance |
| GET | `/api/routing/stats` | Per-instance effective load and health scores |
| POST | `/api/routing/override` | Manual routing override (admin) |

## Traffic Switching Scenarios

8 canonical scenarios are demonstrated in `scripts/demo_traffic_switching.py` and the CAPSLOCK Validation tab:

| Scenario | Decision | Trigger |
|----------|----------|---------|
| Healthy baseline | no_change | All healthy, balanced load |
| Version A overloaded | route | A has 3x traffic, switch to B |
| Traffic spike | enter_spread | 25% growth above 5-min average |
| ICAP penalty on A | route | A health = 45 (below floor), effective load inflated |
| Critical ICAP health | force_spread | Aggregate = 58, below threshold 70 |
| Cooldown active | no_change | 30s since last switch (need 60s) |
| Recovery from spread | collapse_to_single | Growth 1% below 3% exit threshold |
| Marginal improvement | no_change | Best instance only 9% better (need 20%) |

Run the demo:

```bash
python scripts/demo_traffic_switching.py          # simulated
python scripts/demo_traffic_switching.py --live   # calls localhost:8082
```

## Build and Deploy

```bash
# Build
go build -o bin/ssdlb ./cmd/ssdlb

# Run
./bin/ssdlb --port 8082 --icap-health-url http://localhost:8081/api/icap/health

# Docker
docker build -t ssdlb:latest .

# Helm
helm install ssdlb ./charts/
```

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 8082 | Listening port |
| `--icap-health-url` | - | Policy engine health endpoint |
| `--spread-entry` | 0.08 | Traffic growth threshold to enter spread |
| `--spread-exit` | 0.03 | Growth threshold to exit spread |
| `--force-spread-health` | 70 | Aggregate health to force spread |
| `--cooldown` | 60s | Minimum time between routing changes |
| `--min-improvement` | 0.20 | Minimum gain to trigger a switch |

## Integration with Other Components

| Component | Interaction |
|-----------|-------------|
| Policy Engine | Reads aggregate and per-instance ICAP health |
| ICAP Operator | Health scores flow through policy engine bridge |
| MEDS | MEDS notifies policy engine of deployments; SSDLB routes scanning traffic |
