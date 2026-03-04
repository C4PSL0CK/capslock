#!/usr/bin/env python3
"""
Traffic Switching Demonstration — PP2
======================================
Simulates the SSDLB routing decision engine across 8 progressively complex
scenarios and prints a metric comparison table.

Covers panel feedback:
  "Traffic switching demonstration should be planned for PP2.
   Metric based comparisons to be done for validation."

Usage:
  # Standalone simulation (no services needed):
  python3 scripts/demo_traffic_switching.py

  # Against live services:
  python3 scripts/demo_traffic_switching.py --live
"""
import sys
import argparse
import json
import time
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# Inline routing engine (mirrors ssdlb/controller/main.py logic)
# ---------------------------------------------------------------------------

ICAP_HEALTH_SPREAD_THRESHOLD = 70
ICAP_INSTANCE_HEALTHY_FLOOR  = 60
TREND_ENTER_GROWTH_RATIO     = 0.08
TREND_EXIT_GROWTH_RATIO      = 0.03
COOLDOWN_SECONDS             = 60
MIN_CHANGE_RATIO             = 0.20


@dataclass
class RouterState:
    mode: str = "single"           # single | spread
    selected: str = "a"
    last_switch_ts: float = 0.0
    spread_since_ts: float = 0.0


@dataclass
class ScenarioInput:
    name: str
    description: str
    # Per-version request rates (req/s)
    rates: dict = field(default_factory=lambda: {"a": 10.0, "b": 10.0, "c": 10.0})
    # Short (1m) vs medium (5m) total rates for trend detection
    short_rate: float = 30.0
    medium_rate: float = 30.0
    # ICAP health per version (0-100)
    icap_health: dict = field(default_factory=lambda: {"a": 92, "b": 91, "c": 90})
    # Aggregate ICAP health
    icap_aggregate: int = 91
    # Current router state before this decision
    state: RouterState = field(default_factory=RouterState)
    # Seconds since last switch (for cooldown)
    seconds_since_switch: float = 120.0


def health_weighted_rates(rates: dict, icap_instances: dict) -> dict:
    weighted = {}
    for ver, rate in rates.items():
        score = icap_instances.get(ver, {}).get("health_score", 100)
        if score < ICAP_INSTANCE_HEALTHY_FLOOR:
            penalty = 3.0 * (ICAP_INSTANCE_HEALTHY_FLOOR - score) / ICAP_INSTANCE_HEALTHY_FLOOR
            weighted[ver] = rate * (1.0 + penalty)
        else:
            weighted[ver] = rate
    return weighted


def decide(scenario: ScenarioInput) -> dict:
    """
    Simulate one SSDLB auto-route decision cycle.
    Returns a dict describing the decision and reasoning.
    """
    s = scenario.state
    now = 1000.0  # fixed synthetic timestamp
    instances = {v: {"health_score": h, "ready": h > 0}
                 for v, h in scenario.icap_health.items()}

    # --- Guardrail: cooldown ---
    if scenario.seconds_since_switch < COOLDOWN_SECONDS:
        return {
            "decision": "no_change",
            "mode": s.mode,
            "selected": s.selected,
            "reason": f"cooldown ({scenario.seconds_since_switch:.0f}s < {COOLDOWN_SECONDS}s)",
            "event": "guardrail_cooldown",
        }

    # --- ICAP health gate: force spread if aggregate too low ---
    if scenario.icap_aggregate < ICAP_HEALTH_SPREAD_THRESHOLD:
        new_mode = "spread"
        return {
            "decision": "spread" if s.mode != "spread" else "no_change",
            "mode": new_mode,
            "selected": "all",
            "reason": f"ICAP health {scenario.icap_aggregate} < threshold {ICAP_HEALTH_SPREAD_THRESHOLD}",
            "event": "icap_health_forced_spread",
            "icap_aggregate": scenario.icap_aggregate,
        }

    # --- Spread mode recovery ---
    if s.mode == "spread":
        if scenario.medium_rate == 0:
            return {"decision": "no_change", "mode": "spread", "selected": "all",
                    "reason": "spread: no traffic data", "event": "spread_continue"}

        growth = (scenario.short_rate - scenario.medium_rate) / scenario.medium_rate
        if growth <= TREND_EXIT_GROWTH_RATIO:
            weighted = health_weighted_rates(scenario.rates, instances)
            best = min(weighted, key=weighted.get)
            return {
                "decision": "collapse_to_single",
                "mode": "single",
                "selected": best,
                "reason": f"traffic growth {growth:.1%} <= exit threshold {TREND_EXIT_GROWTH_RATIO:.1%}",
                "event": "recovered_to_single",
                "growth": f"{growth:.1%}",
            }
        return {
            "decision": "no_change", "mode": "spread", "selected": "all",
            "reason": f"traffic growth {growth:.1%} > exit threshold {TREND_EXIT_GROWTH_RATIO:.1%}",
            "event": "spread_continue",
        }

    # --- Single mode: trend-based spread entry ---
    if scenario.medium_rate > 0:
        growth = (scenario.short_rate - scenario.medium_rate) / scenario.medium_rate
        if growth >= TREND_ENTER_GROWTH_RATIO:
            return {
                "decision": "enter_spread",
                "mode": "spread",
                "selected": "all",
                "reason": f"traffic growth {growth:.1%} >= enter threshold {TREND_ENTER_GROWTH_RATIO:.1%}",
                "event": "predictive_spread_entered",
                "growth": f"{growth:.1%}",
            }

    # --- Single mode: pick best version ---
    weighted = health_weighted_rates(scenario.rates, instances)
    best = min(weighted, key=weighted.get)
    current = s.selected

    if best != current:
        current_load  = weighted.get(current, 0)
        best_load     = weighted.get(best, 0)
        if current_load > 0:
            improvement = (current_load - best_load) / current_load
            if improvement < MIN_CHANGE_RATIO:
                return {
                    "decision": "no_change",
                    "mode": "single",
                    "selected": current,
                    "reason": f"improvement {improvement:.1%} < min {MIN_CHANGE_RATIO:.1%}",
                    "event": "no_switch_min_change",
                }

    icap_penalty = any(
        scenario.icap_health.get(v, 100) < ICAP_INSTANCE_HEALTHY_FLOOR
        for v in ["a", "b", "c"]
    )
    return {
        "decision": "route" if best != current else "no_change",
        "mode": "single",
        "selected": best,
        "reason": f"lowest effective load (weighted rates: {', '.join(f'{v}={weighted[v]:.1f}' for v in sorted(weighted))})",
        "event": "ok",
        "icap_penalty_applied": icap_penalty,
    }


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

SCENARIOS = [
    ScenarioInput(
        name="1. Healthy baseline",
        description="All 3 versions healthy, balanced load. Expect: stay on current version.",
        rates={"a": 10.0, "b": 10.0, "c": 10.0},
        short_rate=30.0, medium_rate=30.0,
        icap_health={"a": 94, "b": 91, "c": 90},
        icap_aggregate=92,
        state=RouterState(mode="single", selected="a"),
        seconds_since_switch=120,
    ),
    ScenarioInput(
        name="2. Version A overloaded",
        description="Version A has 3x the load. Expect: switch to B or C.",
        rates={"a": 30.0, "b": 10.0, "c": 10.0},
        short_rate=50.0, medium_rate=50.0,
        icap_health={"a": 91, "b": 92, "c": 90},
        icap_aggregate=91,
        state=RouterState(mode="single", selected="a"),
        seconds_since_switch=120,
    ),
    ScenarioInput(
        name="3. Traffic spike detected",
        description="1m rate 25% above 5m average. Expect: enter spread mode.",
        rates={"a": 12.5, "b": 12.5, "c": 12.5},
        short_rate=37.5, medium_rate=30.0,   # 25% growth
        icap_health={"a": 92, "b": 91, "c": 90},
        icap_aggregate=91,
        state=RouterState(mode="single", selected="b"),
        seconds_since_switch=120,
    ),
    ScenarioInput(
        name="4. Degraded ICAP on version A",
        description="Version A ICAP health drops below floor (60). Expect: penalty applied, route away from A.",
        rates={"a": 10.0, "b": 10.5, "c": 11.0},
        short_rate=31.5, medium_rate=31.5,
        icap_health={"a": 45, "b": 91, "c": 90},   # A below floor
        icap_aggregate=75,
        state=RouterState(mode="single", selected="a"),
        seconds_since_switch=120,
    ),
    ScenarioInput(
        name="5. Aggregate ICAP health critically low",
        description="Overall ICAP health below spread threshold (70). Expect: force spread mode.",
        rates={"a": 10.0, "b": 10.0, "c": 10.0},
        short_rate=30.0, medium_rate=30.0,
        icap_health={"a": 55, "b": 60, "c": 58},
        icap_aggregate=58,   # below threshold
        state=RouterState(mode="single", selected="b"),
        seconds_since_switch=120,
    ),
    ScenarioInput(
        name="6. Cooldown active after recent switch",
        description="Only 30s since last routing change. Expect: no change (cooldown).",
        rates={"a": 5.0, "b": 20.0, "c": 5.0},
        short_rate=30.0, medium_rate=30.0,
        icap_health={"a": 92, "b": 91, "c": 90},
        icap_aggregate=91,
        state=RouterState(mode="single", selected="a"),
        seconds_since_switch=30,  # cooldown not expired
    ),
    ScenarioInput(
        name="7. Recovery from spread mode",
        description="Traffic has stabilised after spike (growth 1% < 3% exit threshold). Expect: collapse to single.",
        rates={"a": 10.0, "b": 10.2, "c": 9.8},
        short_rate=30.3, medium_rate=30.0,   # 1% growth — below exit threshold
        icap_health={"a": 92, "b": 91, "c": 90},
        icap_aggregate=91,
        state=RouterState(mode="spread", selected="all"),
        seconds_since_switch=180,
    ),
    ScenarioInput(
        name="8. Marginal improvement below min-change threshold",
        description="Best version only 10% better than current (need 20%). Expect: no switch.",
        rates={"a": 10.0, "b": 9.1, "c": 10.5},   # B is 9% better than A
        short_rate=29.6, medium_rate=29.6,
        icap_health={"a": 91, "b": 92, "c": 90},
        icap_aggregate=91,
        state=RouterState(mode="single", selected="a"),
        seconds_since_switch=120,
    ),
]


# ---------------------------------------------------------------------------
# Live mode: call real SSDLB API
# ---------------------------------------------------------------------------

def call_live_auto_route(base_url: str) -> Optional[dict]:
    if not HAS_REQUESTS:
        return None
    try:
        r = _requests.post(f"{base_url}/auto-route", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


def call_live_state(base_url: str) -> Optional[dict]:
    if not HAS_REQUESTS:
        return None
    try:
        r = _requests.get(f"{base_url}/state", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

COL_W = [32, 14, 12, 14, 52]
SEP   = "+" + "+".join("-" * (w + 2) for w in COL_W) + "+"
HDR   = ("| {:<{}} | {:<{}} | {:<{}} | {:<{}} | {:<{}} |").format(
    "Scenario", COL_W[0],
    "Decision",  COL_W[1],
    "Mode",      COL_W[2],
    "Selected",  COL_W[3],
    "Reason",    COL_W[4],
)

ANSI = {
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "red":    "\033[91m",
    "cyan":   "\033[96m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

def colour(text: str, name: str) -> str:
    return f"{ANSI[name]}{text}{ANSI['reset']}"

def decision_colour(d: str) -> str:
    if d in ("route", "collapse_to_single", "enter_spread"):
        return colour(d, "green")
    if d == "no_change":
        return colour(d, "yellow")
    if "forced" in d or "icap_health" in d:
        return colour(d, "red")
    return d


def print_table(results: list):
    print()
    print(colour("  CAPSLOCK — SSDLB Traffic Switching Demonstration", "bold"))
    print(colour(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "cyan"))
    print()
    print(SEP)
    print(HDR)
    print(SEP)
    for row in results:
        s_name  = row["scenario"][:COL_W[0]]
        decision = row["result"]["decision"][:COL_W[1]]
        mode     = row["result"]["mode"][:COL_W[2]]
        selected = row["result"]["selected"][:COL_W[3]]
        reason   = row["result"]["reason"][:COL_W[4]]
        print(("| {:<{}} | {:<{}} | {:<{}} | {:<{}} | {:<{}} |").format(
            s_name, COL_W[0],
            decision, COL_W[1],
            mode, COL_W[2],
            selected, COL_W[3],
            reason, COL_W[4],
        ))
    print(SEP)


def print_metric_comparison(results: list):
    print()
    print(colour("  Metric Comparison — Before vs After Each Scenario", "bold"))
    print()

    headers = ["Scenario", "ICAP Agg.", "Traffic Growth", "Active Mode", "Routed To", "Event"]
    widths  = [32, 10, 15, 12, 10, 32]
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    hdr = "| " + " | ".join(f"{h:<{widths[i]}}" for i, h in enumerate(headers)) + " |"
    print(sep)
    print(hdr)
    print(sep)

    for row in results:
        s   = row["scenario_obj"]
        r   = row["result"]
        growth = ""
        if s.medium_rate > 0:
            g = (s.short_rate - s.medium_rate) / s.medium_rate
            growth = f"{g:+.1%}"

        icap_agg = str(s.icap_aggregate)
        mode     = r["mode"]
        selected = r["selected"]
        event    = r.get("event", "")

        # Colour-code based on health
        if s.icap_aggregate < ICAP_HEALTH_SPREAD_THRESHOLD:
            icap_agg = colour(icap_agg, "red")
        elif s.icap_aggregate < 80:
            icap_agg = colour(icap_agg, "yellow")
        else:
            icap_agg = colour(icap_agg, "green")

        cols = [s.name[:widths[0]], icap_agg, growth, mode, selected, event]
        raw_widths = widths[:]
        # pad manually (ANSI codes don't count in width)
        row_str = "| "
        for i, col in enumerate(cols):
            visible_len = len(col) - (len(col) - len(col.replace("\033[", "").split("m", 1)[-1]) - 5 if "\033[" in col else 0)
            pad = raw_widths[i] - len(col.replace(f"\033[{col.split('[')[1].split('m')[0]}m", "").replace("\033[0m", "")) if "\033[" in col else raw_widths[i] - len(col)
            row_str += col + " " * max(0, pad) + " | "
        print(row_str)

    print(sep)


def print_summary(results: list):
    print()
    print(colour("  Summary", "bold"))
    print()

    decisions = [r["result"]["decision"] for r in results]
    events    = [r["result"].get("event", "") for r in results]

    counts = {}
    for d in decisions:
        counts[d] = counts.get(d, 0) + 1

    for decision, count in sorted(counts.items()):
        icon = "+" if decision in ("route", "collapse_to_single", "enter_spread") else "-"
        print(f"  {icon} {decision:<30} {count} scenario(s)")

    print()
    print("  ICAP health gate triggered:", sum(1 for e in events if "icap" in e), "time(s)")
    print("  Cooldown guardrail fired:  ", sum(1 for e in events if "cooldown" in e), "time(s)")
    print("  Spread mode entered:       ", sum(1 for d in decisions if "spread" in d), "time(s)")
    print("  Recovery to single:        ", sum(1 for d in decisions if d == "collapse_to_single"), "time(s)")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CAPSLOCK SSDLB traffic switching demo")
    parser.add_argument("--live", action="store_true",
                        help="Call the live SSDLB API at localhost:8082 for the current state")
    parser.add_argument("--ssdlb-url", default="http://localhost:8082",
                        help="SSDLB base URL (default: http://localhost:8082)")
    args = parser.parse_args()

    print()
    print(colour("=" * 90, "bold"))
    print(colour("  CAPSLOCK — Traffic Switching Demo (PP2 Validation)", "bold"))
    print(colour("=" * 90, "bold"))

    # --- Live state snapshot (optional) ---
    if args.live and HAS_REQUESTS:
        print()
        print(colour("  Live SSDLB State", "bold"))
        state = call_live_state(args.ssdlb_url)
        if state and "error" not in state:
            print(f"  Mode:     {state.get('mode', 'N/A')}")
            print(f"  Selected: {state.get('last_selected', 'N/A')}")
            print(f"  Since:    {state.get('last_switch_ts', 'N/A')}")
        else:
            print(f"  Could not reach SSDLB at {args.ssdlb_url}: {state}")

        print()
        print(colour("  Live auto-route decision:", "bold"))
        decision = call_live_auto_route(args.ssdlb_url)
        print(f"  {json.dumps(decision, indent=4)}")
        print()

    # --- Simulated scenarios ---
    print()
    print(colour("  Running 8 routing scenarios...", "cyan"))
    print()

    results = []
    for s in SCENARIOS:
        result = decide(s)
        results.append({"scenario": s.name, "scenario_obj": s, "result": result})
        # Brief per-scenario output
        event  = result.get("event", "")
        symbol = colour("OK", "green") if result["decision"] != "no_change" else colour("--", "yellow")
        if "icap_health" in event or "forced" in event:
            symbol = colour("!!", "red")
        print(f"  [{symbol}] {s.name}")
        print(f"       {s.description}")
        print(f"       -> {result['decision'].upper()} | mode={result['mode']} | to={result['selected']}")
        print(f"          {result['reason']}")
        print()

    # --- Comparison tables ---
    print_table(results)
    print()
    print_metric_comparison(results)
    print_summary(results)

    print(colour("=" * 90, "bold"))
    print()


if __name__ == "__main__":
    main()
