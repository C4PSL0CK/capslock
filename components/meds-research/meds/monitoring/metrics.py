from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# Promotion metrics
promotion_requests_total = Counter(
    'meds_promotion_requests_total',
    'Total promotion requests',
    ['environment', 'status']
)

promotion_decision_total = Counter(
    'meds_promotion_decision_total',
    'Promotion decisions',
    ['decision', 'source_env', 'target_env']
)

risk_score_distribution = Histogram(
    'meds_risk_score_distribution',
    'Distribution of risk scores',
    ['environment'],
    buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
)

policy_evaluation_duration = Histogram(
    'meds_policy_evaluation_duration_seconds',
    'Time spent evaluating policies',
    ['policy_count_range']
)

active_promotions = Gauge(
    'meds_active_promotions',
    'Number of active promotions'
)

environment_risk_threshold = Gauge(
    'meds_environment_risk_threshold',
    'Risk threshold by environment',
    ['environment']
)

policy_changes_total = Counter(
    'meds_policy_changes_total',
    'Total policy changes',
    ['action', 'policy_name']
)

api_request_duration = Histogram(
    'meds_api_request_duration_seconds',
    'API request duration',
    ['method', 'endpoint', 'status_code']
)

def record_promotion_request(environment: str, status: str):
    promotion_requests_total.labels(environment=environment, status=status).inc()

def record_promotion_decision(decision: str, source_env: str, target_env: str):
    promotion_decision_total.labels(decision=decision, source_env=source_env, target_env=target_env).inc()

def record_risk_score(score: int, environment: str):
    risk_score_distribution.labels(environment=environment).observe(score)

def record_policy_evaluation_time(duration: float, policy_count: int):
    if policy_count == 0:
        range_label = "0"
    elif policy_count <= 2:
        range_label = "1-2"
    elif policy_count <= 5:
        range_label = "3-5"
    else:
        range_label = "6+"
    policy_evaluation_duration.labels(policy_count_range=range_label).observe(duration)

def set_active_promotions(count: int):
    active_promotions.set(count)

def set_environment_threshold(environment: str, threshold: int):
    environment_risk_threshold.labels(environment=environment).set(threshold)

def record_policy_change(action: str, policy_name: str):
    policy_changes_total.labels(action=action, policy_name=policy_name).inc()

def get_metrics():
    return generate_latest()
