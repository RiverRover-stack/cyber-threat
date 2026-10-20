import pytest

from cyberthreat.data_generator import ATTACK_TYPES, generate_logs
from cyberthreat.detection import detect_all, rule_detect
from cyberthreat.evaluation import event_metrics


@pytest.fixture(scope="module")
def logs():
    return generate_logs()


def test_logs_contain_all_attacks(logs):
    assert set(ATTACK_TYPES) <= set(logs.label)
    assert logs.event_id.is_unique


def test_every_attack_type_detected(logs):
    found = {a.attack_type for a in rule_detect(logs)}
    assert set(ATTACK_TYPES) <= found


def test_metrics_are_high(logs):
    m = event_metrics(logs, detect_all(logs))
    assert m["recall"] >= 0.95 and m["precision"] >= 0.9


def test_reproducible():
    assert generate_logs(seed=1).equals(generate_logs(seed=1))
