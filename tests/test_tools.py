import asyncio

import pytest

from app.controls import TOOL_NAMES, controls
from app.services import fixtures
from app.tools import it_tools
from app.tools.it_tools import TOOLS


def run(coro):
    return asyncio.run(coro)


def call(tool, user_id="emp_001"):
    if tool == "search_it_knowledge":
        return run(TOOLS[tool]("vpn keeps dropping", user_id=user_id))
    return run(TOOLS[tool](user_id))


RESULT_KEYS = {"tool", "ok", "mode", "data", "error", "error_type", "latency_ms"}


# ---- each tool x each mode -------------------------------------------------

@pytest.mark.parametrize("tool", TOOL_NAMES)
def test_tool_ok_mode(tool):
    r = call(tool)
    assert set(r) == RESULT_KEYS
    assert r["ok"] is True and r["mode"] == "ok" and r["error"] is None
    assert isinstance(r["data"], dict) and r["latency_ms"] >= 0


@pytest.mark.parametrize("tool", TOOL_NAMES)
def test_tool_error_mode(tool):
    controls.set_tool_mode(tool, "error")
    r = call(tool)
    assert r["ok"] is False and r["mode"] == "error"
    assert r["data"] is None and r["error_type"] == "error" and r["error"]


@pytest.mark.parametrize("tool", TOOL_NAMES)
def test_tool_slow_mode(tool):
    controls.set_tool_mode(tool, "slow")
    r = call(tool)
    assert r["ok"] is True and r["mode"] == "slow"
    assert r["latency_ms"] >= controls.slow_delay_s * 1000 * 0.9


def test_invalid_mode_and_tool_rejected():
    with pytest.raises(ValueError):
        controls.set_tool_mode("check_vpn_status", "explode")
    with pytest.raises(ValueError):
        controls.set_tool_mode("reset_password", "ok")


def test_unknown_user_returns_structured_error():
    r = run(it_tools.check_account_status("emp_999"))
    assert r["ok"] is False and r["error_type"] == "not_found"


# ---- fixture scenarios -----------------------------------------------------

def test_fixtures_have_seven_employees_with_laptops():
    ids = fixtures.list_user_ids()
    assert ids == [f"emp_00{i}" for i in range(1, 8)]
    for uid in ids:
        u = fixtures.get_user(uid)
        assert u["name"] and u["laptop_id"]


def test_emp_001_vpn_auth_timeout_old_client():
    d = run(it_tools.check_vpn_status("emp_001"))["data"]
    assert d["drops_last_hour"] == 3 and d["last_drop_reason"] == "auth_timeout"
    assert d["client_version"] == "4.1" and d["latest_version"] == "5.2"
    assert d["gateway_status"] == "healthy"
    kb = run(it_tools.search_it_knowledge("VPN drops with auth timeout"))["data"]["matches"]
    assert kb[0]["id"] == "KB-VPN-001"


def test_emp_002_locked_account():
    d = run(it_tools.check_account_status("emp_002"))["data"]
    assert d["locked"] is True and d["failed_attempts"] == 5 and d["auto_unlock_minutes"] == 30
    kb = run(it_tools.search_it_knowledge("my account is locked out"))["data"]["matches"]
    assert kb[0]["id"] == "KB-ACC-002"


def test_emp_003_healthy_and_no_kb_match_for_outlook():
    for tool in ("check_account_status", "check_vpn_status", "check_device_status", "check_network_status"):
        assert call(tool, "emp_003")["ok"] is True
    r = run(it_tools.search_it_knowledge("Outlook shows an unknown error when opening", user_id="emp_003"))
    assert r["ok"] is True and r["data"]["matches"] == []


def test_emp_004_network_tool_fails_via_fixture_flag():
    r = run(it_tools.check_network_status("emp_004"))
    assert r["ok"] is False and r["error_type"] == "timeout"
    # other tools for emp_004 are fine
    assert run(it_tools.check_vpn_status("emp_004"))["ok"] is True
    # other users' network checks are fine
    assert run(it_tools.check_network_status("emp_001"))["ok"] is True


def test_runtime_mode_overrides_fixture_flag():
    controls.set_tool_mode("check_network_status", "slow")
    r = run(it_tools.check_network_status("emp_004"))
    assert r["mode"] == "slow" and r["ok"] is True


def test_emp_005_edr_alert_and_suspicious_signins():
    dev = run(it_tools.check_device_status("emp_005"))["data"]
    acc = run(it_tools.check_account_status("emp_005"))["data"]
    assert dev["edr_alerts"] and dev["edr_alerts"][0]["severity"] == "high"
    assert len(acc["suspicious_signins"]) >= 1


def test_emp_006_recent_password_change_unknown_location():
    acc = run(it_tools.check_account_status("emp_006"))["data"]
    assert acc["recent_password_change"]["known_location"] is False


def test_emp_007_nothing_notable():
    acc = run(it_tools.check_account_status("emp_007"))["data"]
    dev = run(it_tools.check_device_status("emp_007"))["data"]
    assert not acc["locked"] and not acc["suspicious_signins"] and not acc["recent_password_change"]
    assert dev["laptop_id"] == "LT-007" and not dev["edr_alerts"]


def test_troubleshooter_behavior_default_and_override():
    assert fixtures.troubleshooter_behavior("emp_001") == "ok"
    assert fixtures.troubleshooter_behavior("emp_007") == "ok"  # field omitted -> default
    controls.set_troubleshooter_behavior("hallucinate_once")
    assert fixtures.troubleshooter_behavior("emp_001") == "hallucinate_once"
    with pytest.raises(ValueError):
        controls.set_troubleshooter_behavior("lie")


def test_tools_are_read_only():
    before = fixtures.get_user("emp_002")
    r = run(it_tools.check_account_status("emp_002"))
    r["data"]["locked"] = False  # mutate result
    assert fixtures.get_user("emp_002") == before
    assert set(TOOLS) == set(TOOL_NAMES)
