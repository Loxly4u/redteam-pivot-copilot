import json

from pivot_copilot.engagement_log import EngagementLog
from pivot_copilot.suggestions import Suggestion


def _suggestion():
    return Suggestion(
        suggestion_id="h1-exploit-smb-445",
        technique_id="T1210",
        technique_name="Exploitation of Remote Services",
        target_host="h1",
        rationale="test rationale",
        risk="high",
    )


def test_record_approved_decision():
    log = EngagementLog()
    decision = log.record(_suggestion(), approved=True, operator_note="validated in lab")
    assert decision.status == "approved"
    assert decision.operator_note == "validated in lab"
    assert len(log.decisions) == 1


def test_record_rejected_decision():
    log = EngagementLog()
    log.record(_suggestion(), approved=False)
    assert log.decisions[0].status == "rejected"
    assert log.approved_decisions() == []


def test_approved_decisions_filters_correctly():
    log = EngagementLog()
    log.record(_suggestion(), approved=True)
    log.record(_suggestion(), approved=False)
    assert len(log.approved_decisions()) == 1


def test_save_writes_valid_json(tmp_path):
    log = EngagementLog()
    log.record(_suggestion(), approved=True)
    out_path = tmp_path / "log.json"
    log.save(out_path)

    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert len(data["decisions"]) == 1
    assert data["decisions"][0]["status"] == "approved"


def test_log_never_contains_execution_fields():
    """Sanity check that the log schema only records decisions, not actions taken."""
    log = EngagementLog()
    decision = log.record(_suggestion(), approved=True)
    fields = decision.__dict__.keys()
    assert "executed" not in fields
    assert "exploit_result" not in fields
