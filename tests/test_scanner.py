import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from actionguard.scanner import load_known_compromised, scan_repo

FIXTURES = Path(__file__).parent / "fixtures"


def test_flags_mutable_tag_as_unpinned():
    findings = scan_repo(FIXTURES)
    unpinned = [f for f in findings if f.owner_repo.endswith("fake-action") and f.status == "UNPINNED"]
    assert len(unpinned) == 1
    assert unpinned[0].file.endswith("vulnerable-demo.yml")


def test_sha_pinned_action_is_not_flagged_unpinned():
    findings = scan_repo(FIXTURES)
    fixed = [f for f in findings if f.file.endswith("fixed-demo.yml") and "fake-action" in f.owner_repo]
    assert len(fixed) == 1
    assert fixed[0].status == "PINNED"
    assert fixed[0].severity == "INFO"


def test_known_compromised_action_is_flagged_critical():
    findings = scan_repo(FIXTURES)
    critical = [f for f in findings if f.owner_repo == "tj-actions/changed-files"]
    assert len(critical) == 1
    assert critical[0].severity == "CRITICAL"


def test_known_compromised_data_loads():
    known = load_known_compromised()
    assert "tj-actions/changed-files" in known
