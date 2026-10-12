"""The bulk 'fix the recommended ones' button must never decide something for you."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "LinuxGuardianSuite"))

from linuxguardian_ui.pages.hardening import bulk_candidates  # noqa: E402


def fx(fid, recommended=True, applied=False, kind="user"):
    return {"id": fid, "label": fid, "kind": kind, "effect": ["x"], "recommended": recommended, "caution": "", "applied": applied}


def chk(cid, state, fixes, title=None):
    return {"id": cid, "title": title or cid, "state": state, "fixes": fixes}


def test_only_single_recommended_unapplied_fixes_for_real_problems():
    checks = [
        chk("screen_sharing", "attention", [fx("vino_off"), fx("vino_prompt", recommended=False), fx("vino_tailscale", recommended=False)]),
        chk("screen_lock", "attention", [fx("screen_lock")]),
        chk("fw6", "attention", [fx("ufw_ipv6", kind="root")]),
        chk("done", "ok", [fx("x")]),
        chk("optional", "attention", [fx("y", recommended=False)]),
        chk("already", "attention", [fx("z", applied=True)]),
        chk("nofix", "attention", []),
        chk("info", "info", [fx("w")]),
    ]
    assert [f["id"] for f in bulk_candidates(checks)] == ["screen_lock", "ufw_ipv6"]


def test_a_choice_between_remedies_is_never_made_for_the_user():
    # Screen Sharing has a recommended option (turn off) but also alternatives: the person must pick.
    checks = [chk("screen_sharing", "attention", [fx("vino_off"), fx("vino_prompt", recommended=False)])]
    assert bulk_candidates(checks) == []
