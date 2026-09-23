from jevguard.collectors.host import account_change_events, file_change_events


def test_detects_privileged_group_change():
    previous = {"users": {}, "groups": {"wheel": ["alice"]}}
    current = {"users": {}, "groups": {"wheel": ["alice", "mallory"]}}
    events = account_change_events(previous, current)
    assert len(events) == 1
    assert events[0].event_type == "group_membership_changed"
    assert events[0].severity == "high"


def test_detects_persistence_file_creation():
    events = file_change_events({}, {"/etc/systemd/system/x.service": {"sha256": "a"}})
    assert events == []  # first observation establishes a baseline
    events = file_change_events(
        {"/etc/systemd/system/a.service": {"sha256": "a"}},
        {
            "/etc/systemd/system/a.service": {"sha256": "a"},
            "/etc/systemd/system/x.service": {"sha256": "b"},
        },
    )
    assert events[0].category == "persistence"
    assert events[0].severity == "high"


def test_user_systemd_unit_is_high_severity_persistence():
    path = "/home/alice/.config/systemd/user/implant.service"
    events = file_change_events(
        {"/home/alice/.profile": {"sha256": "a"}},
        {
            "/home/alice/.profile": {"sha256": "a"},
            path: {"sha256": "b"},
        },
    )
    assert len(events) == 1
    assert events[0].category == "persistence"
    assert events[0].severity == "high"
