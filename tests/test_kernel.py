from jevguard.collectors.kernel import parse_kernel_record


def test_parses_ufw_block_record():
    event = parse_kernel_record({
        "MESSAGE": (
            "[UFW BLOCK] IN=enp1s0 OUT= MAC=x SRC=192.0.2.44 DST=192.0.2.10 "
            "PROTO=TCP SPT=51000 DPT=22"
        ),
        "__CURSOR": "kernel-1",
        "__REALTIME_TIMESTAMP": "1787699000100000",
    })
    assert event is not None
    assert event.event_type == "firewall_packet_blocked"
    assert event.source_ip == "192.0.2.44"
    assert event.destination_port == 22
