from pathlib import Path

from jevguard.collectors.network import collect_network


def test_parses_tcp_listener(tmp_path: Path):
    proc = tmp_path / "net"
    proc.mkdir()
    process_root = tmp_path / "proc"
    process = process_root / "123"
    (process / "fd").mkdir(parents=True)
    (process / "comm").write_text("web-test\n")
    (process / "cmdline").write_bytes(b"python\0-m\0http.server\0")
    (process / "status").write_text("Name:\tweb-test\nUid:\t1000 1000 1000 1000\n")
    (process / "exe").symlink_to("/usr/bin/python")
    (process / "fd" / "3").symlink_to("socket:[1]")
    (proc / "tcp").write_text(
        "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1\n"
    )
    events = collect_network(proc, process_root)
    assert len(events) == 1
    assert events[0].event_type == "listening_port"
    assert events[0].destination_ip == "127.0.0.1"
    assert events[0].destination_port == 8080
    assert events[0].evidence["socket_inode"] == "1"
    assert events[0].process == "web-test"
    assert events[0].evidence["pid"] == 123
