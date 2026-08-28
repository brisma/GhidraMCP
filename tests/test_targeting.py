"""What the bridge must never do: send a call somewhere the caller did not choose."""
import pytest

import bridge_mcp_ghidra as bridge


def test_a_call_without_a_selection_is_refused(ghidra):
    """One Ghidra is up and nothing has chosen it. The call must not go out.

    This is the shape of the incident: a bridge that picks a target on the
    caller's behalf picks it from boot order, and boot order is not a choice.
    """
    only = ghidra(0, "SLUS_010.71")
    bridge.list_instances()          # discovery has seen it

    with pytest.raises(RuntimeError, match="use_instance"):
        bridge.safe_get("probe")

    assert only.requests == [], "nothing may be sent before a target is chosen"


def test_a_silent_instance_is_never_replaced_by_another(ghidra):
    """The chosen instance stops answering. Nothing may be sent anywhere.

    Silence is not evidence of absence, and the instance most likely to fall
    silent is the busy one -- the one you are working in.
    """
    lunar1 = ghidra(0, "SLUS_006.28-unpacked.exe")
    lunar2 = ghidra(1, "SLUS_010.71")
    bridge.ghidra_request_timeout = 1

    bridge.use_instance(lunar1.port)
    lunar1.go_silent()

    with pytest.raises(RuntimeError, match="did not answer"):
        bridge.safe_get("probe")

    assert lunar1.requests == [], "the call must not go out unconfirmed"
    assert lunar2.requests == [], "and above all it must not go to the other game"


def test_the_call_reaches_the_chosen_instance_and_no_other(ghidra):
    """The ordinary path: choose one of two, and only that one is spoken to."""
    lunar1 = ghidra(0, "SLUS_006.28-unpacked.exe")
    lunar2 = ghidra(1, "SLUS_010.71")

    bridge.use_instance(lunar2.port)
    bridge.safe_get("probe")

    assert [r[1] for r in lunar2.requests] == ["/probe"]
    assert lunar1.requests == []


def test_list_instances_marks_the_chosen_one(ghidra):
    lunar1 = ghidra(0, "SLUS_006.28-unpacked.exe")
    lunar2 = ghidra(1, "SLUS_010.71")
    bridge.use_instance(lunar2.port)

    lines = bridge.list_instances()

    assert any("SLUS_010.71" in ln and "[ACTIVE]" in ln for ln in lines), lines
    assert not any("SLUS_006.28" in ln and "[ACTIVE]" in ln for ln in lines), lines


def test_no_background_thread_exists_to_re_point_the_session():
    """There must be no periodic round at all.

    A round that polls with a timeout cannot tell a busy instance from a
    departed one, and the instance most likely to miss it is the one you are
    working in -- so its mistake is to hand the session the other game. No
    grace period fixes that; only not having the round does.
    """
    import ast
    tree = ast.parse(open("bridge_mcp_ghidra.py").read())
    spawns = [n for n in ast.walk(tree)
              if isinstance(n, ast.Call)
              and isinstance(n.func, ast.Attribute) and n.func.attr == "Thread"]
    assert spawns == [], f"a thread is started at line(s) {[n.lineno for n in spawns]}"


def test_the_target_is_followed_when_its_instance_moves_to_another_port(ghidra):
    """Ports are handed out by boot order. The program is what was chosen, so
    when it comes back on another port the bridge follows it there."""
    lunar2 = ghidra(0, "SLUS_010.71")
    bridge.use_instance(lunar2.port)

    lunar2.shutdown()
    moved = ghidra(2, "SLUS_010.71")   # same database, restarted, new port

    bridge.safe_get("probe")

    assert [r[1] for r in moved.requests] == ["/probe"]
    assert bridge.current_target["port"] == moved.port


def test_the_same_program_open_twice_is_an_ambiguity_not_a_coin_toss(ghidra):
    """If the chosen program answers on two ports, neither is 'the' one."""
    first = ghidra(0, "SLUS_010.71", project="a")
    bridge.use_instance(first.port)

    first.shutdown()
    twin_a = ghidra(1, "SLUS_010.71", project="a")
    twin_b = ghidra(2, "SLUS_010.71", project="a")

    with pytest.raises(RuntimeError, match="use_instance"):
        bridge.safe_get("probe")

    assert twin_a.requests == [] and twin_b.requests == []


def test_a_refused_write_raises_instead_of_reading_like_a_network_hiccup(ghidra):
    """A refusal returned as a string starting 'Request failed' is a refusal
    dressed as a flaky connection -- the one reading it will retry."""
    lunar1 = ghidra(0, "SLUS_006.28-unpacked.exe")
    bridge.use_instance(lunar1.port)
    lunar1.shutdown()

    with pytest.raises(RuntimeError, match="not open on any port"):
        bridge.safe_post("probe", {"address": "0x80012e34"})


def test_use_program_chooses_by_content_not_by_port(ghidra):
    """The working rule was 'pick the port by content, not by number'. That
    rule should be the tool, not a discipline the caller has to remember."""
    lunar1 = ghidra(0, "SLUS_006.28-unpacked.exe")
    lunar2 = ghidra(1, "SLUS_010.71")

    bridge.use_program("SLUS_010.71")
    bridge.safe_get("probe")

    assert [r[1] for r in lunar2.requests] == ["/probe"]
    assert lunar1.requests == []


def _headers(req):
    return {k.lower(): v for k, v in req[2].items()}


def test_every_request_names_the_database_and_the_session(ghidra, monkeypatch):
    """The request carries what it believes it is writing to, so the instance
    that performs the write can refuse what is not its own -- and carries who
    is asking, so the undo stack records it."""
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "cc7b64c9-d26b-4055-bd4d-e5ca24381723")
    inst = ghidra(0, "SLUS_010.71", file_id="4d2c1a90")
    bridge.use_instance(inst.port)

    bridge.safe_get("probe")

    h = _headers(inst.requests[0])
    assert h["x-ghidra-file-id"] == "4d2c1a90"
    assert h["x-ghidra-session"] == "cc7b64c9"


def test_no_file_id_header_when_the_plugin_does_not_report_one(ghidra):
    """The Java half may not be rebuilt yet. That must not break anything."""
    inst = ghidra(0, "SLUS_010.71")   # old plugin: /instances has no file_id
    bridge.use_instance(inst.port)

    bridge.safe_get("probe")

    assert "x-ghidra-file-id" not in _headers(inst.requests[0])


def test_a_refusal_by_the_instance_stops_the_call(ghidra):
    """The instance is the only party that knows, at the moment it acts, which
    database it is. When it says no, that must not come back as a line of text
    among the results, which is a thing a reader skims past."""
    inst = ghidra(0, "SLUS_010.71", file_id="4d2c1a90")
    bridge.use_instance(inst.port)
    inst.refuse = True

    with pytest.raises(RuntimeError, match="refused"):
        bridge.safe_post("probe", {"address": "0x80012e34"})

    with pytest.raises(RuntimeError, match="refused"):
        bridge.safe_get("probe")


def test_the_server_option_pins_one_instance_and_verifies_it(ghidra):
    """--ghidra-server used to be a silent default to fall back on. It becomes
    a deliberate pin: this bridge serves that program and no other."""
    inst = ghidra(0, "SLUS_010.71")

    message = bridge._pin_to(f"http://127.0.0.1:{inst.port}/")

    assert "SLUS_010.71" in message
    assert bridge.current_target["port"] == inst.port


def test_a_pin_that_finds_nothing_pins_nothing(ghidra):
    """A pin that quietly half-succeeded would be the old default wearing a
    new name: a target nobody chose."""
    gone = ghidra(0, "SLUS_010.71")
    port = gone.port
    gone.shutdown()

    message = bridge._pin_to(f"http://127.0.0.1:{port}/")

    assert bridge.current_target is None
    assert "nothing pinned" in message


def test_choosing_by_program_also_carries_the_database_identity(ghidra):
    """use_instance and use_program must produce the same target.

    They did not: use_program built its target from discovery, which dropped
    the file id, so a session that chose by program sent no identity and the
    instance had nothing to refuse on. The guard was inert on the path a
    session is most likely to use.
    """
    inst = ghidra(0, "SLUS_010.71", file_id="4d2c1a90")

    bridge.use_program("SLUS_010.71")
    bridge.safe_get("probe")

    assert bridge.current_target["file_id"] == "4d2c1a90"
    assert _headers(inst.requests[0])["x-ghidra-file-id"] == "4d2c1a90"
