"""No tool may reach a Ghidra instance the caller did not choose.

The targeting rules are only worth anything if every tool goes through them.
A tool that builds its own URL, or one added later that forgets, is a hole in
the guarantee -- and the hole would be invisible: the call succeeds, against
whichever program happens to be there.

So rather than trusting each new tool to remember, this walks the whole tool
list and calls every one of them with nothing chosen. All of them must raise,
and the instance that is listening must not receive a byte.

Written as one pass over every tool rather than a test each: the fixture costs
about two seconds to stand up, and the useful output is the whole list of
offenders at once, not the first one alphabetically.
"""
import inspect
import re
import pathlib

import bridge_mcp_ghidra as bridge


# The tools whose whole job is to choose or list targets. They are the only
# things allowed to work before a choice has been made.
EXEMPT = {"list_instances", "use_instance", "use_program"}

# Every tool the D-and-F workflow needs, end to end. Named explicitly so that
# deleting one is a failure rather than a silently smaller sweep below.
CODE_TOOLS = (
    "disassemble", "clear_code", "read_listing", "create_function",
    "delete_function", "analyze_program", "save_program", "get_program_info",
    "create_label", "delete_label", "create_data", "set_comment",
    "undo", "redo",
)


def _tool_names():
    """Every function registered with @mcp.tool(), read from the source."""
    source = pathlib.Path(bridge.__file__).read_text(encoding="utf-8")
    names = re.findall(r"@mcp\.tool\(\)\s*\ndef\s+(\w+)\s*\(", source)
    assert len(names) > 40, f"only found {len(names)} tools; the scan is wrong"
    return sorted(set(names) - EXEMPT)


def _dummy_args(func):
    """Plausible arguments for a tool, from its annotations."""
    args = {}
    for name, param in inspect.signature(func).parameters.items():
        if param.default is not inspect.Parameter.empty:
            continue  # optional: let it default
        annotation = param.annotation
        if annotation is int:
            args[name] = 0
        elif annotation is bool:
            args[name] = False
        elif annotation is list:
            args[name] = []
        else:
            args[name] = "0x1000"
    return args


def test_no_tool_acts_before_a_target_is_chosen(ghidra):
    listening = ghidra(0, "SLUS_010.71")
    bridge.list_instances()  # discovery has seen it; seeing is not choosing

    answered = []
    for name in _tool_names():
        func = getattr(bridge, name)
        try:
            func(**_dummy_args(func))
        except RuntimeError as e:
            if "use_instance" not in str(e):
                answered.append(f"{name}: refused, but not for want of a target ({e})")
        except Exception as e:  # noqa: BLE001 -- any other exception is a miss
            answered.append(f"{name}: raised {type(e).__name__} instead of refusing ({e})")
        else:
            answered.append(f"{name}: returned a result with no target chosen")

    assert answered == [], "these tools do not go through the targeting guard"
    assert listening.requests == [], (
        "a request was sent before any target was chosen: "
        f"{[r[1] for r in listening.requests]}")


def test_the_whole_code_workflow_is_reachable():
    """D, F, and everything needed to check and keep the result."""
    missing = [name for name in CODE_TOOLS if not hasattr(bridge, name)]
    assert missing == [], f"missing from the bridge: {missing}"
