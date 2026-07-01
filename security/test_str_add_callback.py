#!/usr/bin/env python3
"""Local check: str.concat vs str.__add__ C-callback registration.

Requires agent-python installed editable + libfunchook copied next to c_api.so:
  cp agent-python/immunity_python_agent/assess_ext/funchook/build/libfunchook.1.dylib \\
     agent-python/immunity_python_agent/assess_ext/

Usage:
  python security/test_str_add_callback.py
"""

from __future__ import annotations

from immunity_python_agent.assess import c_api_hook, wrapt_hook
from immunity_python_agent.policy.policy import new_policy_rule
from immunity_python_agent.setting import const


def _rule(value: str) -> dict:
    return {
        "command": "",
        "source": "P",
        "target": "R",
        "track": "false",
        "inherit": "false",
        "stack_blacklist": [],
        "tags": [],
        "untags": [],
        "value": value,
    }


def check(signature: str) -> dict:
    item = _rule(signature)
    pr = new_policy_rule(const.NODE_TYPE_PROPAGATOR, item)
    module_path, attr_path = wrapt_hook.split_signature(signature)
    wrapt_ok = (
        wrapt_hook.install_wrapt_patch(module_path, attr_path, pr)
        if module_path
        else False
    )
    in_c_api = signature in const.C_API_PATCHES
    if in_c_api:
        c_api_hook.build_callback_function(pr)
    return {
        "signature": signature,
        "in_C_API_PATCHES": in_c_api,
        "wrapt_patch": wrapt_ok,
        "callback_unicode_concat": hasattr(c_api_hook, "callback_unicode_concat"),
    }


def main() -> None:
    print("=== str.concat (current ruleset) ===")
    for k, v in check("builtins.str.concat").items():
        print(f"  {k}: {v}")

    # reset generated callback before second case
    if hasattr(c_api_hook, "callback_unicode_concat"):
        delattr(c_api_hook, "callback_unicode_concat")

    print("\n=== str.__add__ (proposed rename) ===")
    for k, v in check("builtins.str.__add__").items():
        print(f"  {k}: {v}")

    print(
        "\nInterpretation:"
        "\n  - concat: neither wrapt nor C-callback → += / + taint dead"
        "\n  - __add__: C-callback registered → C layer can propagate taint"
        "\nFull E2E (real PyUnicode_Append hook) needs funchook install;"
        " on some macOS builds install() fails — use Linux CI/agent wheel."
    )


if __name__ == "__main__":
    main()
