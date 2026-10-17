# JFP-Box Python SDK

High-performance Rust-powered Zero-Trust Policy Engine and Tool Interceptor for AI Agents.

## Installation

```bash
pip install jfp-box
```

## Quick Start

```python
import jfp_box

# 1. Load policy (YAML, JSON, or JFP auto-detected)
policy = jfp_box.Policy.from_file("examples/research.yaml")

# Check if policy itself is mathematically sound and compliant
if not policy.is_valid():
    print("Policy violations:", policy.violations())

# 2. Executive / Business Explanation
explanation = policy.explain()
print(f"Risk Level: {explanation['risk_level']}")
print(f"Executive Summary: {explanation['executive_summary']}")

# 3. Real-Time Tool-Call Interception (MCP / Agent Sandbox)
# Intercept unsafe agent tool calls before execution!
verdict = policy.check_tool("bash", "rm -rf /")
print(f"Allowed: {verdict.allowed}")          # False
print(f"Risk Score: {verdict.risk_score}")    # 100
print(f"Reason: {verdict.reason}")            # Blocked: Destructive command pattern detected
```
