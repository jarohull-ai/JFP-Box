use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::BTreeMap;
use std::fs;

use ::jfp_box::{
    manifest_to_json, manifest_to_yaml, parse_auto_manifest, validate, Manifest,
    PolicyExplainer, ToolDecision, ToolGate,
};

#[pyclass]
#[derive(Clone)]
/// Verdict from evaluating a tool invocation against a policy.
pub struct ToolVerdict {
    #[pyo3(get)]
    pub allowed: bool,
    #[pyo3(get)]
    pub decision: String,
    #[pyo3(get)]
    pub tool_name: String,
    #[pyo3(get)]
    pub argument: String,
    #[pyo3(get)]
    pub risk_score: u8,
    #[pyo3(get)]
    pub reason: String,
    #[pyo3(get)]
    pub policy_reference: String,
}

#[pymethods]
impl ToolVerdict {
    fn __repr__(&self) -> String {
        format!(
            "<ToolVerdict allowed={} decision='{}' risk_score={} reason='{}'>",
            self.allowed, self.decision, self.risk_score, self.reason
        )
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new_bound(py);
        dict.set_item("allowed", self.allowed)?;
        dict.set_item("decision", &self.decision)?;
        dict.set_item("tool_name", &self.tool_name)?;
        dict.set_item("argument", &self.argument)?;
        dict.set_item("risk_score", self.risk_score)?;
        dict.set_item("reason", &self.reason)?;
        dict.set_item("policy_reference", &self.policy_reference)?;
        Ok(dict)
    }
}

#[pyclass]
/// A parsed and verified JFP Policy object.
pub struct Policy {
    manifest: Manifest,
}

#[pymethods]
impl Policy {
    #[staticmethod]
    pub fn from_string(content: &str) -> PyResult<Self> {
        match parse_auto_manifest(content) {
            Ok(manifest) => Ok(Self { manifest }),
            Err(violations) => {
                let err_msg = violations
                    .iter()
                    .map(|v| format!("{}: {}", v.code(), v.message()))
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "Policy parsing failed: {}",
                    err_msg
                )))
            }
        }
    }

    #[staticmethod]
    pub fn from_file(path: &str) -> PyResult<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!("Could not read file '{}': {}", path, e))
        })?;
        Self::from_string(&content)
    }

    /// Check if the policy is internally consistent and strictly adheres to JFP rules.
    pub fn is_valid(&self) -> bool {
        validate(&self.manifest).is_empty()
    }

    /// Returns a list of semantic violations if the policy is invalid.
    pub fn violations<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty_bound(py);
        let violations = validate(&self.manifest);
        for v in violations {
            let item = PyDict::new_bound(py);
            item.set_item("code", v.code())?;
            item.set_item("message", v.message())?;
            item.set_item("field", v.field())?;
            list.append(item)?;
        }
        Ok(list)
    }

    /// Explain the policy in plain English and executive risk terms.
    pub fn explain<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let violations = validate(&self.manifest);
        let explanation = PolicyExplainer::explain(&self.manifest, &violations);

        let dict = PyDict::new_bound(py);
        dict.set_item("status", &explanation.status)?;
        dict.set_item("task_id", &explanation.task_id)?;
        dict.set_item("box_id", &explanation.box_id)?;
        dict.set_item("audit_trace_id", &explanation.audit_trace_id)?;
        dict.set_item("network_mode", &explanation.network_mode)?;
        dict.set_item("risk_level", format!("{:?}", explanation.risk_level))?;
        dict.set_item("executive_summary", &explanation.executive_summary)?;
        dict.set_item("security_guardrails", explanation.security_guardrails)?;
        dict.set_item("resource_caps", explanation.resource_caps)?;

        let v_list = PyList::empty_bound(py);
        for hv in &explanation.human_violations {
            let v_dict = PyDict::new_bound(py);
            v_dict.set_item("code", &hv.code)?;
            v_dict.set_item("title", &hv.title)?;
            v_dict.set_item("field", &hv.field)?;
            v_dict.set_item("plain_reason", &hv.plain_reason)?;
            v_dict.set_item("business_impact", &hv.business_impact)?;
            v_list.append(v_dict)?;
        }
        dict.set_item("human_violations", v_list)?;

        Ok(dict)
    }

    /// Intercepts and evaluates an agent tool call against this policy.
    pub fn check_tool(&self, tool: &str, argument: &str) -> ToolVerdict {
        let result = ToolGate::evaluate(&self.manifest, tool, argument);
        ToolVerdict {
            allowed: result.decision == ToolDecision::Allowed,
            decision: format!("{}", result.decision),
            tool_name: result.tool_name,
            argument: argument.to_string(),
            risk_score: result.risk_score,
            reason: result.reason,
            policy_reference: result.policy_reference,
        }
    }

    /// Export policy to JSON string.
    pub fn to_json(&self) -> String {
        manifest_to_json(&self.manifest)
    }

    /// Export policy to YAML string.
    pub fn to_yaml(&self) -> String {
        manifest_to_yaml(&self.manifest)
    }

    /// Get a map of all raw fields in the manifest.
    pub fn fields(&self) -> BTreeMap<String, String> {
        self.manifest.all_fields().clone()
    }
}

/// Standalone check for tool execution without keeping a policy object.
#[pyfunction]
pub fn check_tool_call(policy_content: &str, tool: &str, argument: &str) -> PyResult<ToolVerdict> {
    let policy = Policy::from_string(policy_content)?;
    Ok(policy.check_tool(tool, argument))
}

#[pymodule]
fn jfp_box(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ToolVerdict>()?;
    m.add_class::<Policy>()?;
    m.add_function(wrap_pyfunction!(check_tool_call, m)?)?;
    m.add("__version__", "0.5.0")?;
    Ok(())
}
