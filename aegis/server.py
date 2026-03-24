from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError:  # pragma: no cover - local fallback for environments without MCP installed
    class FastMCP:  # type: ignore[override]
        def __init__(self, name: str) -> None:
            self.name = name

        def tool(self, name: str | None = None):
            def decorator(func):
                return func
            return decorator

        def run(self) -> None:
            raise RuntimeError("The 'mcp' package is not installed. Install project dependencies to run the MCP server.")

from .engine import (
    assess_pq_risk,
    audit_config,
    build_delta_report,
    build_migration_roadmap,
    classify_algorithm,
    generate_inventory_from_runs,
    probe_tls_endpoint as probe_tls_endpoint_engine,
    scan_codebase,
    scan_dependencies as scan_dependencies_engine,
)
from .state import StateStore


mcp = FastMCP("aegis")
STATE = StateStore(Path.cwd())


@mcp.tool(name="scan_codebase")
def scan_codebase_tool(
    pathreq: str,
    languagesopt: list[str] | None = None,
    depthopt: int | None = None,
    include_testsopt: bool = False,
    min_severityopt: str = "medium",
) -> dict[str, Any]:
    result = scan_codebase(pathreq, languagesopt, depthopt, include_testsopt, min_severityopt)
    run_id = STATE.save_run(
        "scan_codebase",
        {
            "pathreq": pathreq,
            "languagesopt": languagesopt,
            "depthopt": depthopt,
            "include_testsopt": include_testsopt,
            "min_severityopt": min_severityopt,
        },
        result,
    )
    return {"scan_id": run_id, **result}


@mcp.tool()
def probe_tls_endpoint(
    hostreq: str,
    portopt: int = 443,
    sniopt: str | None = None,
    starttlsopt: str = "none",
    enumerate_allopt: bool = False,
) -> dict[str, Any]:
    result = probe_tls_endpoint_engine(hostreq, portopt, sniopt, starttlsopt, enumerate_allopt)
    run_id = STATE.save_run(
        "probe_tls_endpoint",
        {
            "hostreq": hostreq,
            "portopt": portopt,
            "sniopt": sniopt,
            "starttlsopt": starttlsopt,
            "enumerate_allopt": enumerate_allopt,
        },
        result,
    )
    return {"scan_id": run_id, **result}


@mcp.tool(name="audit_config")
def audit_config_tool(
    pathreq: str,
    formatopt: str = "auto",
    complianceopt: list[str] | None = None,
) -> dict[str, Any]:
    result = audit_config(pathreq, formatopt, complianceopt)
    run_id = STATE.save_run(
        "audit_config",
        {"pathreq": pathreq, "formatopt": formatopt, "complianceopt": complianceopt},
        result,
    )
    return {"scan_id": run_id, **result}


@mcp.tool()
def scan_dependencies(
    manifest_pathreq: str,
    lockfile_pathopt: str | None = None,
    transitiveopt: bool = True,
) -> dict[str, Any]:
    result = scan_dependencies_engine(manifest_pathreq, lockfile_pathopt, transitiveopt)
    run_id = STATE.save_run(
        "scan_dependencies",
        {
            "manifest_pathreq": manifest_pathreq,
            "lockfile_pathopt": lockfile_pathopt,
            "transitiveopt": transitiveopt,
        },
        result,
    )
    return {"scan_id": run_id, **result}


@mcp.tool(name="assess_pq_risk")
def assess_pq_risk_tool(
    servicesreq: list[dict[str, Any]],
    crqc_horizon_yearsopt: int = 10,
    migration_lead_yearsopt: int = 2,
) -> dict[str, Any]:
    return assess_pq_risk(servicesreq, crqc_horizon_yearsopt, migration_lead_yearsopt)


@mcp.tool(name="classify_algorithm")
def classify_algorithm_tool(
    algorithmreq: str,
    use_casereq: str,
    contextopt: str | None = None,
) -> dict[str, Any]:
    return classify_algorithm(algorithmreq, use_casereq, contextopt)


@mcp.tool()
def generate_inventory(
    scan_idsreq: list[str],
    group_byopt: str = "severity",
    formatopt: str = "json",
) -> dict[str, Any]:
    runs = []
    for scan_id in scan_idsreq:
        run = STATE.get_run(scan_id)
        if run is not None:
            runs.append(run)
    inventory_result = generate_inventory_from_runs(runs, group_byopt)
    inventory_id = STATE.save_inventory(scan_idsreq, inventory_result["inventory"])
    payload = {"inventory_id": inventory_id, **inventory_result}
    if formatopt == "markdown":
        payload["rendered"] = _inventory_markdown(payload["inventory"])
    elif formatopt == "sarif":
        payload["rendered"] = _inventory_sarif(payload["inventory"])
    return payload


@mcp.tool()
def get_migration_roadmap(
    inventory_idreq: str,
    target_complianceopt: list[str] | None = None,
    team_sizeopt: int = 3,
    include_patchesopt: bool = True,
) -> dict[str, Any]:
    inventory = STATE.get_inventory(inventory_idreq)
    if inventory is None:
        raise ValueError(f"Unknown inventory_id: {inventory_idreq}")
    return build_migration_roadmap(inventory["result"], team_sizeopt, include_patchesopt, target_complianceopt)


@mcp.tool()
def get_delta_report(
    baseline_idreq: str,
    current_idreq: str,
    highlight_regressionsopt: bool = True,
) -> dict[str, Any]:
    baseline = STATE.get_inventory(baseline_idreq)
    current = STATE.get_inventory(current_idreq)
    if baseline is None or current is None:
        raise ValueError("Unknown baseline_idreq or current_idreq.")
    return build_delta_report(baseline["result"], current["result"], highlight_regressionsopt)


def _inventory_markdown(inventory: dict[str, Any]) -> str:
    lines = [
        "# Crypto Inventory",
        "",
        f"- Total findings: {inventory['summary_stats']['total_findings']}",
        f"- Critical: {inventory['summary_stats']['critical']}",
        f"- High: {inventory['summary_stats']['high']}",
        f"- Medium: {inventory['summary_stats']['medium']}",
        f"- Low: {inventory['summary_stats']['low']}",
        "",
    ]
    for group, findings in inventory["grouped_findings"].items():
        lines.append(f"## {group}")
        for finding in findings:
            label = finding.get("algo", finding.get("issue", "finding"))
            lines.append(f"- {finding.get('file')}:{finding.get('line', '?')} {label} [{finding.get('severity')}]")
        lines.append("")
    return "\n".join(lines)


def _inventory_sarif(inventory: dict[str, Any]) -> dict[str, Any]:
    results = []
    for findings in inventory["grouped_findings"].values():
        for finding in findings:
            results.append(
                {
                    "ruleId": finding.get("algo", finding.get("key_path", "crypto-finding")),
                    "level": _sarif_level(finding.get("severity", "medium")),
                    "message": {"text": finding.get("suggested_replacement", finding.get("issue", "Crypto finding"))},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.get("file")},
                                "region": {"startLine": finding.get("line", 1)},
                            }
                        }
                    ],
                }
            )
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "aegis"}}, "results": results}]}


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
