"""一键验证正在运行的内部助手；仅发送固定的虚构资料。"""

import json
from datetime import datetime, timezone
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

BASE_URL = "http://127.0.0.1:8000"
REPORT = Path(__file__).resolve().parents[1] / "reports" / "demo.json"
OPENER = build_opener(ProxyHandler({}))


def call(path, body=None, method="POST"):
    request = Request(
        BASE_URL + path,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with OPENER.open(request, timeout=150) as response:
        return json.load(response)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    session_ids = []
    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Local B-module demo with placeholder gate; not an M1/M2 evaluation",
        "status": "running",
        "checks": [],
    }
    exit_code = 0
    try:
        require(call("/health", method="GET").get("status") == "ok", "Backend not healthy")
        first = call("/chat", {"message": "虚构实验资料：项目编号是 DEMO-482。请记住，只回复收到。"})
        session_ids.append(first["session_id"])
        require(first["route"] == "internal" and first["gate_decision"] == "not_checked", "Internal baseline route failed")
        report["checks"].append({"name": "internal_baseline", "passed": True})

        second = call("/chat", {"message": "刚才项目编号是什么？只回答编号。", "session_id": session_ids[0]})
        require("DEMO-482" in second["answer"] and second["turn_count"] == 2, "Model did not recall the synthetic identifier")
        report["checks"].append({"name": "session_memory", "passed": True, "answer": second["answer"]})

        separate = call("/chat", {"message": "刚才项目编号是什么？如果没有收到资料就说不知道，不要猜测。"})
        session_ids.append(separate["session_id"])
        require(separate["session_id"] != session_ids[0] and "DEMO-482" not in separate["answer"], "Session isolation check failed")
        report["checks"].append({"name": "session_isolation", "passed": True, "answer": separate["answer"]})

        fallback = call("/chat", {"message": "刚才项目编号是什么？只回答编号。", "session_id": session_ids[0], "route_mode": "external_candidate"})
        require(fallback["gate_decision"] == "deny" and fallback["fallback"] is True and fallback["external_attempted"] is False and fallback["route"] == "internal", "Denied-call fallback failed")
        require("DEMO-482" in fallback["answer"], "Fallback lost the synthetic fact")
        report["checks"].append({"name": "denial_and_internal_fallback", "passed": True, "response": fallback})

        call("/sessions/" + session_ids[0], method="DELETE")
        try:
            call("/chat", {"message": "继续", "session_id": session_ids[0]})
        except HTTPError as exc:
            code = exc.code
            exc.close()
            require(code == 404, "Deleted session returned an unexpected HTTP status")
        else:
            raise AssertionError("Deleted session was still accessible")
        report["checks"].append({"name": "session_reset", "passed": True})
        report["status"] = "passed"
    except (AssertionError, KeyError, ValueError, OSError) as exc:
        report["status"] = "failed"
        report["error"] = str(exc)
        if isinstance(exc, HTTPError):
            exc.close()
        exit_code = 1
    finally:
        for sid in session_ids:
            try:
                call("/sessions/" + sid, method="DELETE")
            except HTTPError as exc:
                if exc.code != 404:
                    report.setdefault("cleanup_errors", []).append(str(exc))
                exc.close()
            except (URLError, OSError) as exc:
                report.setdefault("cleanup_errors", []).append(str(exc))
        if report.get("cleanup_errors"):
            report["status"] = "failed"
            exit_code = 1
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    for check in report["checks"]:
        print("PASS:", check["name"])
    print("Result:", report["status"])
    print("Report:", REPORT)
    if "error" in report:
        print("Error:", report["error"])
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
