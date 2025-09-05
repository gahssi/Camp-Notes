#!/usr/bin/env python3
"""
InsightVM SQL metrics exporter (Active Risk severity bins, tag-scoped)

Produces two CSV metric reports (scoped to assets with a given tag):
  1) ALL vulnerabilities by severity (Critical/High/Medium/Low) using Active Risk bins
  2) NEW vulnerabilities by severity first discovered in the LAST FULL CALENDAR MONTH

Env vars:
  INSIGHTVM_HOST=<hostname[:port]>              (required) e.g. console.example.com:3780
  INSIGHTVM_USER=<username>                     (required)
  INSIGHTVM_PASS=<password>                     (required)
  INSIGHTVM_SSL_VERIFY=true|false               (default: true)
  INSIGHTVM_TAG_NAME=<tag name>                 (default: "test")  # tag scope is REQUIRED
  INSIGHTVM_DATA_MODEL_VERSION=<version>        (default: "2.3.0", falls back to 2.0.0 then 1.2.0)
  INSIGHTVM_OUTPUT_DIR=<dir>                    (default: current directory)
"""

from base64 import b64encode
from datetime import datetime, date, timedelta
import http.client
import json
import os
import ssl
import sys
from time import sleep
from urllib.parse import urlparse
import uuid
import re
from pathlib import Path

API_BASE = "/api/3"

# ---------------- helpers ----------------

def _nowstamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")

def parse_host_port(host_env: str):
    if "://" in host_env:
        u = urlparse(host_env)
        host = u.hostname or ""
        port = u.port or 3780
    else:
        if ":" in host_env:
            host, port_s = host_env.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                host, port = host_env, 3780
        else:
            host, port = host_env, 3780
    if not host:
        raise ValueError("Invalid INSIGHTVM_HOST")
    return host, port

def last_full_calendar_month(today: date | None = None):
    """
    Example: if today is 2025-09-04 -> (2025-08-01, 2025-09-01)
    """
    today = today or date.today()
    first_of_this_month = today.replace(day=1)
    end_excl = first_of_this_month
    start = (first_of_this_month - timedelta(days=1)).replace(day=1)
    return start, end_excl

# --- ACTIVE RISK severity bins (0–1000) ---
# Low:    1–249 (we'll include 0 as Low as well, just in case)
# Medium: 250–499
# High:   500–749
# Critical: 750–1000
def sql_active_risk_severity_expr():
    return """
        CASE
            WHEN dv.riskscore >= 750 THEN 'Critical'
            WHEN dv.riskscore >= 500 THEN 'High'
            WHEN dv.riskscore >= 250 THEN 'Medium'
            ELSE 'Low'
        END AS severity
    """

def order_by_severity():
    return """
        ORDER BY CASE severity
            WHEN 'Critical' THEN 1
            WHEN 'High' THEN 2
            WHEN 'Medium' THEN 3
            ELSE 4
        END
    """

class InsightVmApi:
    def __init__(self, host, port, username, password, verify_ssl=True):
        auth = b64encode(f"{username}:{password}".encode("ascii")).decode()
        self.json_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}",
        }
        self.csv_headers = {
            "Accept": "text/csv",  # SQL Query Export returns CSV
            "Authorization": f"Basic {auth}",
        }
        ctx = None
        if not verify_ssl:
            ctx = ssl._create_unverified_context()
        self.conn = http.client.HTTPSConnection(host, port=port, context=ctx)

    def _request(self, method, path, headers=None, body=None, expect_json=True):
        hdrs = headers or self.json_headers
        payload = body
        if isinstance(body, (dict, list)):
            payload = json.dumps(body)
        self.conn.request(method, path, payload, hdrs)
        resp = self.conn.getresponse()
        status = resp.status
        data = resp.read()
        if status >= 400:
            text = data.decode(errors="replace")
            raise RuntimeError(f"{method} {path} -> HTTP {status}: {text}")
        if expect_json:
            return json.loads(data.decode() or "{}")
        return resp, data

    # ---- tags
    def get_tag_id_by_name(self, name):
        page, size = 0, 200
        name_lc = name.strip().lower()
        while True:
            result = self._request("GET", f"{API_BASE}/tags?page={page}&size={size}")
            resources = result.get("resources", [])
            for t in resources:
                tname = t.get("name", "")
                if tname.lower() == name_lc:
                    return t.get("id")
            page += 1
            if len(resources) < size:
                break
        return None

    # ---- reports
    def create_sql_query_report(self, name, query, version="2.3.0", scope=None):
        body = {"name": name, "format": "sql-query", "query": query, "version": version}
        if scope:
            body["scope"] = scope
        try:
            return self._request("POST", f"{API_BASE}/reports", body)
        except RuntimeError as e:
            if "version" in str(e) or "400" in str(e):
                for v in ("2.0.0", "1.2.0"):
                    body["version"] = v
                    try:
                        return self._request("POST", f"{API_BASE}/reports", body)
                    except RuntimeError:
                        continue
            raise

    def generate_report(self, report_id):
        return self._request("POST", f"{API_BASE}/reports/{report_id}/generate")

    def get_report_instance(self, report_id, instance_id):
        return self._request("GET", f"{API_BASE}/reports/{report_id}/history/{instance_id}")

    def wait_until_complete(self, report_id, instance_id, poll_seconds=5, max_minutes=60):
        deadline = datetime.now().timestamp() + max_minutes * 60
        terminal = {"complete", "failed", "aborted"}
        while True:
            details = self.get_report_instance(report_id, instance_id)
            status = str(details.get("status", "")).lower()
            if status in terminal:
                return details
            if datetime.now().timestamp() > deadline:
                raise TimeoutError(f"Report {report_id}/{instance_id} timed out (last status={status})")
            sleep(poll_seconds)

    def download_report_output(self, report_id, instance_id):
        resp, data = self._request(
            "GET",
            f"{API_BASE}/reports/{report_id}/history/{instance_id}/output",
            headers=self.csv_headers,
            expect_json=False,
        )
        ctype = resp.getheader("Content-Type", "application/octet-stream").lower()
        dispo = resp.getheader("Content-Disposition", "") or ""
        m = re.search(r'filename="?([^\";]+)"?', dispo)
        suggested = m.group(1) if m else None
        return suggested, ctype, data

    def delete_report(self, report_id):
        return self._request("DELETE", f"{API_BASE}/reports/{report_id}")

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

def main():
    HOST = os.environ.get("INSIGHTVM_HOST", "").strip()
    USER = os.environ.get("INSIGHTVM_USER", "").strip()
    PASS = os.environ.get("INSIGHTVM_PASS", "").strip()
    SSL_VERIFY = os.environ.get("INSIGHTVM_SSL_VERIFY", "true").strip().lower() != "false"
    TAG_NAME = os.environ.get("INSIGHTVM_TAG_NAME", "test").strip()  # REQUIRED; default 'test'
    MODEL_VERSION = os.environ.get("INSIGHTVM_DATA_MODEL_VERSION", "2.3.0").strip() or "2.3.0"
    OUT_DIR = Path(os.environ.get("INSIGHTVM_OUTPUT_DIR", ".")).resolve()

    if not HOST or not USER or not PASS:
        sys.exit("Host, user, or password not defined; check environment variables and try again!")

    host, port = parse_host_port(HOST)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    sev_case = sql_active_risk_severity_expr()
    sev_order = order_by_severity()

    start_prev, end_prev = last_full_calendar_month()
    start_prev_s = start_prev.strftime("%Y-%m-%d")
    end_prev_s = end_prev.strftime("%Y-%m-%d")

    # 1) ALL vulnerabilities by Active Risk severity (scoped by tag)
    ALL_VULNS_BY_SEVERITY = f"""
        SELECT
            {sev_case},
            COUNT(*) AS asset_vulnerability_pairs,
            SUM(fav.vulnerability_instances) AS vulnerability_instances,
            COUNT(DISTINCT fav.asset_id) AS affected_assets
        FROM fact_asset_vulnerability AS fav
        JOIN dim_vulnerability AS dv ON dv.vulnerability_id = fav.vulnerability_id
        GROUP BY severity
        {sev_order}
    """

    # 2) NEW last full month by Active Risk severity (scoped by tag)
    NEW_LAST_MONTH_BY_SEVERITY = f"""
        SELECT
            {sev_case},
            COUNT(*) AS asset_vulnerability_pairs,
            SUM(fav.vulnerability_instances) AS vulnerability_instances,
            COUNT(DISTINCT fav.asset_id) AS affected_assets,
            '{start_prev_s}'::date AS window_start,
            ('{end_prev_s}'::date - INTERVAL '1 day') AS window_end_inclusive
        FROM fact_asset_vulnerability AS fav
        JOIN fact_asset_vulnerability_age AS fava
          ON fava.asset_id = fav.asset_id AND fava.vulnerability_id = fav.vulnerability_id
        JOIN dim_vulnerability AS dv ON dv.vulnerability_id = fav.vulnerability_id
        WHERE fava.first_discovered >= '{start_prev_s}'
          AND fava.first_discovered <  '{end_prev_s}'
        GROUP BY severity
        {sev_order}
    """

    QUERIES = {
        "metrics_all_vulns_by_active_risk": ALL_VULNS_BY_SEVERITY,
        "metrics_new_last_month_by_active_risk": NEW_LAST_MONTH_BY_SEVERITY,
    }

    api = InsightVmApi(host, port, USER, PASS, verify_ssl=SSL_VERIFY)

    if not TAG_NAME:
        sys.exit("INSIGHTVM_TAG_NAME is required (e.g., 'test').")
    tag_id = api.get_tag_id_by_name(TAG_NAME)
    if not tag_id:
        sys.exit(f"Tag named '{TAG_NAME}' not found on the console; aborting to avoid unscoped export.")
    scope = {"tags": [tag_id]}  # scope report to 'test' assets only

    try:
        for name, query in QUERIES.items():
            print(f"\n[+] Generating metrics: {name}")
            started = datetime.now()

            report_name = f"adhoc-{name}-{uuid.uuid4()}"
            report = api.create_sql_query_report(report_name, query, version=MODEL_VERSION, scope=scope)
            report_id = report["id"]

            instance = api.generate_report(report_id)
            instance_id = instance.get("id") or instance.get("instance", {}).get("id")

            details = api.wait_until_complete(report_id, instance_id, poll_seconds=5, max_minutes=60)
            status = str(details.get("status", "")).lower()
            if status != "complete":
                print(f"[!] Report {name} ended in status '{status}'. Skipping download.")
            else:
                suggested, ctype, data = api.download_report_output(report_id, instance_id)
                ts = _nowstamp()
                base = suggested or f"insightvm_{name}_{ts}.csv"
                base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
                out_path = OUT_DIR / base
                with open(out_path, "wb") as f:
                    f.write(data)
                print(f"[✓] Saved {name} to: {out_path} (Content-Type: {ctype})")

            api.delete_report(report_id)

            elapsed = (datetime.now() - started).seconds
            print(f"[i] {name} completed in {elapsed} seconds")

    finally:
        api.close()

if __name__ == "__main__":
    main()
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def parse_host_port(host_env: str):
    """
    Accepts:
      console.example.com
      console.example.com:3780
      https://console.example.com:3780
      http://console.example.com (port ignored; HTTPS is always used)
    Returns (host, port)
    """
    if "://" in host_env:
        u = urlparse(host_env)
        host = u.hostname or ""
        port = u.port or 3780
    else:
        if ":" in host_env:
            host, port_s = host_env.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                host, port = host_env, 3780
        else:
            host, port = host_env, 3780
    if not host:
        raise ValueError("Invalid INSIGHTVM_HOST")
    return host, port


class InsightVmApi:
    def __init__(self, host, port, username, password, verify_ssl=True):
        # auth header
        auth = b64encode(f"{username}:{password}".encode("ascii")).decode()
        self.json_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}",
        }
        # use text/csv for report output; console returns CSV for SQL Query Export
        self.csv_headers = {
            "Accept": "text/csv",
            "Authorization": f"Basic {auth}",
        }

        ctx = None
        if not verify_ssl:
            # NOT for prod; used for self-signed consoles
            ctx = ssl._create_unverified_context()

        self.conn = http.client.HTTPSConnection(host, port=port, context=ctx)

    # -------- helpers --------
    def _request(self, method, path, headers=None, body=None, expect_json=True):
        hdrs = headers or self.json_headers
        payload = body
        if isinstance(body, (dict, list)):
            payload = json.dumps(body)

        self.conn.request(method, path, payload, hdrs)
        resp = self.conn.getresponse()
        status = resp.status
        data = resp.read()

        if status >= 400:
            # include response text (best effort) for debugging
            text = data.decode(errors="replace")
            raise RuntimeError(f"{method} {path} -> HTTP {status}: {text}")

        if expect_json:
            return json.loads(data.decode() or "{}")
        return resp, data  # return the raw HTTPResponse (for headers) + bytes

    # -------- tags (optional scope) --------
    def get_tag_id_by_name(self, name):
        """Find tag id by (case-insensitive) exact name match."""
        # v3 list endpoints use page/size
        page = 0
        size = 200
        name_lc = name.strip().lower()
        while True:
            result = self._request(
                "GET", f"{API_BASE}/tags?page={page}&size={size}"
            )
            resources = result.get("resources", [])
            for t in resources:
                tname = t.get("name", "")
                if tname.lower() == name_lc:
                    return t.get("id")
            # pagination
            page += 1
            if len(resources) < size:
                break
        return None

    # -------- reports --------
    def create_sql_query_report(self, name, query, version="2.0.0", scope=None):
        """
        Create an ad-hoc SQL Query Export report template.
        Falls back to data model version 1.2.0 if 2.0.0 is rejected by the console.
        """
        body = {
            "name": name,
            "format": "sql-query",
            "query": query,
            "version": version,
        }
        if scope:
            body["scope"] = scope

        try:
            return self._request("POST", f"{API_BASE}/reports", body)
        except RuntimeError as e:
            # Fallback if console doesn't support that data model version
            if "version" in str(e) or "400" in str(e):
                if version != "1.2.0":
                    body["version"] = "1.2.0"
                    return self._request("POST", f"{API_BASE}/reports", body)
            raise

    def generate_report(self, report_id):
        return self._request(
            "POST", f"{API_BASE}/reports/{report_id}/generate"
        )

    def get_report_instance(self, report_id, instance_id):
        return self._request(
            "GET", f"{API_BASE}/reports/{report_id}/history/{instance_id}"
        )

    def wait_until_complete(self, report_id, instance_id, poll_seconds=5, max_minutes=60):
        deadline = datetime.now().timestamp() + max_minutes * 60
        terminal = {"complete", "failed", "aborted"}
        while True:
            details = self.get_report_instance(report_id, instance_id)
            status = str(details.get("status", "")).lower()
            if status in terminal:
                return details
            if datetime.now().timestamp() > deadline:
                raise TimeoutError(f"Report {report_id}/{instance_id} timed out (last status={status})")
            sleep(poll_seconds)

    def download_report_output(self, report_id, instance_id):
        # Returns (filename, content_type, bytes)
        resp, data = self._request(
            "GET",
            f"{API_BASE}/reports/{report_id}/history/{instance_id}/output",
            headers=self.csv_headers,
            expect_json=False,
        )
        ctype = resp.getheader("Content-Type", "application/octet-stream").lower()
        dispo = resp.getheader("Content-Disposition", "") or ""
        # try filename from disposition; otherwise synthesize
        m = re.search(r'filename="?([^";]+)"?', dispo)
        suggested = m.group(1) if m else None
        return suggested, ctype, data

    def delete_report(self, report_id):
        return self._request("DELETE", f"{API_BASE}/reports/{report_id}")

    # convenience
    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def main():
    HOST = os.environ.get("INSIGHTVM_HOST", "").strip()
    USER = os.environ.get("INSIGHTVM_USER", "").strip()
    PASS = os.environ.get("INSIGHTVM_PASS", "").strip()
    SSL_VERIFY = os.environ.get("INSIGHTVM_SSL_VERIFY", "true").strip().lower() != "false"
    TAG_NAME = os.environ.get("INSIGHTVM_TAG_NAME", "").strip()  # e.g., "test"
    MODEL_VERSION = os.environ.get("INSIGHTVM_DATA_MODEL_VERSION", "2.0.0").strip() or "2.0.0"
    OUT_DIR = Path(os.environ.get("INSIGHTVM_OUTPUT_DIR", ".")).resolve()

    if not HOST or not USER or not PASS:
        sys.exit("Host, user, or password not defined; check environment variables and try again!")

    host, port = parse_host_port(HOST)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # A practical "asset ↔ vulnerability" query for per-asset vulnerability rows.
    # (Your originals are kept below; this one is most aligned with "all vulnerabilities of all assets".)
    ASSET_VULN_QUERY = """
        SELECT
            da.asset_id,
            da.ip_address,
            da.host_name,
            dv.vulnerability_id,
            dv.nexpose_id,
            dv.title,
            htmlToText(dv.description) AS description,
            dv.severity_score,
            dv.riskscore,
            fv.first_discovered,
            fv.most_recently_discovered,
            fv.vulnerability_instances,
            dsol.nexpose_id AS solution_nexpose_id,
            dsol.solution_type,
            htmlToText(dsol.fix) AS fix,
            dsol.summary
        FROM fact_vulnerability AS fv
        JOIN dim_vulnerability AS dv ON dv.vulnerability_id = fv.vulnerability_id
        JOIN dim_asset AS da ON da.asset_id = fv.asset_id
        LEFT JOIN dim_asset_vulnerability_best_solution AS davbs
            ON davbs.asset_id = fv.asset_id AND davbs.vulnerability_id = fv.vulnerability_id
        LEFT JOIN dim_solution AS dsol ON dsol.solution_id = davbs.solution_id
        ORDER BY da.asset_id, dv.vulnerability_id
    """

    # Your original queries kept as options (uncomment if you also want them).
    QUERIES = {
        "asset_vulnerabilities": ASSET_VULN_QUERY,
        # "assets": """
        #     SELECT fa.asset_id, da.ip_address, da.host_name, da.mac_address, dos.vendor as operating_system_vendor,
        #            dos.name as operating_system_name, dos.version as operating_system_version,
        #            fa.scan_finished as last_scanned, fa.riskscore, fa.vulnerabilities, fa.critical_vulnerabilities,
        #            fa.severe_vulnerabilities, fa.moderate_vulnerabilities, fa.vulnerability_instances
        #     FROM fact_asset AS fa
        #     JOIN dim_asset AS da ON da.asset_id = fa.asset_id
        #     JOIN dim_operating_system AS dos ON dos.operating_system_id = da.operating_system_id
        # """,
        # "finding_with_best_solution": """
        #     SELECT davbs.asset_id, davbs.vulnerability_id, davbs.solution_id, ds.nexpose_id, ds.solution_type,
        #            htmlToText(ds.fix) as fix, ds.summary
        #     FROM dim_asset_vulnerability_best_solution AS davbs
        #     JOIN dim_solution AS ds ON davbs.solution_id = ds.solution_id
        # """
    }

    api = InsightVmApi(host, port, USER, PASS, verify_ssl=SSL_VERIFY)

    # Optional scope by tag
    scope = None
    if TAG_NAME:
        tag_id = api.get_tag_id_by_name(TAG_NAME)
        if not tag_id:
            print(f"[WARN] Tag named '{TAG_NAME}' not found; running without tag scoping.")
        else:
            scope = {"tags": [tag_id]}

    try:
        for name, query in QUERIES.items():
            print(f"\n[+] Generating report for query: {name}")
            started = datetime.now()

            report_name = f"adhoc-{name}-{uuid.uuid4()}"
            report = api.create_sql_query_report(report_name, query, version=MODEL_VERSION, scope=scope)
            report_id = report["id"]

            instance = api.generate_report(report_id)
            instance_id = instance.get("id") or instance.get("instance", {}).get("id")

            details = api.wait_until_complete(report_id, instance_id, poll_seconds=5, max_minutes=120)
            status = str(details.get("status", "")).lower()
            if status != "complete":
                print(f"[!] Report {name} ended in status '{status}'. Skipping download.")
            else:
                suggested, ctype, data = api.download_report_output(report_id, instance_id)
                # pick extension by content type
                if "csv" in ctype:
                    ext = ".csv"
                elif "zip" in ctype:
                    ext = ".zip"
                else:
                    ext = ".dat"

                # filename
                ts = _nowstamp()
                base = suggested or f"insightvm_{name}_{ts}{ext}"
                # sanitize
                base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
                out_path = OUT_DIR / base

                with open(out_path, "wb") as f:
                    f.write(data)
                print(f"[✓] Saved {name} to: {out_path} (Content-Type: {ctype})")

            # cleanup the ad-hoc template no matter what
            api.delete_report(report_id)

            elapsed = (datetime.now() - started).seconds
            print(f"[i] {name} completed in {elapsed} seconds")

    finally:
        api.close()


if __name__ == "__main__":
    main()
