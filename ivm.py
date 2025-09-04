#!/usr/bin/env python3
"""
InsightVM SQL Query Export helper
- Creates an ad-hoc SQL report template
- (Optionally) scopes it to assets with a given tag name
- Generates the report, polls until complete, downloads to a local file
- Cleans up the ad-hoc template

Env vars:
  INSIGHTVM_HOST=<hostname[:port]>         (required) e.g. console.example.com:3780
  INSIGHTVM_USER=<username>                (required)
  INSIGHTVM_PASS=<password>                (required)
  INSIGHTVM_SSL_VERIFY=true|false          (default: true)
  INSIGHTVM_TAG_NAME=<tag name>            (optional; e.g. "test" to scope report to that tag)
  INSIGHTVM_DATA_MODEL_VERSION=<version>   (optional; default: tries 2.0.0 then 1.2.0)
  INSIGHTVM_OUTPUT_DIR=<dir>               (optional; default: current directory)
"""

from base64 import b64encode
from datetime import datetime
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


def _nowstamp():
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
