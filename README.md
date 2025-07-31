# Camp-Notes

## 0. Introduction and scope

### 0.1 Purpose

This document establishes a company-wide baseline for **API security** across the product lifecycle. It translates proven practices into clear, implementable controls for service teams and platform owners so that APIs are designed, built, tested, deployed, operated, and retired with security as a first-class objective.

### 0.2 Scope and applicability

The guidance applies to all APIs—public, partner, and internal—regardless of architectural style (REST, RPC, GraphQL, event-driven), deployment model (cloud, on-prem, hybrid), or consumer (human, service, device). It covers **security-specific** considerations; broader API design topics are out of scope except where they materially affect security (e.g., versioning, deprecation).

### 0.3 Audience

* **Service Owners & Developers** — implement and verify control requirements in code and configuration.
* **Platform & SRE** — enforce shared controls at gateways, ingress/egress, service mesh, and runtime infrastructure.
* **Security Engineering** — define standards, provide reference implementations, assure compliance, and monitor risk.
* **Data Owners** — classify data and approve protective controls proportionate to sensitivity.

### 0.4 Normative language

The terms **MUST**, **SHOULD**, and **MAY** indicate requirement strength. Where trade-offs exist, this document favors controls that reduce exploitability, contain blast radius, and simplify assurance.

### 0.5 Lifecycle alignment

Controls are organized to mirror the API lifecycle—**design → build → test → deploy → operate → retire**—so teams can integrate them into architecture reviews, CI/CD, change management, and operational runbooks.

### 0.6 Security posture and risk overview

APIs expose valuable functionality and data through machine interfaces. Compared with traditional web channels, they often present **greater reachability** (more entry points), **finer-grained operations**, and **richer metadata**, which can amplify impact when compromised. Key risk themes include:

* **Confidentiality risks**

  * Excessive data exposure or field-level overfetch; poorly scoped resources and generic endpoints that leak internal representations.
  * Credential and token leakage via URLs, logs, referrers, browser storage, or misconfigured CORS.
  * Man-in-the-middle interception when transport protections are weak or mixed content is allowed.

* **Integrity risks**

  * Object- and function-level authorization gaps (BOLA/BFLA) enabling read/write of unauthorized resources.
  * Injection and deserialization flaws (e.g., SQLi, XSS via consuming apps, XML parser attacks, header/parameter pollution) corrupting data or execution.
  * Credential stuffing and session weaknesses leading to spoofed identities and tampered requests.

* **Availability risks**

  * Abuse of write or search operations (wildcards, expensive queries) to degrade service or exhaust backends.
  * Unbounded payload sizes, file uploads without inspection, and client-initiated renegotiation/costly handshake patterns.
  * Zombie and deprecated endpoints that remain routable and exploitable.

* **Operational and ecosystem risks**

  * Incomplete inventory or drift between documented and runtime behavior.
  * Misconfiguration in cloud/container platforms (overly permissive networks, secrets at rest, weak TLS/ciphers).
  * Overly verbose errors disclosing implementation details and system topology.

The best practices that follow are designed to **prevent**, **detect**, and **contain** these failures by combining strong identity, least-privilege authorization, robust input/output handling, transport security, abuse prevention, observability, and disciplined lifecycle management.

### 0.7 Design prompts (use before the first line of code)

Teams should answer these questions during design reviews and update them as the API evolves:

* **Consumers & trust boundaries:** Who will call this API (human, service, device)? From which networks? Where does authentication terminate?
* **Data sensitivity:** What data classes traverse this API? What are the confidentiality/integrity/availability requirements?
* **Authorization model:** Which roles/scopes/attributes are required per operation and object? How is ownership of resources determined?
* **Interaction model:** Which methods or operations are allowed? What are size limits, pagination defaults, and query constraints?
* **Abuse resistance:** What quotas, rate limits, and anomaly signals apply per token, client, IP, and tenant?
* **Observability:** What must be logged at gateway and service layers? How will denied attempts and token failures be detected and alerted?
* **Secrets & keys:** Where are credentials stored, rotated, and audited?
* **Versioning & retirement:** How will changes be introduced, communicated, and how are old endpoints decommissioned?
* **Operational dependencies:** What upstream/downstream systems are in scope, and how do failure modes propagate?

### 0.8 Roles and responsibilities

* **Service Owner** — accountable for API behavior, implementing control requirements, and remediating findings.
* **Platform/SRE** — operates gateways/meshes, enforces central policies (authN/Z, TLS, quotas), and maintains secure defaults.
* **Security Engineering** — authors standards, provides guardrails (linters, templates, pipelines), performs threat modeling and assurance testing, and monitors runtime risk.
* **Data Owner** — classifies data, approves retention and masking rules, and signs off on exposure through APIs.

---

## 1) Discovery, documentation, and inventory

> Maintain an **API inventory** across production and lower environments; include third-party dependencies. Inventory must be **runtime-validated** to catch undocumented endpoints and schema drift.

> Author documentation in **machine-readable schemas** (OpenAPI/OAS, etc.) and use schema validators in CI/CD—while understanding their limitations. Monitor for **API drift** and close gaps with runtime discovery.

> Capture **data flows** in diagrams and classify APIs by sensitivity and data type to prioritize controls.

---

## 2) Gateway, identity, and tokens

> Put all externally reachable APIs **behind an API gateway** for centralized authN/Z checks, rate limiting, and logging; avoid re-implementing these features per service.

> Use a **centralized OAuth/OIDC Authorization Server** to issue and sign tokens; do _not_ mint access/refresh tokens in APIs or gateways. Centralization ensures consistent policies and key management.

> Prefer **opaque tokens to external clients; translate to JWTs internally** (phantom/split token patterns) so claims are not depended upon by third parties and privacy is preserved.

> Use **token exchange** for service-to-service calls to scope privileges narrowly; do not forward a client’s token across trust boundaries.

> Enforce **scopes** for coarse-grained authorization at the edge; evaluate finer authorization deeper in the service.

---

## 3) Authentication and session management

> **All endpoints require authentication**. Prefer OAuth2/OIDC or signed API keys for server-to-server. Avoid Basic Auth and bespoke schemes.

> For browser clients, **use session cookies** with `HttpOnly`, `Secure`, and appropriate `SameSite`. Pair with CSRF defenses.

> Do **not** place credentials, tokens, or API keys in **URLs**; these leak through logs and referrers. Use the `Authorization` header.

> If you adopt JWTs, **pin the algorithm**, set **short expirations**, sign tokens, and **never** accept `alg:"none"`. Exclude sensitive data from claims.

---

## 4) Authorization and access control

> Default-deny. Enforce **object-level authorization** (BOLA/IDOR) on _every_ request server-side; never trust client-supplied identifiers.

> Check that the **HTTP method** is authorized for the caller and resource; respond with **405** when inappropriate.

> Tie **scopes/roles/attributes** to endpoints and data sets; apply least privilege and separate admin planes from data planes.

---

## 5) Input validation and content negotiation

> Validate all input: **type/format/range/length**; reject unexpected fields and define **request size limits**. Use strong types where possible.

> Use **secure parsers**. Harden XML parsers against **XXE/signature wrapping** or avoid XML where possible.

> Enforce **Content-Type/Accept** strictly. Never mirror `Accept` into `Content-Type`. Use **415/406** when types are wrong.

> Always return the **correct Content-Type**; check error paths.

---

## 6) Output encoding and browser-facing protections

> Encode output and avoid reflecting user input; prevent **XSS/SQLi/RCE** with prepared statements and output encoding.

> Send **security headers** where applicable:  
> `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a minimal **Content-Security-Policy** (`default-src 'none'; frame-ancestors 'none'; sandbox`).

---

## 7) Transport security (TLS)

> **TLS is mandatory** for all non-public, state-changing, or credentialed traffic; prefer v1.2+. Enable **HSTS** for your production hostnames.

> Manage certificates and cipher configuration centrally; test regularly. (Security/Platform)

---

## 8) CORS (cross-origin requests)

> For cross-origin browser access, implement **CORS** correctly: handle **preflight** and explicitly set `Access-Control-Allow-Origin/Methods/Headers`.

---

## 9) Error handling and status codes

> Use **consistent error formats**. Avoid leaking stack traces, SQL, config, or internal details in messages.

> Return precise **status codes**: e.g., `401` (unauthenticated), `403` (unauthorized), `404` (not found), `405` (method), `415` (media type), `429` (rate limit). Keep messages generic.

---

## 10) Rate limiting and abuse prevention

> Apply **rate limits/quotas** at the gateway to contain brute force, scraping, and enumeration; tune dynamically as usage evolves.

> Prefer **adaptive controls** over blanket limits; separate per-token, per-IP, and per-resource policies. (Platform)

---

## 11) Logging, monitoring, and audit

> Log **before and after** security-relevant actions to durable storage; capture denied attempts and token validation failures. Centralize logs (SIEM) and set alerts.

> Define what must be logged across infrastructure, apps, and APIs; include performance/uptime telemetry and allocate storage for API analytics.

---

## 12) Data protection and secrets

> Encrypt **in transit** (TLS). Use **masking/redaction** in responses and logs for sensitive fields. (Security/Platform)

> Avoid “encrypting everything twice.” Prefer strong **transport protection** and proven crypto libraries; manage keys properly and **never** hard-code or store in client storage.

> Manage service credentials via **secrets stores** (Kubernetes Secrets/KMS); avoid long-lived keys at rest on disk. Rotate regularly.

---

## 13) Browser threats: CSRF and mixed contexts

> Defend **CSRF**: use anti-CSRF tokens or `SameSite` cookies, and ensure XSS is addressed first. Apply to **state-changing** methods.

---

## 14) Operational hygiene

> **Do not** use production/sensitive data in test environments. Use synthetic or masked data. (Service Owner)

> Lock down **management endpoints**: keep them off the Internet or require MFA, IP restrictions, and separate hosts/ports/subnets.

---

## 15) Versioning, deprecation, and “zombie” endpoints

> Adopt a clear **versioning strategy** and **deprecation policy**; document timelines and migration paths.

> Continuously find and **retire unused or legacy endpoints** to reduce attack surface and stop data leakage; combine documentation with **runtime discovery** to catch drift.

---

## 16) Testing, threat modeling, and assurance

> **Shift left**: perform threat modeling, automated scanning in CI/CD, and regular **pen tests** focused on business-logic abuse.

> Include **business logic** in design reviews; security issues often manifest only after deploy, so prioritize fast **detection and response** in runtime. Map controls to OWASP ASVS.

---

## Appendix A — Additional implementation notes

> Prefer **edge checks**: many controls (transport, rate limits, IP allow/deny) belong in infrastructure/gateway, not application code. Treat them as **infrastructure-as-code** owned by Platform/SRE.

> When using browser-facing APIs, add **Referrer-Policy** alongside CSP and other headers to minimize token leakage via referrers.

> Tools to consider for automation and guardrails (augment, don’t replace review): **Dredd**, **Spectral**, **Vacuum** (OpenAPI lint); **ZAP** for DAST.


BONUS:
Threat modelling, code and runtime analysis, and vulnerability scanning MUST be performed against all the developed APIs exposed to the public internet and within internal network. For detailed understanding of the process, please contact the Security team.

Tool(s) that have not been tested but worth considering:
	• apiaryio/dredd: Language-agnostic HTTP API Testing Tool
	• stoplightio/spectral: A flexible JSON/YAML linter for creating automated style guides
	• daveshanley/vacuum: vacuum is the worlds fastest OpenAPI 3, OpenAPI 2 / Swagger linter and quality analysis tool

Tool(s) that are currently being tested by Security team:
	• zaproxy/zaproxy: The ZAP by Checkmarx Core project


References:
https://cloudsecurityalliance.org/download/artifacts/security-guidelines-for-providing-and-consuming-apis
https://habr.com/en/articles/595075/
https://cdn-blog.getastra.com/2024/08/03236e5b-the-ultimate-api-security-audit-vapt-checklist.pdf
https://content.salt.security/rs/352-UXR-417/images/SaltSecurity-Whitepaper-API_Security_Best_Practices_20210825.pdf
https://26857953.fs1.hubspotusercontent-eu1.net/hubfs/26857953/Escape%20API%20Security%20checklist.pdf?ref=escape.tech
https://assets.treblle.com/what-breaks-in-api-security.pdf
https://www.stackhawk.com/blog/api-security-best-practices-ultimate-guide/
https://curity.io/resources/learn/api-security-best-practices/
https://www.impart.security/api-security-best-practices
 
