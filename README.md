# Camp-Notes


## 0) Introduction, scope, and how to use this guide

**What this is.**  
This guide is a curated set of API **security** best practices developed by engineering and security practitioners. It exists to make secure outcomes repeatable across teams, reduce avoidable mistakes, and capture what works in our environment.

**Who should use it.**

- **Service Owners / Developers** designing and building APIs.
    
- **Platform / SRE** operating gateways, identity, networking, and telemetry.
    
- **Security** defining policy, providing guardrails, and assuring controls.
    

**How to read it.**

- Items use **RFC 2119** language (“MUST/SHOULD/MAY”) to signal priority.
    
- Treat these as **strong defaults**. Exceptions require risk review and a documented compensating control.
    
- Apply practices across the full lifecycle: **design → build → test → deploy → operate → retire**.
    

**What’s in scope.**  
Controls for public and internal APIs (REST, GraphQL, gRPC/HTTP), browser- and service-to-service use cases, and the shared platform that enforces them (gateway, identity, observability). General API design topics (naming, pagination, etc.) are out of scope unless they materially affect security.

---

### 0.1 A short primer: who, how, and what are we securing?

**Who interacts with our APIs?**
- **End users via first/third-party apps** (browsers, mobile, device clients).
- **Partner and machine clients** (service accounts, backend jobs, integrations).
    

**How do they access?**
- Through an **edge** (API gateway, WAF, CDN) enforcing TLS, rate limits, authN/Z.
- With **federated identity** (OAuth2/OIDC), short-lived tokens, and policy at the edge and service tiers.
- Over **zero-trust** networks: authenticated, authorized, and encrypted by default.
    

**What components make up API security here?**
- **API gateway** (central authN/Z, quotas, schema checks, threat protections)
- **Authorization server / IdP** (token issuance, keys/rotation, scopes)
- **Service mesh / mTLS** for east-west where applicable
- **Secrets management** (KMS/secret store; no credentials in code or client storage)
- **Observability** (central logs, traces, metrics, anomaly detection)
- **CI/CD security** (linting, schema validation, SAST/DAST, dependency checks)
- **Data protection** (classification, field-level masking/redaction, encryption)
    

---

### 0.2 Why this matters: API-specific risks to address

APIs inherit traditional web risks and **amplify** them through automation, richer data, and connectivity. Key risk themes:
- **Expanded attack surface**: more entry points, more services, more versions; “zombie”/undocumented endpoints and drift increase exposure.
- **Data overexposure**: overly broad responses, generic or “wildcard” resource access, or direct plumbing of request fields into DB queries.
- **Broken authZ/authN**: object-level access control failures (BOLA/IDOR), token misuse or leakage, weak session handling, or forwarding end-user tokens across trust boundaries.
- **Injection and input flaws**: SQL/XML/JSONPath injection, HTTP parameter pollution, unsafe deserialization, and insufficient content-type validation.
- **Client and browser risks**: XSS enabling CSRF bypass, mixed content over TLS, and permissive CORS causing token or data leakage.
- **Abuse and availability**: credential-stuffing, scraping, and unbounded writes leading to **DoS** on services or data stores.
- **Supply and platform misconfig**: weak TLS/ciphers, unmanaged certificates, insecure cloud/container defaults, exposed admin planes, or missing inline malware scanning for uploads.
- **Privacy and compliance**: APIs concentrating **PII/PHI** increase the blast radius of any breach and require strict minimization and observability.
- **Error and system leakage**: verbose errors or headers that disclose versions, topology, or internal identifiers.
    

This guide’s controls are structured to mitigate those risks at each lifecycle stage and across the stack—edge, identity, service, data, and runtime operations.

### 0.3 Ownership and accountability

Every API must have a named **Service Owner**. Shared controls are operated by **Platform/SRE**; security policy, threat modeling, and assurance are owned by **Security**. Ownership is recorded in the API inventory and reviewed at each release and during deprecation.

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
 
