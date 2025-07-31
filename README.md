# Camp-Notes

> Not every user has a right to every web service. This is vital, as you don't want administrative web services to be misused. The API key SHOULD be sent along as a cookie, body parameter, or HTTP message header to ensure that privileged collections or actions are properly protected from unauthorized use. Every API MUST BE authenticated before it can be used.

Try testing for broken authentication scenarios like reuse of old tokens or using tokens from a different context.

> Use standard patterns and frameworks such as OAuth2 or JWT rather than implementing your own authentication or authorization mechanisms.

> Server versioning information or any other sensitive information from the HTTP headers SHOULD BE removed/masked according to industry best practices (e.g. removing the Server or 
X-Powered-By header). This prevents any form of targeted attacks since the vulnerabilities are mostly specific to the vendors.

> Modern browsers support many HTTP headers that can improve web application security to protect against clickjacking, cross-site scripting, and other common attacks. Your API SHOULD use security HTTP headers to improve the level of protection. See the list of OWASP Secure Headers to form the combination of headers. Ideally you SHOULD include HTTP Security Headers at least in these areas unless there is an incompatibility with some functional requirement:
	• HTTP Strict Transport Security (HSTS)
	• Content-Security-Policy
	• X-Frame-Options
	• X-Content-Type-Options
	• X-Permitted-Cross-Domain-Policies
	• Referrer-Policy
	• Clear-Site-Data
	• Cross-Origin-Embedder-Policy
	• Cross-Origin-Opener-Policy
	• Cross-Origin-Resource-Policy
	
> RESTful web services SHOULD use session-based authentication, either by establishing a session token via a POST or by using an API key (Client ID and a Client Secret) as a POST body argument or as a cookie. Usernames, passwords, session tokens, API keys, and sensitive information MUST NOT appear in the URL, as this can be captured in web server logs, which makes them intrinsically valuable.

> RESTful API often use GET (read), POST (create), PUT (replace/update) and DELETE (to delete a record). Not all of these are valid choices for every single resource collection, user, or action. Make sure the incoming HTTP method is valid for the session token/API key and associated resource collection, action, and record.

> Make sure that any default behaviors SHOULD deny access rather than granting them. This ensures that coding errors or unhandled exceptions do not inadvertently grant access. 
Use claims-based access control to allow access to requests that fulfill concrete authorization policies.

> While designing a REST API, DO NOT just use 200 for success or 404 for error. Every error message needs to be customized as NOT to reveal any unnecessary information. Here are some guidelines to consider for each REST API status return code. Proper error handle may help to validate the incoming requests and better identify the potential security risks.
	• 200 OK - Response to a successful REST API action.
	• 400 Bad Request - The request is malformed, such as message body format error.
	• 401 Unauthorized - Wrong or no authentication ID/password provided.
	• 403 Forbidden - It's used when the authentication succeeded but authenticated user doesn't have permission to the requested resource
	• 404 Not Found - When a non-existent resource is requested
	• 405 Method Not Allowed - The error checking for unexpected HTTP method. For example, the RestAPI is expecting HTTP GET, but HTTP PUT is used.
	• 429 Too Many Requests - The error is used when there may be DOS attack detected or the request is rejected due to rate limiting

> Everything you know about input validation applies to RESTful web services, but add 10% because automated tools can easily fuzz your interfaces for hours on end at high velocity. Help the user input high-quality data into your web services, such as ensuring a Zip code makes sense for the supplied address, or the date makes sense. If not, reject that input. Also, make sure that the output encoding is robust for your application. Some other specific forms of input validations need to be implemented:
	• Secure parsing: Use a secure parser for parsing the incoming messages. If you are using XML, make sure to use a parser that is NOT VULNERABLE to XXE and similar attacks.
	• Strong typing: It's difficult to perform most attacks if the only allowed values are true or false, or a number, or one of a small number of acceptable values. Strongly type incoming data as quickly as possible.
	• Validate incoming content-types: When POSTing or PUTting new data, the client will specify the Content-Type (e.g. application/xml or application/json) of the incoming data. The server SHOULD NEVER assume the Content-Type; it SHOULD ALWAYS check that the Content-Type header and the content are the same types. A lack of Content-Type header or an unexpected Content-Type header SHOULD result in the server rejecting the content with a 406 Not Acceptable response.
	• Validate response types: It is common for REST services to allow multiple response types (e.g. application/xml or application/json, and the client specifies the preferred order of response types by the Accept header in the request. DO NOT simply copy the Accept header to the Content-type header of the response. Reject the request (ideally with a 406 Not Acceptable response) if the Accept header does not specifically contain one of the allowable types. Because there are many MIME types for the typical response types, it's important to document for clients specifically which MIME types should be used.
	• XML input validation: XML-based services MUST ensure that they are protected against common XML-based attacks by using secure XML-parsing. This typically means protecting against XML External Entity attacks, XML-signature wrapping etc.

> API's input/output data SHOULD escape dangerous characters, tags and HTML attributes that cause JavaScript to be evaluated. You can use standard libraries which have been thoroughly checked by many professionals. However, DO NOT TRY TO DO THIS YOURSELF. Use a known library or the auto-escaping features of your favorite template library. This needs to be done in the browser and on your server if you allow users to submit data that is saved into a database. Relevant article.

> Production data or any form of sensitive data SHOULD NOT be used while testing the APIs in the test environment.

> API rate limiting monitors the access to an API endpoint for a given client (usually based on IP address) and checks to see whether a predetermined allowed number of accesses has been made within a given window. The more robust and preferred option is to use dynamic rate limiting in either an API gateway or an API firewall, where the processing burden can be offloaded to dedicated processors

> Cookies are the primary method used across external-facing APIs to save authentication information in the browser. Client's browsers will automatically send the authentication information with every request to the API. Prevention against Cross Site Request Forgery (CSRF) is a must while using this technique. It is also strongly recommended to use cookies with HTTPOnly and/or Secure flags set. This will allow the browser to send along the token for authentication purposes, but won’t expose it to the JavaScript environment.

> For resources exposed by RESTful web services, it's important to make sure any PUT, POST, and DELETE request is protected from Cross Site Request Forgery. Typically, one would use a token-based approach. See Cross-Site Request Forgery Prevention Cheat Sheet for more information on how to implement CSRF-protection.

CSRF is easily achieved even when using random tokens if any XSS exists within your application, so PLEASE MAKE SURE you understand how to prevent XSS

> A URL or even a POSTed form SHOULD NEVER contain an access control "key" or similar that provides automatic verification. A contextual data check needs to be done, server side, with each request to protect the API from broken access control. See IDOR for more information.

> When your API's resources receive requests from a domain other than the API's domain, you MUST enable cross-origin resource sharing (CORS) for selected methods on the resource. This amounts to having your API respond to the OPTIONS preflight request with at least the following CORS-required response headers:
	• Access-Control-Allow-Methods
	• Access-Control-Allow-Headers
	• Access-Control-Allow-Origin

> In addition to HTTPS/TLS, JSON Web Token (JWT) is an open standard that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. JWT can be used not only to ensure the message integrity but also authentication of both message sender/receiver. The JWT includes the digital signature hash value of the message body to ensure message integrity during the transmission.

> When serving up content to your users over TLS, it’s important that you DO NOT include content served over HTTP such as images, JavaScript, or CSS. By mixing HTTP content with HTTPS content, you expose your users to Man-in-the-Middle attacks and eliminate the security benefits that TLS provides.

> For the communication to be set up, a number of checks on the certificates MUST be passed:
	• Check certificate expiry
	• Check CA signature
	• Check that a value in the Subject Alternative Name extension or in the Subject Distinguished Name field matches the authorized client.

> The following checklist MUST be followed while using a TLS certificate:
	• X.509 certificates key length MUST be strong (e.g. if RSA is used the key MUST be at least 2048 bits).
	• X.509 certificates MUST be signed only with secure hashing algorithms (e.g. not signed using the MD5 hash, due to known collision attacks on this hash).
	• SHA-1 (or MD5) certificates SHOULD NOT BE used. The problem isn't the security of the server's real certificate; it's the client policy that allows the client to trust low-security certificates. StackExchange link

> The encryption ciphers supported by the server may allow an attacker to eavesdrop on the connection. Verify the following guidelines:
	• When serving up content to your users, ONLY strong ciphers are enabled (128 bits and above).
	• When connecting to other remote systems ensure that your client DOES NOT connect using a weak cipher if the server supports it.
	• Renegotiation MUST be properly configured (e.g. Insecure Renegotiation MUST be disabled, due to Man in the Middle (MiTM) attacks and Client-initiated Renegotiation MUST be disabled, due to Denial of Service vulnerability).

Further guidance regarding the last two TLS best practices is available in base security requirements documentation

> “Zombie endpoints” are those that are not actively maintained or used as intended, but are still accessible to users. These zombie endpoints are easy targets for attackers, and can compromise an entire API or system.

Monitoring, managing, and deprecating unused endpoints is essential to eliminate data leakage. In general, API versioning and documentation enable simpler API updates and minimize API implementation drift.



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
 
