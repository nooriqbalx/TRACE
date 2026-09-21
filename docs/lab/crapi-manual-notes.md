# crAPI Manual Exploitation Notes

## BOLA: vehicle location (identity service)

**Endpoint:** GET /identity/api/v2/vehicle/{vehicle_id}/location

**Preconditions:**
- Two registered crAPI users, A and B, each with a valid login token
  (role=user). No special privilege needed on either account.
- Each user has added their own vehicle via the dashboard.

**Exact request:**
GET /identity/api/v2/vehicle/ddb239a6-6c4e-42cb-bbda-5b948b921ef4/location HTTP/1.1
Host: localhost:8888
Authorization: Bearer <user B's token, sub=b@gmail.com>
(vehicle ID belongs to user A; token belongs to user B)

**Response evidence (what proves it):**
HTTP status: 200
{"carId":"ddb239a6-6c4e-42cb-bbda-5b948b921ef4",
 "vehicleLocation":{"id":1,"latitude":"32.778889","longitude":"-91.919243"},
 "fullName":"Noor Iqbal","email":"a@gmail.com"}

User B's token retrieved user A's live GPS coordinates, full name and email.
Coordinates match user A's location shown in A's own dashboard, confirming
this is genuinely A's data, not a placeholder or default value.

**Root cause (in my own words):**
The JWT issued at login only encodes sub (the user's email) and role;
it carries no claim tying the token to a specific vehicle or resource. This
means authorization has to be enforced at the point the server looks up
the vehicle by ID in the database (i.e. "does this vehicle belong to the
authenticated subject?"). This endpoint accepts any authenticated user's
token and returns the requested vehicle_id's data unconditionally, with no
ownership check against the token's sub claim. Any valid, logged-in user
can therefore enumerate other users' vehicle IDs (e.g. via the community
forum, where vehicle IDs are exposed) and read their location, name and
email. This is a textbook Broken Object-Level Authorization vulnerability
(OWASP API1:2023, CWE-639).

**Fix:**
Before returning vehicle data, the endpoint should look up the vehicle's
owner_id and compare it against the authenticated user's identity (from
the validated token), returning 403 if they don't match. This check must
happen at the database/business-logic layer, not rely on any client-
supplied value, since IDs in the URL are always attacker-controlled.

**How a defender would detect it:**
- Log every vehicle-location request with the (authenticated_user,
  requested_vehicle_id) pair; alert when a single user's token requests
  location for many distinct vehicle IDs in a short window (enumeration
  pattern).
- A WAF/API gateway rule flagging path-parameter values that don't match
  any resource the caller is known to own, if an ownership index is
  available at the gateway layer.
- This is exactly the kind of check TRACE's deterministic verifier will
  automate later: create two users, attempt cross-access, confirm the
  differential (owner succeeds, non-owner should fail but doesn't).

## Note: vehicle-details endpoint (not this path)
Tried GET /identity/api/v2/vehicle/{id} (no /location suffix) with B's token
against A's vehicle ID -> HTTP 404, "No static resource". This route does
not exist on the identity service; the dashboard's vehicle-details data is
served via a different path/service, not yet identified. Not pursued further
for this project; the confirmed BOLA on /location is sufficient evidence for
this class.

## Broken Authentication: OTP brute-force on password reset

**Endpoint:** `POST /identity/api/auth/v3/check-otp`
**Related:** `POST /identity/api/auth/forget-password` (triggers OTP)

**Preconditions:**
- Any known/guessable user email (e.g. from the community forum, or the
  signup flow itself confirms whether an email exists).
- No authentication required to call either endpoint.

**Exact request:**

**Response evidence (what proves it):**
- OTP is exactly 4 digits (0000-9999), confirmed from a real reset email
  ("Your one time generated otp is: 2509").
- Automated script sent 201 sequential guesses (OTP 0000-0200) against a
  single triggered reset, with no authentication, no CAPTCHA, and no
  session/device binding required.
- Result: 201/201 requests answered in 4 seconds total (~50 req/s), zero
  HTTP 429 responses, zero lockout, zero increase in response latency
  across the run.
- 200 of 201 wrong guesses returned HTTP 500 (unhandled server error)
  instead of a clean 400/401 "invalid OTP" response; 1 returned a
  different status. The 500s did not slow down or block subsequent
  requests, ruling out an accidental circuit-breaker effect.
- Full 10,000-value keyspace is therefore exhaustible in an estimated
  ~200 seconds (~3.3 minutes) from a single script/connection; multiple
  parallel connections would reduce this further.
- Earlier manual test (see reset flow screenshot) confirmed OTP 2509 was
  the real, valid, one-time code for that trigger, verifying the OTP
  check itself is a genuine gate, not decorative, which is what makes
  its brute-forceability meaningful.

**Root cause (in my own words):**
The password-reset flow protects account takeover with only a 4-digit
numeric OTP (10,000 possible values) and enforces no server-side controls
against repeated guessing, no rate limit per email/IP, no exponential
backoff, no maximum-attempts lockout, and no CAPTCHA after N failures.
Because the OTP space is so small and guessing is unthrottled, the
"knowledge factor" this flow relies on provides negligible real security;
an attacker who knows or can enumerate a victim's email can take over the
account in minutes without ever touching the victim's mailbox. Separately,
invalid OTP values trigger an HTTP 500 rather than a handled validation
error, suggesting the invalid-OTP code path is not gracefully handled
(likely an unhandled exception, e.g. on OTP lookup miss), which is a
robustness issue independent of the rate-limiting gap.

**Fix:**
- Rate-limit `check-otp` per (email, IP) pair: e.g. lock the account's
  reset flow after 5 failed attempts for a cooldown period, and/or
  exponential backoff per attempt.
- Increase OTP entropy/length or pair it with a second factor (e.g. also
  require the original session token from the forgot-password step).
- Invalidate the OTP entirely after N failed attempts, not just after
  first successful use.
- Fix input handling so invalid/unrecognized OTPs return a clean 400,
  not a 500, and add server-side logging/alerting on repeated 500s from
  the same email or IP, since that pattern itself is a brute-force signal.

**How a defender would detect it:**
- Alert on >N `check-otp` requests for the same email or from the same IP
  within a short window, regardless of response status.
- Alert on repeated 500 responses from the same source, an unhandled
  error occurring dozens of times per second from one client is itself
  anomalous, independent of what the endpoint does.
- This is the second concrete pattern TRACE's deterministic verifier
  will need to check for the broken-authentication class: trigger a
  reset, fire a bounded, capped batch of guesses (never the full
  keyspace against a real target), and confirm whether a 429/lockout
  ever appears within that capped budget.

## BOLA + Excessive Data Exposure: mechanic service reports

**Endpoint:** `GET /workshop/api/mechanic/mechanic_report?report_id={id}`

**Preconditions:**
- Any authenticated user token (role=user).
- A valid, existing report_id. IDs are sequential integers, trivially
  enumerable (this report was id=6 after only a handful of test accounts
  and submissions).

**Exact request:**
(report belongs to user A, who submitted it; token belongs to user B, who
has no relationship to A, this vehicle, or this report)

**Response evidence (what proves it):**
Identical response returned for both A's own token and B's token against
the same report_id, confirming no ownership check is performed.

Two distinct issues in this one finding:
1. **BOLA (API1:2023, CWE-639):** any authenticated user can read any
   report by guessing/enumerating its sequential integer ID, regardless
   of who submitted it or which vehicle it concerns.
2. **Excessive Data Exposure (API3:2023, CWE-213):** the response
   includes the vehicle owner's full phone number
   (vehicle.owner.number), a field never requested or displayed
   anywhere in the Contact Mechanic UI flow. Even the legitimate report
   owner is being served more PII than the feature needs, and this
   over-exposure is what makes the BOLA bug above significantly worse,
   an attacker doesn't just learn "a report exists", they get a phone
   number and email tied to a specific VIN.

**Root cause (in my own words):**
Same systemic pattern as the vehicle-location bug: the JWT carries only
`sub` and `role`, no resource-scoping claim, so authorization must be
enforced server-side per request. This endpoint performs no such check,
it looks up report_id in the database and returns the full nested object
graph (mechanic, vehicle, owner) to any bearer of a valid token. The
sequential integer ID makes enumeration trivial (no UUID randomness to
brute-force), so an attacker can iterate report_id=1,2,3... and harvest
every user's email, phone number and VIN from this single endpoint.
Additionally, the response serializer was not scoped down for this
use case, it appears to reuse a general-purpose "full report" object
that includes fields (owner.number) irrelevant to a mechanic-status
lookup, which is a separate, additive privacy failure on top of the
missing ownership check.

**Fix:**
- Enforce ownership: before returning a report, check that the
  requesting user's sub matches either vehicle.owner or the assigned
  mechanic, return 403 otherwise.
- Switch report_id (and other resource identifiers of this kind) from
  sequential integers to random UUIDs, removing easy enumerability as
  defense in depth (this alone does not fix the BOLA, but raises the
  cost of exploitation).
- Apply response-level field minimization: define a narrow serializer
  for this endpoint that omits owner.number and any other field the
  calling context does not need, rather than reusing a broad internal
  model.

**How a defender would detect it:**
- Alert on a single (authenticated_user, report_id) access pattern
  where report_id values span many different owners in a short window,
  the same enumeration signature as the vehicle-location bug.
- Response-size/field-content monitoring: flag endpoints whose
  responses include PII fields (phone, email) not present in the
  corresponding request or UI flow, a form of data-loss-prevention
  check at the API gateway.
- This is now the second and third confirmed instance of the identical
  missing-ownership-check pattern across two unrelated resource types
  (vehicle location, service reports). TRACE's BOLA verifier oracle
  should therefore be written generically, parameterized by resource
  type and ID field, not hardcoded to one endpoint, since this app
  demonstrates the same root cause recurs across a codebase.

## Note: report_link exposes VIN in URL query string
The contact_mechanic response and the browser URL both carried the VIN
as a plaintext query parameter
(?VIN=L5WJ7PDXP16AZV22F, and report links follow the same pattern with
report_id). Identifiers like this ending up in URLs means they persist
in browser history, server access logs, and any shared screenshot or
referrer header, a minor but real exposure surface, distinct from but
related to the excessive-exposure finding above.
