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
