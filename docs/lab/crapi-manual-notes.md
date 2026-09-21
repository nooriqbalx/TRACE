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
