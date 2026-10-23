#!/usr/bin/env python3
"""
WAF Signature Validation Test Suite - F5 Distributed Cloud (XC) WAF
-------------------------------------------------------------------
Purpose: Send HTTP requests that carry the *shapes* of known attack patterns
(suspicious field names, path-traversal strings, large bodies) to an app
published through an F5 Distributed Cloud HTTP Load Balancer with a WAF
(App Firewall) policy attached. Nothing here exploits anything; it only
checks whether the WAF recognizes the patterns and, in Blocking mode,
stops them.

How to use it:
  1. Set TARGET_BASE_URL to the domain of your XC HTTP Load Balancer
     (the public name that resolves to F5's Regional Edges), NOT your
     origin server directly, or the WAF never sees the traffic.
  2. Run once with the App Firewall in "Monitoring" mode. Nothing is
     blocked, but every match still shows up as a security event.
  3. Switch the App Firewall to "Blocking" mode and run again. Blocked
     requests get XC's block page, which contains a Support ID. This script
     pulls that ID out for you.
  4. In the XC Console, open your load balancer's Security Analytics and
     add a filter on "req_id" with the Support ID to jump straight to that
     event and see which signatures matched. (The Support ID and req_id are
     the same value.)
     In Monitoring mode there's no block page, so search on the User-Agent
     instead: every request carries a unique "waf-test/<id>" tag in it.

Requires Python 3.8+ and nothing outside the standard library.
"""

# ---------------------------------------------------------------------
# Imports - all at the top so every part of the script can use them,
# no matter how the script is started.
# ---------------------------------------------------------------------
import datetime        # timestamps for each request
import json            # saving results to a file
import random          # random characters for the multipart boundary
import string          # ready-made sets of letters and digits
import re             # pattern matching, to find the Support ID in the block page
import urllib.error    # error types raised by urllib (e.g. 403 responses)
import urllib.parse    # URL-encoding query string values
import urllib.request  # actually sending HTTP requests
import uuid            # random IDs for multipart boundaries and test IDs

# ---------------------------------------------------------------------
# CONFIG - edit these before running
# ---------------------------------------------------------------------
TARGET_BASE_URL = "https://bourbon.cloud.myf5demo.com"

# An upload-handling path (tests 1-3) and a path that takes a filename-style
# query parameter (test 4). The WAF inspects the request BEFORE it reaches
# your app, so a signature can match even if these paths don't exist. A
# missing path just means that in Monitoring mode you'll see a 404 from your
# app instead of a 200; the security event is still recorded.
UPLOAD_PATH = "/upload.php"
FILE_PARAM_PATH = "/view/php?file=report.pdf"  # e.g. /view.php?file=report.pdf

# How much filler to put in front of the payload in test 3. I couldn't find
# a documented body-inspection limit for XC's WAF, so this test simply
# checks whether a payload buried deep in a large body is still caught.
# Start with 64 KB; try bigger values (e.g. 1 MB) to probe further.
LARGE_BODY_PADDING_BYTES = 64 * 1024

# Settings for test 2b (the PHP2Shell-style multipart shape).
# MANY_FIELDS_COUNT: how many ordinary form fields to include. A normal form
#   has a handful; 50 is unusual without being huge.
# REPEATED_SESSION_FIELDS: how many times the PHP_SESSION_UPLOAD_PROGRESS
#   field appears. A real form sends it once.
MANY_FIELDS_COUNT = 50
REPEATED_SESSION_FIELDS = 3

# Text that appears on your block page. The XC block page says
# "The requested URL was rejected..." and shows "Your Support ID is: ...".
# If you configured a custom block page, change this to text from yours.
BLOCK_PAGE_MARKER = "requested url was rejected"

# A normal browser User-Agent. Without this, urllib sends "Python-urllib/3.x".
# XC's bot classification can flag script-style clients as suspicious on
# their own, and then you can't tell whether the attack pattern or the
# User-Agent caused the reaction. A unique "waf-test/<id>" tag is added to
# the end of this string for every request, so you can find each one in
# Security Analytics by filtering on user agent.
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
)


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------
def timestamp():
    """Return the current UTC time as an ISO-8601 string ending in 'Z'."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.isoformat().replace("+00:00", "Z")


def find_support_id(body_text):
    """Look for "Support ID is: <value>" in a response body and return the
    value, or None if it isn't there.

    The block page is HTML, so first we strip out the HTML tags (anything
    between < and >) to leave plain text, then search for the phrase.
    re.IGNORECASE means upper/lower case doesn't matter.
    """
    plain = re.sub(r"<[^>]+>", " ", body_text)
    match = re.search(r"support\s*id\s*is:?\s*([A-Za-z0-9-]+)", plain, re.IGNORECASE)
    return match.group(1) if match else None


def looks_like_waf_block(status_code, body_text):
    """Decide whether a response looks like the WAF blocked the request.

    We check the page content rather than the status code alone, because
    the status code of a WAF block page depends on how the policy is set up
    (a custom block page lets you pick any code), and your app could send a
    403 of its own. Seeing the block page text or a Support ID is the
    reliable signal.
    """
    lowered = body_text.lower()
    return BLOCK_PAGE_MARKER.lower() in lowered or find_support_id(body_text) is not None


def send_request(url, method="GET", body=None, extra_headers=None):
    """Send one HTTP request and describe what happened, without crashing.

    Returns a dict with:
      test_id     - the unique tag we put in this request's User-Agent
      status_code - the HTTP status (None if we never reached a server)
      waf_blocked - True/False, or None if we never reached a server
      support_id  - the XC Support ID from the block page, if there was one
      error       - a short note if something went wrong
    """
    test_id = uuid.uuid4().hex[:12]
    headers = {"User-Agent": f"{BROWSER_USER_AGENT} waf-test/{test_id}"}
    headers.update(extra_headers or {})

    req = urllib.request.Request(url, data=body, method=method, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            status = response.getcode()
            # Read at most 64 KB of the reply - plenty to find a block page.
            # decode(..., "replace") turns any odd bytes into "?" instead
            # of crashing.
            text = response.read(65536).decode("utf-8", "replace")
            error = None
    except urllib.error.HTTPError as e:
        # urllib treats any 4xx/5xx status as an exception, but it is still a
        # real response with a real status code and body - which is exactly
        # where a WAF block page shows up.
        status = e.code
        text = e.read(65536).decode("utf-8", "replace")
        error = f"HTTP {e.code} {e.reason}"
    except urllib.error.URLError as e:
        # The request never reached a server at all (DNS failure, connection
        # refused, TLS problem, timeout). This is NOT a WAF decision.
        return {
            "test_id": test_id,
            "status_code": None,
            "waf_blocked": None,
            "support_id": None,
            "error": f"Connection problem (not a WAF response): {e.reason}",
        }

    return {
        "test_id": test_id,
        "status_code": status,
        "waf_blocked": looks_like_waf_block(status, text),
        "support_id": find_support_id(text),
        "error": error,
    }


def build_multipart_body(fields, boundary):
    """Build a multipart/form-data body by hand (what a browser sends when
    you submit a form with a file upload).

    `fields` is a list of dicts, one per form field:
        {"name": ..., "value": ..., "filename": ... (optional),
         "content_type": ... (optional)}

    `boundary` is the marker string that separates fields. It must match the
    boundary in the Content-Type header so the server can split the body.
    """
    parts = []
    for field in fields:
        disposition = f'Content-Disposition: form-data; name="{field["name"]}"'
        if "filename" in field:
            disposition += f'; filename="{field["filename"]}"'
        part = f"--{boundary}\r\n{disposition}\r\n"
        if "content_type" in field:
            part += f'Content-Type: {field["content_type"]}\r\n'
        part += f'\r\n{field["value"]}\r\n'
        parts.append(part)
    parts.append(f"--{boundary}--\r\n")  # the closing boundary has "--" at the end
    return "".join(parts).encode("utf-8")


def make_boundary():
    """Make a multipart boundary in the same format Chrome uses.

    Chrome (and other WebKit/Blink browsers) use "----WebKitFormBoundary"
    followed by exactly 16 random letters and digits. An earlier version of
    this script used 32 hex characters instead, which no real browser sends,
    so a WAF comparing it against our Chrome User-Agent could flag the
    mismatch.

    random.choices() picks 16 characters (with repeats allowed) from the
    pool of upper/lowercase letters and digits.
    """
    pool = string.ascii_letters + string.digits
    return "----WebKitFormBoundary" + "".join(random.choices(pool, k=16))


def send_multipart(path, fields):
    """Convenience wrapper: build a multipart body and POST it to `path`.
    Returns the result dict plus the body size in bytes."""
    boundary = make_boundary()
    body = build_multipart_body(fields, boundary)
    result = send_request(
        TARGET_BASE_URL + path,
        method="POST",
        body=body,
        extra_headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    return result, len(body)


def record(results, name, expect_block, result, **extra):
    """Print one test's outcome and add it to the results list.

    `expect_block` is True if, in Blocking mode, this request SHOULD be
    blocked, False if it should get through, and None if it depends on your
    policy (we just report what happened).
    """
    if result["waf_blocked"] is None:
        verdict = "ERROR"          # never reached the server
    elif expect_block is None:
        verdict = "INFO"           # no fixed expectation, check Security Analytics
    elif result["waf_blocked"] == expect_block:
        verdict = "PASS"
    else:
        verdict = "FAIL"

    entry = {"test": name, "timestamp": timestamp(), "expect_block": expect_block,
             "verdict": verdict, **extra, **result}
    print(f"  Test ID    : waf-test/{result['test_id']}")
    print(f"  Status     : {result['status_code']}  (WAF block? {result['waf_blocked']})")
    if result["support_id"]:
        print(f"  Support ID : {result['support_id']}   <- filter req_id on this")
    if result["error"]:
        print(f"  Note       : {result['error']}")
    print(f"  Verdict    : {verdict}")
    results.append(entry)


# ---------------------------------------------------------------------
# TEST 1: Baseline (negative control)
# ---------------------------------------------------------------------
# An ordinary small upload. If the WAF blocks THIS, you have a false
# positive and real users would be blocked too. It runs first on purpose:
# see the note about malicious-user detection in main().
def test_1_baseline(results):
    print("\n[Test 1] Baseline upload - expect: NOT blocked")
    result, size = send_multipart(UPLOAD_PATH, [
        {"name": "file", "value": "ordinary file content",
         "filename": "notes.txt", "content_type": "text/plain"},
    ])
    record(results, "1_baseline", expect_block=False, result=result, body_bytes=size)


# ---------------------------------------------------------------------
# TEST 2a: PHP_SESSION_UPLOAD_PROGRESS field name (single field)
# ---------------------------------------------------------------------
# The field name used by the PHP session.upload_progress technique. On its
# own, with a harmless value, it may not trip any attack signature. If you
# want it caught, a custom rule in the XC policy (for example a service
# policy matching that string in the request body) is the dependable way.
# So this test reports what happened rather than declaring pass/fail.
def test_2_session_upload_progress(results):
    print("\n[Test 2a] PHP_SESSION_UPLOAD_PROGRESS field - depends on your policy")
    result, size = send_multipart(UPLOAD_PATH, [
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "value": f"waf_sig_test_{uuid.uuid4().hex[:8]}"},
        {"name": "file", "value": "test content",
         "filename": "test.txt", "content_type": "text/plain"},
    ])
    record(results, "2a_session_upload_progress", expect_block=None, result=result, body_bytes=size)


# ---------------------------------------------------------------------
# TEST 2b: Upload-progress field + many fields + repeated session field
# ---------------------------------------------------------------------
# The PHP2Shell reporting (CVE-2026-109618 / -109619) describes crafted
# multipart uploads using PHP's session upload-progress feature, and WAF
# vendors say they watch for excessive field counts and repeated
# session-related fields. This test sends that SHAPE: the upload-progress
# field repeated a few times plus MANY_FIELDS_COUNT ordinary fields.
#
# It stays small on purpose (a few KB). It does not try to exhaust memory
# or trigger the bug; it only checks whether the WAF flags the shape.
#
# Compare with test 2a: if 2b is blocked but 2a isn't, the WAF is keying on
# the field count / repetition rather than the field name alone.
def test_2b_upload_progress_many_fields(results):
    print(f"\n[Test 2b] Upload-progress field x{REPEATED_SESSION_FIELDS} + "
          f"{MANY_FIELDS_COUNT} fields - depends on your policy")

    fields = []
    # The session upload-progress field, repeated a few times.
    for i in range(REPEATED_SESSION_FIELDS):
        fields.append({"name": "PHP_SESSION_UPLOAD_PROGRESS",
                       "value": f"waf_sig_test_{i}_{uuid.uuid4().hex[:8]}"})
    # Lots of ordinary small fields. A list comprehension builds them all
    # in one line: field_0 = value_0, field_1 = value_1, and so on.
    fields += [{"name": f"field_{i}", "value": f"value_{i}"} for i in range(MANY_FIELDS_COUNT)]
    # And a normal small file, so it still looks like an upload.
    fields.append({"name": "file", "value": "test content",
                   "filename": "test.txt", "content_type": "text/plain"})

    result, size = send_multipart(UPLOAD_PATH, fields)
    record(results, "2b_upload_progress_many_fields", expect_block=None, result=result,
           body_bytes=size, field_count=len(fields))


# ---------------------------------------------------------------------
# TEST 3: Attack pattern buried deep in a large body
# ---------------------------------------------------------------------
# Puts LARGE_BODY_PADDING_BYTES of filler first and a path-traversal string
# AFTER it. If test 4 (same string in the URL) is blocked but this one gets
# through, the WAF isn't inspecting that far into request bodies, and an
# attacker could hide a payload there. Reported as INFO because the right
# answer depends on your policy's size settings.
def test_3_payload_deep_in_body(results):
    print(f"\n[Test 3] Payload after {LARGE_BODY_PADDING_BYTES} bytes of padding - compare with test 4")
    padding = "A" * LARGE_BODY_PADDING_BYTES
    result, size = send_multipart(UPLOAD_PATH, [
        {"name": "padding", "value": padding},
        {"name": "path", "value": "../../../../etc/passwd"},  # sits after the padding
    ])
    record(results, "3_payload_deep_in_body", expect_block=None, result=result, body_bytes=size)


# ---------------------------------------------------------------------
# TEST 4: Path traversal / LFI payloads in a query parameter
# ---------------------------------------------------------------------
# Classic Local File Inclusion strings. XC's attack signatures cover
# directory traversal, so with signatures set to block these should be
# stopped. Security Analytics shows which signature IDs matched.
def test_4_path_traversal(results):
    print("\n[Test 4] Path traversal / LFI payloads - expect: blocked")
    payloads = [
        "../../../../etc/passwd",
        "php://filter/convert.base64-encode/resource=index",
        "....//....//....//etc/passwd",
    ]
    for payload in payloads:
        # quote() URL-encodes characters like ":" so the URL is valid.
        # The WAF decodes it again before matching.
        url = f"{TARGET_BASE_URL}{FILE_PARAM_PATH}?file={urllib.parse.quote(payload)}"
        print(f"  Payload    : {payload}")
        result = send_request(url)
        record(results, "4_path_traversal", expect_block=True, result=result, payload=payload)


# ---------------------------------------------------------------------
# Main - runs every test, prints a summary, saves results to JSON
# ---------------------------------------------------------------------
def main():
    if TARGET_BASE_URL == "https://your-app.example.com":
        print("!! Edit TARGET_BASE_URL at the top of this script before running. !!")
        return

    print("WAF Signature Test Suite - F5 Distributed Cloud")
    print(f"Target  : {TARGET_BASE_URL}")
    print(f"Started : {timestamp()}")
    print("=" * 60)

    # Order matters. If malicious-user detection is enabled on the load
    # balancer, XC can start challenging or blocking YOUR IP after it sees
    # several attacks from it. Running the baseline first keeps it clean.
    # If a re-run's baseline suddenly fails, that's the likely reason:
    # check Security Analytics / Malicious Users for your IP.
    results = []
    test_1_baseline(results)
    test_2_session_upload_progress(results)
    test_2b_upload_progress_many_fields(results)
    test_3_payload_deep_in_body(results)
    test_4_path_traversal(results)

    # Summary table. PASS/FAIL only make sense in Blocking mode; in
    # Monitoring mode everything gets through by design.
    print("\n" + "=" * 72)
    print(f"{'Test':<32}{'Status':<8}{'Blocked':<9}{'Verdict':<9}Support ID")
    for r in results:
        label = r["test"] + (f" ({r['payload'][:10]}..)" if "payload" in r else "")
        print(f"{label:<32}{str(r['status_code']):<8}{str(r['waf_blocked']):<9}"
              f"{r['verdict']:<9}{r['support_id'] or '-'}")

    output_file = "waf_test_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to {output_file}")
    print("In Security Analytics, filter req_id on each Support ID (Blocking mode)")
    print("or user agent containing waf-test/<id> (Monitoring mode).")


# This only runs when you start the script directly (python waf_signature_tests.py),
# not when another script imports it.
if __name__ == "__main__":
    main()