# Sanitized network artifact fixtures for regression tests (no real secrets).

SSE_SAMPLE = """HTTP/2 200 OK
content-type: text/event-stream

data: {"token":"Hello, how can I assist?"}

"""

TRACE_HEADERS = {
    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-4bf92f3577b34da6a3ce929d0e0e4737-01",
    "x-request-id": "req_01abcdef",
    "cf-ray": "654321-BLR",
}
