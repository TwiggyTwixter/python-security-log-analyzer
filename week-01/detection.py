from collections import defaultdict, deque
from datetime import datetime, timedelta

def detect_brute_force(events, threshold=3, window_minutes=5):
    window = timedelta(minutes=window_minutes)
    recent_failures = defaultdict(deque)
    alerts = []

    sorted_events = sorted(
        events,
        key=lambda event: event["timestamp"]
    )

    for event in sorted_events:
        if event["event"] != "login_failure":
            continue
        
        ip = event["ip"]
        timestamp = datetime.fromisoformat(event["timestamp"])

        failures = recent_failures[ip]
        failures.append(timestamp)

        while failures and timestamp - failures[0] > window:
            failures.popleft()
        
        if len(failures) == threshold:
            alerts.append({
                "ip": ip,
                "count": len(failures),
                "timestamp": event["timestamp"]
            })
    return alerts