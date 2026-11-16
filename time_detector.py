import json
from datetime import datetime, timedelta
from collections import defaultdict, deque

ALERT_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)

events = []

with open("events.jsonl", "r") as file:
    for line in file:
        event = json.loads(line)
        event["timestamp"] = datetime.fromisoformat(
            event["timestamp"]
        )
        events.append(event)

#Process events in chronological order
events.sort(key=lambda event: event["timestamp"])

#Track recent failures for each IP
recent_failures = defaultdict(deque)
alerted_ips = set()

for event in events:

    if event["event"] != "login_failure":
        continue

    ip = event["ip"]
    timestamp = event["timestamp"]

    recent_failures[ip].append(timestamp)

    #Remove events older than five minutes
    while (
        recent_failures[ip]
        and timestamp - recent_failures[ip][0] > TIME_WINDOW
    ):
        recent_failures[ip].popleft()

    #Generate an alert
    if len(recent_failures[ip]) >= ALERT_THRESHOLD:
        if ip not in alerted_ips:
            print(
                f"[ALERT] {ip}: "
                f"{len(recent_failures[ip])} failed logins "
                f"within 5 minutes"
            )
            alerted_ips.add(ip)