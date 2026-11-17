import json
from collections import Counter

ALERT_THRESHOLD = 2

#store all security events
events = []

#Read the JSONL file
with open("events.jsonl", "r") as file:
	for line in file:
		event = json.loads(line)
		events.append(event)

#Extract failed login events
failed_logins = [
	event for event in events
	if event["event"] == "login_failure"
]

# Count failed logins by IP address
ip_counts = Counter(
	event["ip"] for event in failed_logins
)

# Count failed logins by Username
username_counts = Counter(
	event["username"] for event in failed_logins
)

total_failures = len(failed_logins)

#Display report
print("=== SECURITY LOG REPORT ===")
print(f"Total events: {len(events)}")
print(f"Failed logins: {len(failed_logins)}")

print("\nFailed logins by IP:")

for ip, count in ip_counts.items():
	print(f"{ip}: {count}")

print("\n=== SECURITY ALERTS ===")

for ip, count in ip_counts.items():
	if count >= ALERT_THRESHOLD:
		print(f"[ALERT] Suspicious activity from {ip}")
		print(f"        Failed attempts: {count}")

print("\n=== FAILED LOGINS BY USERNAME ===")
for username, count in username_counts.items():
	print(f"{username}:{count}")

print("\n=== ADDITIONAL SECURITY ALERTS ===")

#Detect repeated attempts against one username
for username, count in username_counts.items():
	if count >= ALERT_THRESHOLD:
		print(f"[ALERT] Multiple failures targeting: {username}")
		print(f"        failed attempts: {count}")

# Detect unusually high overall failure volume
if total_failures >= 5:
	print("[ALERT] High volume of failed logins across the system")