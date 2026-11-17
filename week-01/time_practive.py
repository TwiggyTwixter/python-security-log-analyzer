from datetime import datetime, timedelta

first_login = datetime.fromisoformat("2026-11-16T08:00:00Z")
second_login = datetime.fromisoformat("2026-11-16T08:03:00Z")

difference = second_login - first_login

print(f"Time difference: {difference}")
print(f"Difference in seconds: {difference.total_seconds()}")

window = timedelta(minutes=5)

if difference <= window:
    print("Both events occured within 5 minutes")