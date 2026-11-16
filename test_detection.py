import unittest
from detection import detect_brute_force

class TestBruteForceDetection(unittest.TestCase):

    def test_three_failures_within_five_minutes(self):
        events = [
            {
                "timestamp": "2026-11-16T08:00:00Z",
                "event": "login_failure",
                "ip": "203.0.113.15"
            },
            {
                "timestamp": "2026-11-16T08:02:00Z",
                "event": "login_failure",
                "ip": "203.0.113.15"
            },
            {
                "timestamp": "2026-11-16T08:04:00Z",
                "event": "login_failure",
                "ip": "203.0.113.15"
            }
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "203.0.113.15")

    def test_failures_outside_time_window(self):
        events = [
            {
                "timestamp": f"2026-11-16T08:{minute:02d}:00Z",
                "event": "login_failure",
                "ip": "203.0.113.15"
            }
            for minute in [0, 10, 20]
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    def test_failures_from_different_ips(self):
        events = [
            {
                "timestamp": "2026-11-16T08:00:00Z",
                "event": "login_failure",
                "ip": ip
            }
            for ip in [
                "192.0.2.101",
                "192.0.2.102",
                "192.0.2.103"
            ]
        ]

        alerts = detect_brute_force(events)
        self.assertEqual(len(alerts), 0)

    def test_successful_login_not_counted(self):
        events = [
            {
                "timestamp": "2026-11-16T08:00:00Z",
                "event": "login_failure",
                "ip": "203.0.113.15"
            },
            {
                "timestamp": "2026-11-16T08:01:00Z",
                "event": "login_success",
                "ip": "203.0.113.15"
            },
            {
                "timestamp": "2026-11-16T08:02:00Z",
                "event": "login_failure",
                "ip": "203.0.113.15"
            }
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    def test_no_duplicate_alerts(self):
        events = [
            {
                "timestamp": f"2026-11-16T08:0{minute}:00Z",
                "event": "login_failure",
                "ip": "203.0.113.15"
            }
            for minute in range(5)
        ] 

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)

if __name__ == "__main__":
    unittest.main()