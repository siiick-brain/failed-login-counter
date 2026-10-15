import contextlib
import io
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import count_failed_logins


class CountFailedLoginsTests(unittest.TestCase):
    def test_counts_failed_password_lines_by_validated_source_ip(self):
        """Count valid addresses and group missing or invalid ones as unknown."""
        lines = [
            "Failed password for admin from 203.0.113.5 port 52144 ssh2",
            "Failed password for root from 203.0.113.5 port 52150 ssh2",
            "Failed password for user from 999.1.1.1 port 52151 ssh2",
            "Failed password for user without an address",
            "failed password for user from 198.51.100.7 port 52152 ssh2",
            "Accepted password for user from 192.0.2.9 port 52153 ssh2",
        ]

        self.assertEqual(
            count_failed_logins.count_failed_logins(lines),
            Counter({"203.0.113.5": 2, "unknown": 2}),
        )

    def test_cli_prints_counts_in_descending_count_then_ip_order(self):
        """Print the most frequent addresses first, with numeric IP ordering."""
        lines = [
            "Oct 15 10:21:03 server sshd[1]: Failed password for user from 203.0.113.5 port 1 ssh2",
            "Oct 15 10:21:04 server sshd[2]: Failed password for user from 203.0.113.5 port 2 ssh2",
            "Oct 15 10:21:05 server sshd[3]: Failed password for user from 192.0.2.10 port 3 ssh2",
            "Oct 15 10:21:06 server sshd[4]: Failed password for user from 192.0.2.2 port 4 ssh2",
            "Oct 15 10:21:07 server sshd[5]: Failed password for user from 999.1.1.1 port 5 ssh2",
        ]

        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "sample-auth.log"
            log_path.write_text("\n".join(lines), encoding="utf-8")
            output = io.StringIO()
            with patch("sys.argv", ["count_failed_logins.py", str(log_path)]):
                with contextlib.redirect_stdout(output):
                    exit_code = count_failed_logins.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            output.getvalue(),
            "203.0.113.5: 2\n192.0.2.2: 1\n192.0.2.10: 1\nunknown: 1\n",
        )

    def test_cli_marks_ips_at_or_above_the_threshold_as_suspicious(self):
        """Mark each address whose count meets the requested threshold."""
        lines = [
            "Oct 15 10:21:03 server sshd[1]: Failed password for user from 203.0.113.5 port 1 ssh2",
            "Oct 15 10:21:04 server sshd[2]: Failed password for user from 203.0.113.5 port 2 ssh2",
            "Oct 15 10:21:05 server sshd[3]: Failed password for user from 203.0.113.5 port 3 ssh2",
            "Oct 15 10:21:06 server sshd[4]: Failed password for user from 192.0.2.2 port 4 ssh2",
            "Oct 15 10:21:07 server sshd[5]: Failed password for user from 192.0.2.2 port 5 ssh2",
            "Oct 15 10:21:08 server sshd[6]: Failed password for user from 198.51.100.7 port 6 ssh2",
        ]

        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "sample-auth.log"
            log_path.write_text("\n".join(lines), encoding="utf-8")
            output = io.StringIO()
            with patch(
                "sys.argv",
                ["count_failed_logins.py", "--threshold", "2", str(log_path)],
            ):
                with contextlib.redirect_stdout(output):
                    exit_code = count_failed_logins.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            output.getvalue(),
            "203.0.113.5: 3 SUSPICIOUS\n192.0.2.2: 2 SUSPICIOUS\n198.51.100.7: 1\n",
        )

    def test_cli_reports_when_no_failed_logins_are_found(self):
        """Print a clear message when the log contains no failed passwords."""
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "sample-auth.log"
            log_path.write_text(
                "Oct 15 10:21:03 server sshd[1]: Accepted password for user\n",
                encoding="utf-8",
            )
            output = io.StringIO()
            with patch("sys.argv", ["count_failed_logins.py", str(log_path)]):
                with contextlib.redirect_stdout(output):
                    exit_code = count_failed_logins.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(output.getvalue(), "No failed logins found.\n")

    def test_cli_reports_file_read_errors_and_returns_failure(self):
        """Report unreadable log files on stderr and return a failure code."""
        error_output = io.StringIO()
        with (
            patch("sys.argv", ["count_failed_logins.py", "missing-auth.log"]),
            patch.object(Path, "open", side_effect=OSError("file not found")),
        ):
            with contextlib.redirect_stderr(error_output):
                exit_code = count_failed_logins.main()

        self.assertEqual(exit_code, 1)
        self.assertIn("Error reading missing-auth.log:", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
