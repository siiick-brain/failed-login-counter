# Failed Login Counter

A small Python command-line tool that counts failed OpenSSH password logins by
source IPv4 address. It reads a log file and reports the results; it does not
monitor a computer in real time or block login attempts.

## Requirements

- Python 3.10 or later
- An OpenSSH authentication log, or a text file with lines in the same format

No third-party packages are needed.

## Run it

Pass the path to the log file as an argument:

```powershell
python .\count_failed_logins.py .\sample-auth.log
```

On Linux, for example:

```bash
python3 count_failed_logins.py /var/log/auth.log
```

Depending on the Linux distribution, the SSH log may instead be at
`/var/log/secure`. You may need permission to read the log.

To mark addresses with two or more failed attempts:

```powershell
python .\count_failed_logins.py --threshold 2 .\sample-auth.log
```

The threshold is inclusive: an address is marked `SUSPICIOUS` when its count
is equal to or greater than the threshold.

## What it counts

The tool counts lines containing the case-sensitive text `Failed password`.
Valid source IPv4 addresses are counted separately. If a matching line has no
valid IPv4 address, it is counted under `unknown`. Other lines, including
successful logins, are ignored.

Results are printed from highest count to lowest. Addresses with equal counts
are sorted numerically, and `unknown` appears after valid addresses with the
same count. If there are no failed logins, the tool prints
`No failed logins found.` An unreadable file produces an error on stderr and a
failure exit code.

## Example

The included `sample-auth.log` contains fictional example entries. Run:

```powershell
python .\count_failed_logins.py .\sample-auth.log
```

Expected output:

```text
203.0.113.5: 2
192.0.2.10: 1
```

The IP addresses in the sample are reserved for documentation and are not real
login sources.

## Run the tests

```powershell
python -m unittest -v
```

## Privacy

Real authentication logs can contain usernames, IP addresses, and other
potentially sensitive details. Keep them private and use the included sample
when you only want to try the program.
