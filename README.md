# SSH Log Analyzer (Detector)

A command-line tool in Python that reads an SSH authentication log, counts
the failed password attempts per IP address and flags the IPs that look like
brute-force attacks.

## What it is

When a server is exposed to the internet, bots try thousands of passwords
against it. This tool finds those bots in a log file: an IP is marked as
**suspicious** when it has **3 or more `Failed password` events within
5 minutes**.

## Demo

Running the tool prints the suspicious IPs, then the number of distinct IPs
seen in the log, and writes a CSV report:

```
$ python analyzer.py SSH.log
112.95.230.3
123.235.32.19
...
1008
```

First rows of `report.csv`:

```
IP,Failures,Suspicious
173.234.31.186,2,False
52.80.34.196,143,False
```

## How to run it

Requirements: Python 3 (only the standard library is used).

1. Get the OpenSSH log from the [Loghub](https://github.com/logpai/loghub)
   dataset and save it as `SSH.log` in the project folder. The log is not
   included in this repository.
2. Run:

```
python analyzer.py SSH.log
```

Use `python analyzer.py -h` to see the help message.

Output:

- The suspicious IPs, one per line, followed by the total number of
  distinct IPs.
- `report.csv`, with one row per IP and the columns `IP`, `Failures` and
  `Suspicious`.

## How it works

1. `read_failures` keeps only the lines that contain `Failed password`.
2. `extract_ip`, `extract_time` and `extract_day` pull the IP, the time and
   the day out of each line.
3. `group_by_ip` counts the failures per IP.
4. `times_by_ip` builds, for each IP, the list of moments (in seconds) of
   its failures. Moments include the day, so failures from different days
   are never mixed.
5. `is_suspicious` sorts those moments and checks if any 3 consecutive
   failures happened within 300 seconds.
6. `show_suspicious` prints the flagged IPs and `write_csv` exports the
   full report.

## Results

Analysis of the Loghub OpenSSH log, which covers December 10 to January 7:

| Metric | Value |
| --- | --- |
| Failed password events | 197,587 |
| Distinct IPs | 1,008 |
| Suspicious IPs (3 failures in 5 min) | 481 |

The first version of the rule compared only the time of day and flagged 488
IPs. Adding the day removed 7 false positives, so the final number is 481.

### Limitations

- The log lines have no year. The tool counts days from December 1st and
  assumes the log only crosses from December to January once.
- The rule is fixed (3 failures, 300 seconds). Slow attacks that spread
  their attempts over hours are not detected.
- Only `Failed password` lines are analyzed. Other kinds of failures, such
  as `Invalid user` lines without a password attempt, are ignored.

## What I learned and what I would improve

- Working with the time of day alone was not enough: failures from
  different days at the same hour looked close to each other. Including the
  day made the detection more reliable.
- I verified the code step by step: the sum of failures per IP matches the
  197,587 lines counted directly.
- Next improvements: choose the thresholds with command-line options, also
  compare failures against later `Accepted` logins from the same IP, and
  add automated tests.
