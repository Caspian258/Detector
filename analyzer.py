import argparse
import csv


def read_failures(data_base):
    # Open the log file in read mode. "with" closes the file automatically
    # when the block ends, even if an error happens in the middle.
    with open(data_base, 'r') as file:
        # This list will hold every line that reports a failed login.
        errors = []
        for line in file:
            # Only the lines containing "Failed password" matter here.
            if 'Failed password' in line:
                # strip() removes the newline character at the end.
                errors.append(line.strip())
    # Return the list so the other functions can work with it.
    return errors


def extract_ip(line):
    # Split the line into words separated by spaces.
    words = line.split()
    # In a line like "... Failed password for root from 5.36.59.76 port ...",
    # the IP is always the word right after "from". The position of "from"
    # changes (for example "invalid user" adds two words), so I look for it
    # with index() instead of using a fixed number.
    position = words.index('from')
    return words[position + 1]


def group_by_ip(lines):
    # Dictionary: key = IP address, value = number of failed attempts.
    ip_attempts = {}
    for line in lines:
        ip = extract_ip(line)
        # If I have already seen this IP, add one to its counter.
        if ip in ip_attempts:
            ip_attempts[ip] += 1
        # If it is the first time, create the key with a counter of 1.
        else:
            ip_attempts[ip] = 1
    return ip_attempts


def extract_time(line):
    # A log line starts like this: "Dec 10 06:55:48 ...".
    # Characters 0-2 are the month, 4-5 the day and 7-14 the time.
    # Slicing [7:15] keeps only the "HH:MM:SS" part.
    time = line[7:15]
    return time


def to_seconds(time_text):
    # Convert a text like "06:55:48" into seconds since midnight, because
    # text cannot be subtracted but numbers can.
    # split(':') gives ['06', '55', '48'].
    time = time_text.split(':')
    # int() turns each piece into a number. One hour has 3600 seconds
    # and one minute has 60.
    hours = int(time[0]) * 3600
    minutes = int(time[1]) * 60
    seconds = int(time[2])
    total_time = hours + minutes + seconds
    return total_time


def times_by_ip(lines):
    # Dictionary: key = IP address, value = list with the moment (in
    # seconds) of each failed attempt from that IP.
    ip_attempts_time = {}
    for line in lines:
        ip = extract_ip(line)
        # Seconds of the day plus the seconds of the full days that passed
        # (86400 seconds per day). Without the day, two failures at the same
        # hour on different days would look close to each other.
        # extract_day is defined below; that is fine because Python looks
        # for it when this function runs, not when it is defined.
        seconds = to_seconds(extract_time(line)) + 86400 * extract_day(line)
        # If the IP already has a list, add the new moment to it.
        if ip in ip_attempts_time:
            ip_attempts_time[ip].append(seconds)
        # If not, create the list with this first moment.
        else:
            ip_attempts_time[ip] = [seconds]
    return ip_attempts_time


def is_suspicious(times):
    # Rule: an IP is suspicious if it has 3 failures within 5 minutes
    # (300 seconds). sorted() makes a new ordered list, so the original
    # list is not modified.
    sorted_times = sorted(times)
    # I compare each failure with the one two places ahead. If those two
    # are 300 seconds or less apart, there are 3 failures in that window.
    # The "- 2" keeps position + 2 inside the list. With fewer than 3
    # failures the range is empty and the function returns False.
    for position in range(len(times) - 2):
        difference = sorted_times[position + 2] - sorted_times[position]
        if difference <= 300:
            return True
    return False


def show_suspicious(times_dict):
    # Go through every IP and print only the suspicious ones.
    for ip in times_dict:
        times = times_dict[ip]
        if is_suspicious(times):
            print(ip)


def extract_day(line):
    # The log has no year, so I count days from December 1st.
    # split() also handles the double space in lines like "Jan  1".
    words = line.split()
    month = words[0]
    day = int(words[1])
    # December has 31 days, so January 1st becomes day 32, and so on.
    if month == 'Jan':
        day = 31 + day
    return day


def write_csv(path, ip_failures, times_dict):
    header = ['IP', 'Failures', 'Suspicious']
    # newline='' avoids blank lines between rows (the csv module adds its
    # own line endings) and utf-8 keeps the file readable on any system.
    with open(path, mode="w", encoding="utf-8", newline="") as f_exit:
        writer = csv.writer(f_exit)
        writer.writerow(header)
        # items() gives each IP together with its number of failures.
        for ip, failures in ip_failures.items():
            # Ask is_suspicious about this IP using its list of moments.
            suspicious = is_suspicious(times_dict[ip])
            writer.writerow([ip, failures, suspicious])


# Command line: the log file path is required, for example
# "python analyzer.py SSH.log". argparse also builds the -h help message.
parser = argparse.ArgumentParser(
    description='SSH log analyzer that detects suspicious IP addresses'
)

parser.add_argument('log_path', help='Path to the SSH log file to analyze')

args = parser.parse_args()

# Main flow: read the failed lines, group their moments by IP, print the
# suspicious IPs, then print how many different IPs there are in total.
detected_errors = times_by_ip(read_failures(args.log_path))

show_suspicious(detected_errors)

print(len(detected_errors))

# Export the full report (IP, failures, suspicious) to a CSV file.
write_csv(
    'report.csv',
    group_by_ip(read_failures(args.log_path)),
    detected_errors
)
