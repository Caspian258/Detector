import argparse
import csv

def read_failures(data_base):
    with open(data_base, 'r') as file:
        errors = []
        for line in file:
            if 'Failed password' in line:
                errors.append(line.strip())
        return errors

def extract_ip(line):
    words = line.split()
    position = words.index('from')
    return words[position + 1]

def group_by_ip(lines):
    ip_attempts = {}
    for line in lines:
        ip = extract_ip(line)

        if ip in ip_attempts:
            ip_attempts[ip] += 1
        else:
            ip_attempts[ip] = 1

    return ip_attempts

def extract_time(line):
    time = line[7:15]
    return time

def to_seconds(time_text):
    time = time_text.split(':')

    hours = int(time[0]) * 3600
    minutes = int(time[1]) * 60
    seconds = int(time[2])

    total_time = hours + minutes + seconds

    return total_time

def times_by_ip(lines):
    ip_attempts_time = {}
    for line in lines:
        ip = extract_ip(line)
        seconds = to_seconds(extract_time(line)) + 86400 * extract_day(line)

        if ip in ip_attempts_time:
            ip_attempts_time[ip].append(seconds)
            
        else:
            ip_attempts_time[ip] = [seconds]
            
    return ip_attempts_time

def is_suspicious(times):
    sorted_times = sorted(times)
    for position in range(len(times) - 2):
        difference = sorted_times[position + 2] - sorted_times[position]

        if difference <= 300:
            return True
    return False

def show_suspicious(times_dict):
    for ip in times_dict:
        times = times_dict[ip]

        if is_suspicious(times):
            print(ip)

def extract_day(line):
    words = line.split()
    month = words[0]
    day = int(words[1])
    if month == 'Jan':
        day = 31 + day
    
    return day

def write_csv(path, ip_failures, times_dict):
    header = ['IP', 'Failures', 'Suspicious']
    with open(path, mode="w", encoding="utf-8", newline="") as f_exit:
        writer = csv.writer(f_exit)
        writer.writerow(header)

        for ip, failures in ip_failures.items():
            suspicious = is_suspicious(times_dict[ip])
            writer.writerow([ip, failures, suspicious])


parser = argparse.ArgumentParser(description='SSH log analyzer that detects suspicious IP addresses')

parser.add_argument('log_path', help='Path to the SSH log file to analyze')

args = parser.parse_args()

detected_errors = times_by_ip(read_failures(args.log_path))

show_suspicious(detected_errors)

print(len(detected_errors))

write_csv('report.csv', group_by_ip(read_failures(args.log_path)), detected_errors)