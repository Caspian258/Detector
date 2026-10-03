examples = [
    'Dec 10 06:55:48 LabSZ sshd[24200]: test',
    'Jan  1 10:00:00 LabSZ sshd[24200]: test',
    'Jan  7 10:00:00 LabSZ sshd[24200]: test'
]


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
        seconds = to_seconds(extract_time(line))

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


detected_errors = times_by_ip(read_failures('SSH.log'))

show_suspicious(detected_errors)

print(len(detected_errors))

for line in examples:
    day = extract_day(line)
    print(day)