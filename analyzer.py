example = ['Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2', 
           'Dec 10 07:13:43 LabSZ sshd[24227]: Failed password for root from 5.36.59.76 port 42393 ssh2']

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

failed_attempts = len(read_failures('SSH.log'))

ip_failures = group_by_ip(read_failures('SSH.log'))

print(f'There are: {failed_attempts} failed attempts')
print(f'There are: {sum(ip_failures.values())} failed attempts')

for line in example:
    print(extract_time(line))