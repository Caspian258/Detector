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

failed_attempts = len(read_failures('SSH.log'))

ip_failures = group_by_ip(read_failures('SSH.log'))

print(f'There are: {failed_attempts} failed attempts')
print(f'There are: {sum(ip_failures.values())} failed attempts')