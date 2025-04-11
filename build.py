import argparse
import re

def scan_code(filename):
    # Define vulnerability patterns
    buffer_overflow_patterns = [
        {
            'name': 'strcpy usage',
            'regex': re.compile(r'\bstrcpy\s*\('),
            'description': 'Use of strcpy can lead to buffer overflow. Use strncpy with proper size checks.'
        },
        {
            'name': 'gets usage',
            'regex': re.compile(r'\bgets\s*\('),
            'description': 'gets is inherently unsafe and can cause buffer overflow. Use fgets instead.'
        },
        {
            'name': 'sprintf usage',
            'regex': re.compile(r'\bsprintf\s*\('),
            'description': 'sprintf can cause buffer overflow. Use snprintf instead.'
        },
        {
            'name': 'scanf with %s without width',
            'regex': re.compile(r'\bscanf\s*\([^"]*".*(?<!\d)%s.*"'),
            'description': 'Using %s in scanf without field width can overflow buffer. Use %<width>s (e.g., %255s).'
        }
    ]

    stack_overflow_patterns = [
        {
            'name': 'Large stack-allocated array',
            'regex': re.compile(r'\b\w+\s+\w+\s*\[\s*(\d+)\s*\]'),
            'description': 'Large stack allocation may cause stack overflow. Consider dynamic allocation.',
            'threshold': 1024  # 1KB threshold
        },
        {
            'name': 'Variable-length array (VLA)',
            'regex': re.compile(r'\b\w+\s+\w+\s*\[\s*(\w+)\s*\]'),
            'description': 'Variable-length arrays can cause stack overflow if size is large. Use dynamic allocation.'
        }
    ]

    heap_overflow_patterns = [
        {
            'name': 'malloc followed by unsafe copy',
            'regex': re.compile(r'\bmalloc\s*\(.*\)'),
            'description': 'Heap-allocated buffer may be overflowed due to unsafe operations. Ensure bounds checking.',
            'trigger_functions': re.compile(r'\b(strcpy|strcat|memcpy)\s*\(')
        }
    ]

    vulnerabilities = []

    with open(filename, 'r') as file:
        lines = file.readlines()

    # Check for Buffer Overflow vulnerabilities
    for line_num, line in enumerate(lines, 1):
        for pattern in buffer_overflow_patterns:
            if pattern['regex'].search(line):
                vulnerabilities.append({
                    'line': line_num,
                    'type': 'Buffer Overflow',
                    'name': pattern['name'],
                    'description': pattern['description']
                })

    # Check for Stack Overflow vulnerabilities
    for line_num, line in enumerate(lines, 1):
        for pattern in stack_overflow_patterns:
            match = pattern['regex'].search(line)
            if match:
                if pattern.get('threshold'):
                    size = int(match.group(1))
                    if size > pattern['threshold']:
                        vulnerabilities.append({
                            'line': line_num,
                            'type': 'Stack Overflow',
                            'name': pattern['name'],
                            'description': pattern['description']
                        })
                else:
                    vulnerabilities.append({
                        'line': line_num,
                        'type': 'Stack Overflow',
                        'name': pattern['name'],
                        'description': pattern['description']
                    })

    # Check for Heap Overflow vulnerabilities
    for line_num, line in enumerate(lines, 1):
        if any(malloc_pattern['regex'].search(line) for malloc_pattern in heap_overflow_patterns):
            # Check subsequent lines for trigger functions
            for offset in range(1, 6):  # Check next 5 lines
                if line_num + offset - 1 >= len(lines):
                    break
                next_line = lines[line_num + offset - 1]
                if heap_overflow_patterns[0]['trigger_functions'].search(next_line):
                    vulnerabilities.append({
                        'line': line_num,
                        'type': 'Heap Overflow',
                        'name': 'malloc followed by unsafe copy',
                        'description': heap_overflow_patterns[0]['description']
                    })
                    break  # Avoid multiple reports for the same malloc

    return vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='Scan C/C++ code for common vulnerabilities.')
    parser.add_argument('file', help='Path to the C/C++ file to scan')
    args = parser.parse_args()

    vulnerabilities = scan_code(args.file)

    if not vulnerabilities:
        print("No vulnerabilities found.")
        return

    print("=== Vulnerability Scan Report ===")
    print(f"Scanned File: {args.file}")
    print("================================\n")

    for vuln in vulnerabilities:
        print(f"[Line {vuln['line']}] {vuln['type']}: {vuln['name']}")
        print(f"   - Description: {vuln['description']}\n")

if __name__ == '__main__':
    main()