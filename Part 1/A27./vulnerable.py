'''
Vulnerability - Path Traversal Demo (CWE-22)
Author: Victoria Mok
Student ID: 24790172

When prompted enter, run the following:  ../secret.txt
This will read a file outside the intended 'served_files' directory.
'''

import os

BASE_DIR = 'served_files'
os.makedirs(BASE_DIR, exist_ok=True)

# Create a public file inside the served directory
with open(os.path.join(BASE_DIR, 'hello.txt'), 'w') as outfile:
    outfile.write('Hello World!')

# Create a sensitive file outside the served directory
with open('secret.txt', 'w') as outfile:
    outfile.write('password = topSecret321')

# Simulate a user request, system vulnerability created as there is no validation
filename = input('Enter filename: ')
path = os.path.join(BASE_DIR, filename)

try:
    with open(path, 'r') as infile:
        print(infile.read())
except FileNotFoundError:
    print('File not found.')
