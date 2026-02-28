'''
Vulnerability - Path Traversal Demo Fixed (CWE-22)
Author: Victoria Mok
Student ID: 24790172

When prompted enter, run the following:  ../secret.txt
Access will be denied.
'''

import os

BASE_DIR = os.path.realpath('served_files')
os.makedirs(BASE_DIR, exist_ok=True)

# Create a public file inside the served directory
with open(os.path.join(BASE_DIR, 'hello.txt'), 'w') as f:
    f.write('Hello! This is a public file.')

# Create a sensitive file outside the served directory
with open('secret.txt', 'w') as f:
    f.write('password = topSecret321')

# Simulate a user request
filename = input('Enter filename: ')
full_path = os.path.realpath(os.path.join(BASE_DIR, filename))

# Fixed: check the resolved path is still inside BASE_DIR
if not full_path.startswith(BASE_DIR):
    print('Access denied.')
else:
    try:
        with open(full_path, 'r') as f:
            print(f.read())
    except FileNotFoundError:
        print('File not found.')
