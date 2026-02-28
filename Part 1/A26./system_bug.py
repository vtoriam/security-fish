'''
System Bug - Mutable Default Argument Bug
Author: Victoria Mok
Student ID: 24790172

A common Python bug where a mutable default argument
(a list) is shared across all function calls instead of being
created each time.
'''

# Bug: list is created once and reused
def add_item(item, cart=[]):  
    cart.append(item)
    
    return cart

# Expected: ['apple'] -> Output: ['apple']
print(add_item('apple'))

# Expected: ['banana']  -> Output: ['apple', 'peach']
print(add_item('peach'))

# Expected: ['cherry']  -> Output: ['apple', 'peach', 'mango']
print(add_item('mango'))
