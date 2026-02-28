'''
System Bug- Mutable Default Argument Bug Fixed
Author: Victoria Mok
Student ID: 24790172

Uses None as the default argument and creates a new list
inside the function each time it is called.
'''

# Fix: use None as default, and creates a new list each time
def add_item(item, cart=None):  
    if cart is None:
        cart = []
    cart.append(item)
    return cart

# Output: ['apple']
print(add_item('apple'))

# Output: ['peach']
print(add_item('peach'))

# Output: ['mango]
print(add_item('mango'))
