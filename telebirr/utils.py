from random import choice

def generate_unique(data, length):
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    while 1:
        random_char = "".join(choice(letters) for i in range(length))
        if random_char not in data:
            break
    return random_char
