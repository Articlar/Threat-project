import string
def hash_type(hash_string):
    for char in hash_string:
        if char not in string.hexdigits:
            return "Not a hash"
        
    if (len(hash_string) == 32):
        return "MD5"
    elif (len(hash_string) == 40):
        return "SHA1"
    elif (len(hash_string) == 64):
        return "SHA256"
    else:
        return "Not a hash"