def checkDomain(domain):
    '''
    checkDomain takes a string value 'domain' and checks its domain format. 
    -1 means invalid domain
    0 means success (it is a valid domain)
    '''
    split_domains = domain.split(".")
    if "" in split_domains:
        return -1 # Invalid domain
    elif len(split_domains) < 2:
        return -1

    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
    for part in split_domains:

        # Check for invalid characters
        for char in part:
            if char not in allowed_chars:
                return -1
        # Check for leading/trailing hyphens
        if part[0] == '-' or part[-1] == '-':
            return -1

    return 0