import hashlib
import requests
import getpass

# converts string into bytes to generate it into SHA-1 hash
def get_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest().upper()

# checks password in known breaches
def check_breach(password):
    sha1 = get_sha1(password)
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)

# error catching
    if res.status_code != 200:
        print("Error fetching data")
        return False

# compares hashes
    hashes = (line.split(":") for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

def check_strength(password):
    length = len(password) >= 8
    upper = any(c.isupper() for c in password)
    lower = any(c.islower() for c in password)
    digit = any(c.isdigit() for c in password)
    symbol = any(not c.isalnum() for c in password)

    score = sum([length, upper, lower, digit, symbol])

    if score <= 2:
        return "Weak"
    elif score == 3 or score == 4:
        return "Moderate"
    else:
        return "Strong"

def main():
    password = getpass.getpass("Enter password: ")

    strength = check_strength(password)
    breach_count = check_breach(password)

    print(f"\nStrength: {strength}")

    if breach_count:
        print(f"Found in {breach_count} breaches!")
    else:
        print("Not found in known breaches")

if __name__ == "__main__":
    main()