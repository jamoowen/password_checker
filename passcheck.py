# checks if a given password has been hacked before

import requests
import hashlib
import sys



# runs the pwnedpasswords api and returns the hashed passwords along with the count of 
# how many times they were leaked
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError (f'Error, fetching: {res.status_code}, check api and run again')
    return res

# splits the response into the hashed passwords and the amount leaked
def amount_leaked(response, hash_to_check):
    hashes = (line.split(':') for line in response.text.splitlines()) 
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# hashes the password through sha1 and runs previous functions
# returns the amount the given password was leaked
def check_pwned(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5, tail = sha1pass[:5], sha1pass[5:]
    response = request_api_data(first_5)
    
    return amount_leaked(response, tail)
 
#  checks passwords given in command line.
# prints the count of the leaked pasword
def main(args):
    for password in args:
        count = check_pwned(password)
        if count:
            print(f'{password} was found {count} times. Change it bro.')
        else:
            print(f'{password} not found, good password bud.')
    return 'done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

