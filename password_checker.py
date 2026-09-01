#Collects the name so the audit report cand identify the account being checked.
account = input("Account or system: ")

#Collects the username to make sure the password does not match it.
username = input("Username: ")

#Collect the password to so the program can check if it meets the security criteria specififed below.
password = input("Password: ")

#Rotation intiger is gathered and used to evaluate the password changing policy.
rotation_interval = input("Rotation interval (months): ")
rotation_interval = int(rotation_interval)

password_length = len(password)
length_score = password_length * 10
rotation_count = 36 // rotation_interval

if password_length < 8:
    length_verdict = "WEAK -- does not meet minimum length requirements"
elif password_length <= 11:
    length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
elif password_length <= 14:
    length_verdict = "GOOD -- acceptable length for most systems"
else:
    length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

has_digit = '0' in password or '1' in password or '2' in password or '3' in password or '4' in password or '5' in password or '6' in password or '7' in password or '8' in password or '9' in password

#This comparison checks whether the password is differnet from the username.
not_username = password != username

#This conditional gives a critical warning when the password matches the username.
if not_username is False:
    print("CRITICAL -- password must not match username.")

#These conditionals classify the rotation interval based on the number of months
if rotation_interval > 12:
    rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
elif rotation_interval >= 6:
    rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
else:
    rotation_verdict = "EXCELLENT -- frequent rotation policy detected"


length_ok = password_length >= 15

#The overall Booleazn is true onlt when the password is long enough,has a digit< and is not the username.
overall_pass = length_ok and has_digit and not_username

#Display the formatted password audit report
print("========================================")
print(" PASSWORD AUDIT REPORT")
print("========================================")
print("Account: " + account)
print("Username: " + username)
print("Password length: " + str(password_length) + " characters")
print("Length score: " + str(length_score) + " points")
print("Rotation interval: " + str(rotation_interval) + " months")
print("Rotations (3 yr): " + str(rotation_count))
print("----------------------------------------")

print("Length verdict: " + length_verdict)

#This conditional displays YES when the password contains at lestleast one digi.
if has_digit:
    print("Digit found: YES")
else:
    print("Digit found: NO")

#This conditional displays wherther the password mattches the username.
if not_username:
    print("Username match: NO")
else:
    print("Username match: YES")

print("Rotation verdict: " + rotation_verdict)
print("----------------------------------------")

#This conditional displays PASS only whgen all of the required Voolean checks are true.
if overall_pass:
    print("OVERALL: PASS -- password meets all checked criteria")
else:
    print("OVERALL: FAIL -- see findings above")

print("========================================")