#Sets the batch size to 3 so the program audits 3 passwords each run before displaying the batch summary.
batch_size = 3
count = 0
#These counters are initialized before the while loop to keep track of the number of passwords that pass, fail, and have critical issues.
total_pass = 0
total_fail = 0
critical_count = 0

#Uses a while loop too iterate through the batch of passwords, collecting imput, and evaluating each password against the secutity criteria specified in the program.
while count < batch_size:
    #Collects the name so the audit report can identify the account being checked.
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

    #Classify the password based on its length and provide a verdict according to NIST SP 800-63B reccomendations.
    if password_length < 8:
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length <= 11:
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
    elif password_length <= 14:
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

    #This loop checks each character in the password for a digit. It us better than the week 02 verson because it replaces the long chain of or operators
    #with a simple loop.
    has_digit = False
    for char in password:
        if char in '0123456789':
            has_digit = True

    #This comparison checks whether the password is differnet from the username.
    not_username = password != username

    #This conditional gives a critical warning when the password matches the username.
    if not_username is False:
        print("CRITICAL -- password must not match username.")
        critical_count += 1

    #These conditionals classify the rotation interval based on the number of months
    if rotation_interval > 12:
        rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    length_ok = password_length >= 15

    #The overall Boolean is true only when the password is long enough, has a digit, and is not the username.
    overall_pass = length_ok and has_digit and not_username

    #Display the formatted password audit report
    print("========================================")
    print(" PASSWORD AUDIT REPORT  (" + str(count + 1) + " of " + str(batch_size) + ")")
    print("========================================")
    print("Account: " + account)
    print("Username: " + username)
    print("Password length: " + str(password_length) + " characters")
    print("Length score: " + str(length_score) + " points")
    print("Rotation interval: " + str(rotation_interval) + " months")
    print("Rotations (3 yr): " + str(rotation_count))
    print("----------------------------------------")

    print("Length verdict: " + length_verdict)

    #This conditional displays YES when the password contains at lestleast one digit.
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

    #This conditional displays PASS only when all of the required Boolean checks are true.
    if overall_pass:
        print("OVERALL: PASS -- password meets all checked criteria")
        total_pass += 1
    else:
        print("OVERALL: FAIL -- see findings above")
        total_fail += 1

    print("========================================")
    #Increases count by 1 to move to the next password in the batch.
    count += 1
#Prints the batch summary after all passwords have been audited.
print()
print("========================================")
print("   BATCH AUDIT SUMMARY")
print("========================================")
print("Passwords audited: " + str(batch_size))
print("Passed:            " + str(total_pass))
print("Failed:            " + str(total_fail))
print("Critical flags:    " + str(critical_count))
print("----------------------------------------")
print("NOTE: Input is still hardcoded -- file reading coming in Week 08.")
print("========================================")