def check_length(password):
    """Checks password length against NIST SP 800-63B thresholds. Takes a password string. Returns (length_ok: bool, length_verdict: str)."""
    password_length = len(password)

    # Classify the password based on its length and provide a verdict according to NIST SP 800-63B recommendations.
    if password_length < 8:
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length <= 11:
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
    elif password_length <= 14:
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

    length_ok = password_length >= 15

    return length_ok, length_verdict

def check_digit(password):
    """Checks whether a password contains at least one digit. Takes a password string. Returns has_digit as a Boolean."""
    # Loop through each character looking for a digit.
    has_digit = False

    for char in password:
        if char in '0123456789':
            has_digit = True

    return has_digit


def check_username(password, username):
    """Checks whether a password is different from the username. Takes password and username strings. Returns not_username as a Boolean."""
    # The check passes when the password and username are different.
    not_username = password != username

    return not_username


def check_rotation(rotation_interval):
    """Checks the password rotation interval. Takes an integer number of months. Returns (rotation_ok: bool, rotation_verdict: str)."""
    #These conditionals classify the rotation interval based on the number of months
    if rotation_interval > 12:
        rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    rotation_ok = rotation_interval <= 12

    return rotation_ok, rotation_verdict


def audit_password(account, username, password, rotation_interval):
    """Audits one password by calling the four checking functions. Takes account, username, password, and rotation interval. Returns (passed, failed, critical) as 1-or-0 integers."""
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    # Call the four required checking functions.
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)

    critical = 0

    # Give a critical warning when the password matches the username.
    if not_username is False:
        print("CRITICAL -- password must not match username.")
        critical = 1

    # The overall Boolean is true only when the password is long enough, has a digit, the rotation is ok, and is not the username.
    overall_pass = length_ok and has_digit and not_username and rotation_ok

    # Display the formatted password audit report
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

    # This conditional displays YES when the password contains at least one digit.
    if has_digit:
        print("Digit found: YES")
    else:
        print("Digit found: NO")

    # This conditional displays whether or not the password matches the username.
    if not_username:
        print("Username match: NO")
    else:
        print("Username match: YES")

    print("Rotation verdict: " + rotation_verdict)
    print("----------------------------------------")

    # This conditional displays PASS only when all of the required Boolean checks are true.
    if overall_pass:
        print("OVERALL: PASS -- password meets all checked criteria")
        passed = 1
        failed = 0
    else:
        print("OVERALL: FAIL -- see findings above")
        passed = 0
        failed = 1

    print("========================================")
    # Increases count by 1 to move to the next password in the batch.

    return passed, failed, critical

if __name__ == '__main__':
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

        # Collect and convert the rotation interval to an integer.
        rotation_interval = input("Rotation interval (months): ")
        rotation_interval = int(rotation_interval)

        #Audit the pasword and recieve the three counter values
        passed, failed, critical = audit_password(
            account,
            username,
            password,
            rotation_interval
        )

        # Add this paswords results to the batch totals.
        total_pass += passed
        total_fail += failed
        critical_count += critical

        #Moves to the next password in the batch.
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