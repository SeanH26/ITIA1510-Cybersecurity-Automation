known_breached = [
    "password",
    "password123",
    "123456",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "sunshine"
]


def check_length(password):
    """Checks password length against NIST SP 800-63B thresholds. Takes a password string. Returns (length_ok: bool, length_verdict: str)."""
    password_length = len(password)

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

    # A for loop walks through each character to look for a digit.
    has_digit = False

    for char in password:
        if char in '0123456789':
            has_digit = True

    return has_digit


def check_username(password, username):
    """Checks whether a password is different from the username. Takes password and username strings. Returns not_username as a Boolean."""

    #The check passes when the password and username are different.
    not_username = password != username

    return not_username


def check_rotation(rotation_interval):
    """Checks the password rotation interval. Takes an integer number of months. Returns (rotation_ok: bool, rotation_verdict: str)."""

    #These conditionals classify the rotation interval based on the number of months.
    if rotation_interval > 12:
        rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
    elif rotation_interval >= 6:
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    rotation_ok = rotation_interval <= 12

    return rotation_ok, rotation_verdict


def check_breach(password, known_breached):
    """Checks whether a password appears in the known breached password list."""

    #The in operator checks the list directly instead of manually walking through it with a for loop.
    not_breached = password not in known_breached

    return not_breached


def audit_password(account, username, password, rotation_interval, known_breached):
    """Audits one password by calling the six checking functions. Returns passed, failed, and critical as 1-or-0 integers."""
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    #Call all of the required checking functions.
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)
    not_breached = check_breach(password, known_breached)

    critical = 0

    #A username match is a critical security issue.
    if not_username is False:
        print("CRITICAL -- password must not match username.")
        critical = 1

    #A breached password is also a critical security issue.
    if not_breached is False:
        critical = 1

    #All required checks must pass for the overall password to pass.
    overall_pass = length_ok and has_digit and not_username and not_breached and rotation_ok

    print("========================================")
    print(" PASSWORD AUDIT REPORT (" + str(count + 1) + " of " + str(batch_size) + ")")
    print("========================================")
    print("Account: " + account)
    print("Username: " + username)
    print("Password length: " + str(password_length) + " characters")
    print("Length score: " + str(length_score) + " points")
    print("Rotation interval: " + str(rotation_interval) + " months")
    print("Rotations (3 yr): " + str(rotation_count))
    print("----------------------------------------")

    print("Length verdict: " + length_verdict)

    if has_digit:
        print("Digit found: YES")
    else:
        print("Digit found: NO")

    if not_username:
        print("Username match: NO")
    else:
        print("Username match: YES")

    if not_breached:
        print("Breach check: PASS -- password not found in breach list")
    else:
        print("Breach check: CRITICAL -- password found in known breach list")

    print("Rotation verdict: " + rotation_verdict)
    print("----------------------------------------")

    if overall_pass:
        print("OVERALL: PASS -- password meets all checked criteria")
        passed = 1
        failed = 0
    else:
        print("OVERALL: FAIL -- see findings above")
        passed = 0
        failed = 1

    print("========================================")

    return passed, failed, critical


if __name__ == '__main__':
    credentials = [
        ["Gmail", "jsmith", "password123", 12],
        ["SSH Server", "jsmith", "jsmith", 24],
        ["VPN", "jsmith", "Tr0ub4dor&3correct", 3],
        ["Company Email", "jsmith", "summer2024!", 6],
        ["GitHub", "jsmith", "Blue-Harbor-72-Lantern", 6],
    ]

    batch_size = len(credentials)
    count = 0

    total_pass = 0
    total_fail = 0
    critical_count = 0

    #These lists store the names of accounts that fail or have critical issues.
    failed_accounts = []
    critical_accounts = []

    #Loop through each credential record instead of asking for passwords one at a time.
    for record in credentials:
        account = record[0]
        username = record[1]
        password = record[2]
        rotation_interval = record[3]

        passed, failed, critical = audit_password(
            account,
            username,
            password,
            rotation_interval,
            known_breached
        )

        total_pass += passed
        total_fail += failed
        critical_count += critical

        if failed:
            failed_accounts.append(account)

        if critical:
            critical_accounts.append(account)

        count += 1

    print()
    print("========================================")
    print(" BATCH AUDIT SUMMARY")
    print("========================================")
    print("Credentials audited: " + str(batch_size))
    print("Passed: " + str(total_pass))
    print("Failed: " + str(total_fail))
    print("----------------------------------------")
    print("Failed accounts: " + ", ".join(failed_accounts))
    print("Critical flags: " + str(len(critical_accounts)))
    print("Critical accounts: " + ", ".join(critical_accounts))
    print("----------------------------------------")
    print("NOTE: Breach list and credentials are hardcoded -- file reading coming in Week 08.")
    print("========================================")
