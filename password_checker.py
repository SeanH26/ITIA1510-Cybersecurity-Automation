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

# Tests and other modules import these rules, so keep them outside the main block.
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True,
}


def check_length(password, policy=policy):
    """Check password length and return whether it meets the strong threshold and a verdict."""
    password_length = len(password)
    min_length = policy["min_length"]
    strong_length = policy["strong_length"]

    # Derive the moderate band from the minimum so changing policy keeps the tiers consistent.
    if password_length < min_length:
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length <= min_length + (strong_length - min_length) // 2:
        length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
    elif password_length < strong_length:
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

    length_ok = password_length >= strong_length

    return length_ok, length_verdict


def check_digit(password):
    """Return whether the password contains a digit."""
    return any(char in "0123456789" for char in password)


def check_username(password, username):
    """Return whether the password differs from the username."""
    return password != username


def check_rotation(rotation_interval, policy=policy):
    """Check the rotation interval against policy and return a verdict."""
    max_rotation_months = policy["max_rotation_months"]

    if rotation_interval > max_rotation_months:
        rotation_verdict = (
            "WARNING -- rotation interval exceeds recommended maximum of "
            + str(max_rotation_months)
            + " months"
        )
    elif rotation_interval >= policy["good_rotation_months"]:
        rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    rotation_ok = rotation_interval <= max_rotation_months

    return rotation_ok, rotation_verdict


def check_breach(password, known_breached):
    """Return whether the password is absent from the known breached list."""
    return password not in known_breached


def audit_password(
    account,
    username,
    password,
    rotation_interval,
    known_breached,
    policy,
    report_number=1,
    batch_size=1,
):
    """Audit one credential and return passed, failed, and critical as 1-or-0 integers."""
    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval

    # Policy centralizes the thresholds so individual checks cannot drift apart.
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    not_breached = (
        check_breach(password, known_breached)
        if policy["check_breach_list"]
        else True
    )

    critical = 0

    if not not_username or not not_breached:
        critical = 1

    digit_ok = has_digit or not policy["require_digit"]
    overall_pass = length_ok and digit_ok and not_username and not_breached and rotation_ok

    print("========================================")
    print("   PASSWORD AUDIT REPORT  (" + str(report_number) + " of " + str(batch_size) + ")")
    print("========================================")
    print("Account:           " + account)
    print("Username:          " + username)
    print("Password length:   " + str(password_length) + " characters")
    print("Length score:      " + str(length_score) + " points")
    print("Rotation interval: " + str(rotation_interval) + " months")
    print("Rotations (3 yr):  " + str(rotation_count))
    print("----------------------------------------")

    print("Length verdict:    " + length_verdict)

    if has_digit:
        print("Digit found:       YES")
    else:
        print("Digit found:       NO")

    if not_username:
        print("Username match:    NO")
    else:
        print("Username match:    YES")

    if not policy["check_breach_list"]:
        print("Breach check:      SKIPPED -- disabled by policy")
    elif not_breached:
        print("Breach check:      PASS -- password not found in breach list")
    else:
        print("Breach check:      CRITICAL -- password found in known breach list")

    print("Rotation verdict:  " + rotation_verdict)
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


if __name__ == "__main__":
    credentials = [
        {"account": "Gmail", "username": "jsmith", "password": "password123", "rotation_interval": 12},
        {"account": "SSH Server", "username": "jsmith", "password": "jsmith", "rotation_interval": 24},
        {"account": "VPN", "username": "jsmith", "password": "Tr0ub4dor&3correct", "rotation_interval": 3},
        {"account": "Company Email", "username": "jsmith", "password": "summer2024!", "rotation_interval": 6},
        {"account": "GitHub", "username": "jsmith", "password": "Blue-Harbor-72-Lantern", "rotation_interval": 6},
    ]

    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": [],
    }

    # Named fields stay correct if a credential gains another value later.
    for cred in credentials:
        summary["total"] += 1
        passed, failed, critical = audit_password(
            cred["account"],
            cred["username"],
            cred["password"],
            cred["rotation_interval"],
            known_breached,
            policy,
            summary["total"],
            len(credentials),
        )

        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        if failed:
            summary["failed_accounts"].append(cred["account"])

        # Count a critical account once even if more than one check flags it.
        if critical:
            summary["critical_accounts"].append(cred["account"])

    print()
    print("========================================")
    print("   BATCH AUDIT SUMMARY")
    print("========================================")
    print("Credentials audited: " + str(summary.get("total", 0)))
    print("Passed:              " + str(summary.get("passed", 0)))
    print("Failed:              " + str(summary.get("failed", 0)))
    print("----------------------------------------")
    print("Failed accounts:     " + ", ".join(summary["failed_accounts"]))
    print("Critical flags:      " + str(summary.get("critical", 0)))
    print("Critical accounts:   " + ", ".join(summary["critical_accounts"]))
    print("----------------------------------------")
    print("NOTE: Credentials and breach list are hardcoded -- file reading coming in Week 07.")
    print("========================================")
