import json

#Tests and other modules import these rules
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True,
}


def load_breached(filepath):
    """Read the breached password file. Returns a list of password strings."""
    known_breached = []

    # with closes the file automatically, even if an error occurs, unlike manual f.close().
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Skip blank lines so they are not added as empty passwords.
            if line != "":
                known_breached.append(line)

    return known_breached


def load_credentials(filepath):
    """Read account credentials from a comma-separated text file."""
    credentials = []

    # The with statement ensures the file is closed automatically.
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Blank lines are skipped so they do not create invalid account records.
            if line == "":
                continue

            fields = line.split(",")

            credentials.append({
                "account": fields[0],
                "username": fields[1],
                "password": fields[2],
                "rotation_interval": int(fields[3]),
            })

    return credentials


def write_report(report_lines, filepath):
    """Write each string in report_lines to the file as one line."""
    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")

def save_summary(summary, filepath):
    """Save the audit summary dictionary to a JSON file."""

    # Using with automatically closes the file when finished.
    with open(filepath, "w") as f:
        # indent=2 makes the JSON file easier to read.
        json.dump(summary, f, indent=2)

def load_summary(filepath):
    """Read the JSON summary file and return its dictionary."""

    # Using with automatically closes the file after reading.
    with open(filepath, "r") as f:
        return json.load(f)

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
    report_lines=None,
):
    """Audit one credential and return passed, failed, and critical as 1-or-0 integers."""
    if report_lines is None:
        report_lines = []

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

    report_lines.append("========================================")
    report_lines.append("   PASSWORD AUDIT REPORT  (" + str(report_number) + " of " + str(batch_size) + ")")
    report_lines.append("========================================")
    report_lines.append("Account:           " + account)
    report_lines.append("Username:          " + username)
    report_lines.append("Password length:   " + str(password_length) + " characters")
    report_lines.append("Length score:      " + str(length_score) + " points")
    report_lines.append("Rotation interval: " + str(rotation_interval) + " months")
    report_lines.append("Rotations (3 yr):  " + str(rotation_count))
    report_lines.append("----------------------------------------")

    report_lines.append("Length verdict:    " + length_verdict)

    if has_digit:
        report_lines.append("Digit found:       YES")
    else:
        report_lines.append("Digit found:       NO")

    if not_username:
        report_lines.append("Username match:    NO")
    else:
        report_lines.append("Username match:    YES")

    if not policy["check_breach_list"]:
        report_lines.append("Breach check:      SKIPPED -- disabled by policy")
    elif not_breached:
        report_lines.append("Breach check:      PASS -- password not found in breach list")
    else:
        report_lines.append("Breach check:      CRITICAL -- password found in known breach list")

    report_lines.append("Rotation verdict:  " + rotation_verdict)
    report_lines.append("----------------------------------------")

    if overall_pass:
        report_lines.append("OVERALL: PASS -- password meets all checked criteria")
        passed = 1
        failed = 0
    else:
        report_lines.append("OVERALL: FAIL -- see findings above")
        passed = 0
        failed = 1

    report_lines.append("========================================")

    return passed, failed, critical


if __name__ == "__main__":
    # Load input data from files instead of keeping credentials in the Python code.
    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")
    report_lines = []

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
            report_lines,
        )

        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        if failed:
            summary["failed_accounts"].append(cred["account"])

        # Count a critical account once even if more than one check flags it.
        if critical:
            summary["critical_accounts"].append(cred["account"])

    report_lines.append("")
    report_lines.append("========================================")
    report_lines.append("   BATCH AUDIT SUMMARY")
    report_lines.append("========================================")
    report_lines.append("Credentials audited: " + str(summary.get("total", 0)))
    report_lines.append("Passed:              " + str(summary.get("passed", 0)))
    report_lines.append("Failed:              " + str(summary.get("failed", 0)))
    report_lines.append("----------------------------------------")
    report_lines.append("Failed accounts:     " + ", ".join(summary["failed_accounts"]))
    report_lines.append("Critical flags:      " + str(summary.get("critical", 0)))
    report_lines.append("Critical accounts:   " + ", ".join(summary["critical_accounts"]))
    report_lines.append("========================================")

    # Print and save the same report lines so both outputs match.
    for line in report_lines:
        print(line)

    write_report(report_lines, "report.txt")

    #Save the audit summary as JSON without including passwords.
    save_summary(summary, "audit_summary.json")