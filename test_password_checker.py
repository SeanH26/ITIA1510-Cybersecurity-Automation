import os
import tempfile


from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    load_credentials,
    load_breached,
    write_report,
    save_summary,
    load_summary,
    policy,
    load_history,
    add_to_history,
    save_history,
)

known_breached = load_breached("breached.txt")


# Test check_length with a password that is too short.
length_ok, length_verdict = check_length("abcd", policy)
assert length_ok == False
print("PASS: check_length correctly identified weak password (length_ok = False)")


# Test check_length with a 16-character password.
length_ok, length_verdict = check_length("abcdefghijklmnop", policy)
assert length_ok == True
print("PASS: check_length correctly identified strong password (length_ok = True)")


# Test check_digit with a password containing no digits.
has_digit = check_digit("password")
assert has_digit == False
print("PASS: check_digit correctly returned False for password with no digits")


# Test check_digit with a password containing a digit.
has_digit = check_digit("password1")
assert has_digit == True
print("PASS: check_digit correctly returned True for password containing a digit")


# Test check_username when password matches username.
not_username = check_username("admin", "admin")
assert not_username == False
print("PASS: check_username correctly returned False when password matches username")


# Test check_username when password differs from username.
not_username = check_username("SecurePassword1", "admin")
assert not_username == True
print("PASS: check_username correctly returned True when password differs from username")


# Test check_rotation with an interval greater than 12 months.
rotation_ok, rotation_verdict = check_rotation(18, policy)
assert rotation_ok == False
print("PASS: check_rotation correctly returned False for 18-month interval")


# Test check_rotation with an interval of 6 months.
rotation_ok, rotation_verdict = check_rotation(6, policy)
assert rotation_ok == True
print("PASS: check_rotation correctly returned True for 6-month interval")


#Test check_breach with a password that is in the known breached list.
not_breached = check_breach("password123", known_breached)
assert not_breached == False
print("PASS: check_breach correctly returned False for breached password")


#Test check_breach with a password that is not in the known breached list.
not_breached = check_breach("Blue-Harbor-72-Lantern", known_breached)
assert not_breached == True
print("PASS: check_breach correctly returned True for password not in breach list")


#Test that the policy contains the required strong password length.
assert policy["strong_length"] == 15
print("PASS: policy strong_length is 15")


# Test that the policy includes the required digit rule.
assert "require_digit" in policy
print("PASS: policy contains require_digit")


# Test that load_credentials returns a list.
credentials = load_credentials("credentials.txt")
assert isinstance(credentials, list)
print("PASS: load_credentials returns a list")


# Test that the first credential contains an "account" key.
assert "account" in credentials[0]
print("PASS: first credential contains an account key")


# Test that load_breached returns a list.
known_breached = load_breached("breached.txt")
assert isinstance(known_breached, list)
print("PASS: load_breached returns a list")


# Test that password123 is in the breached password list.
assert "password123" in known_breached
print("PASS: load_breached contains password123")


# Test that write_report writes the report lines correctly.
test_lines = ["First report line", "Second report line"]
write_report(test_lines, "test_report.txt")

with open("test_report.txt", "r") as f:
    saved_text = f.read()

expected_text = "First report line\nSecond report line\n"
assert saved_text == expected_text
print("PASS: write_report correctly saved and retrieved both lines")

# Test that saving and loading JSON returns the same dictionary.
sample = {
    "total": 2,
    "passed": 1,
    "failed": 1,
    "critical": 1,
    "failed_accounts": ["Gmail"],
    "critical_accounts": ["Gmail"],
}

save_summary(sample, "test_summary.json")
loaded_summary = load_summary("test_summary.json")

assert loaded_summary == sample
print("PASS: save_summary and load_summary returned the same dictionary")


#Test that failed_accounts remains a list after loading JSON.
assert isinstance(loaded_summary["failed_accounts"], list)
print("PASS: failed_accounts is a list")

#Test that no passwords from credentials.txt appear in the JSON file.
credentials = load_credentials("credentials.txt")

with open("test_summary.json", "r") as f:
    saved_json = f.read()

#Passwords are excluded because other programs may read the summary.
for cred in credentials:
    assert cred["password"] not in saved_json

print("PASS: JSON summary does not contain any passwords")

# Test that a missing history file returns an empty list.
with tempfile.TemporaryDirectory() as folder:
    filepath = os.path.join(folder, "missing_history.json")
    assert load_history(filepath) == []

print("PASS: load_history returns an empty list for a missing file")


# Test that the first audit run starts at run 1.
history = add_to_history([], sample, 3)

assert len(history) == 1
assert history[0]["run"] == 1
assert history[0]["passed"] == sample["passed"]
assert history[0]["failed"] == sample["failed"]
assert history[0]["critical_accounts"] == sample["critical_accounts"]

print("PASS: add_to_history correctly creates the first run")


# Test that only the newest 2 runs are kept.
history = []

for i in range(3):
    history = add_to_history(history, sample, 2)

assert [entry["run"] for entry in history] == [2, 3]

print("PASS: add_to_history kept only the newest 2 runs")


# Test that saving and loading history returns the same list.
with tempfile.TemporaryDirectory() as folder:
    filepath = os.path.join(folder, "test_history.json")

    save_history(history, filepath)
    loaded_history = load_history(filepath)

    assert loaded_history == history

print("PASS: save_history and load_history returned the same list")


print("----------------------------------------")
print("All 24 tests passed.")