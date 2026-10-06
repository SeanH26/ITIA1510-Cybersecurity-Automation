from password_checker import (
    audit_password,
    check_breach,
    check_digit,
    check_length,
    check_rotation,
    check_username,
    known_breached,
    policy,
)


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

print("----------------------------------------")
print("All 12 tests passed.")