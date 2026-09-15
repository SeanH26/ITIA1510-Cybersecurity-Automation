from password_checker import check_length, check_digit, check_username, check_rotation

# Test check_length with a password that is too short.
length_ok, length_verdict = check_length("abcd")
assert length_ok == False
print("PASS: check_length correctly identified weak password (length_ok = False)")


# Test check_length with a 16-character password.
length_ok, length_verdict = check_length("abcdefghijklmnop")
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
rotation_ok, rotation_verdict = check_rotation(18)
assert rotation_ok == False
print("PASS: check_rotation correctly returned False for 18-month interval")


# Test check_rotation with an interval of 6 months.
rotation_ok, rotation_verdict = check_rotation(6)
assert rotation_ok == True
print("PASS: check_rotation correctly returned True for 6-month interval")


print("----------------------------------------")
print("All 8 tests passed.")
