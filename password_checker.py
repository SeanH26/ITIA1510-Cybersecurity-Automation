# Collect the account or system name.
account = input("Account or system: ")

# Collect the username even though it is not used for a check this week.
# The username will be needed for future versions of the program.
username = input("Username: ")

# Collect the password that will be analyzed.
password = input("Password: ")

# Collect the rotation interval as a string, then convert it to an integer.
rotation_interval = input("Rotation interval (months): ")
rotation_interval = int(rotation_interval)

# Calculate the required password measurements.
password_length = len(password)
length_score = password_length * 10
rotation_count = 36 // rotation_interval

# Display the formatted password audit report.
print("========================================")
print("   PASSWORD AUDIT REPORT")
print("========================================")
print("Account:           " + account)
print("Username:          " + username)
print("Password length:   " + str(password_length) + " characters")
print("Length score:      " + str(length_score) + " points")
print("Rotation interval: " + str(rotation_interval) + " months")
print("Rotations (3 yr):  " + str(rotation_count))
print("----------------------------------------")
print("NOTE: Classification requires conditionals -- coming in Week 02.")
print("========================================")