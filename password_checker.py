# Gets the name of the account or system.
account = input("Account or system: ")

# Gets you the username.
username = input("Username: ")

# Collect the password that will be analyzed.
password = input("Password: ")

#Gives you the rotation interval as a string, then convert it to an integer.
rotation_interval = input("Rotation interval (months): ")
rotation_interval = int(rotation_interval)

# Calculates the required password measurements.
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
