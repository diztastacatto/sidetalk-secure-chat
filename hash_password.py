import bcrypt
import getpass

# Get password from user
password = getpass.getpass("Enter password to hash: ")

# Generate salt and hash
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

# Print the hash
print("BCrypt hash:")
print(hashed.decode('utf-8'))
