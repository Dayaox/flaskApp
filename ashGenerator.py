from werkzeug.security import generate_password_hash

password = '39023902'
hashed_password = generate_password_hash(password, method='sha256')

print(hashed_password)