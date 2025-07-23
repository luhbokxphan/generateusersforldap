import secrets
import string
import hashlib
import base64

def generate_secure_password(length=12):
    # Limit punctuation to safe subset (no quotes, backslashes, semicolons)
    safe_punct = "!@#$%^&*()-_=+"
    characters = string.ascii_letters + string.digits + safe_punct
    return ''.join(secrets.choice(characters) for _ in range(length))

def hash_ssha(password):
    # Create an SSHA hashed password
    salt = secrets.token_bytes(4)
    sha = hashlib.sha1(password.encode() + salt).digest() + salt
    return "{SSHA}" + base64.b64encode(sha).decode()

def generate_ldif_user_entry(username, first_name, last_name, email, base_dn, ou="users"):
    password_plain = generate_secure_password()
    password_hashed = hash_ssha(password_plain)

    dn = f"cn={username},ou={ou},{base_dn}"
    lines = [
        f"dn: {dn}",
        "changetype: add",
        "objectClass: top",
        "objectClass: person",
        "objectClass: organizationalPerson",
        "objectClass: inetOrgPerson",
        f"cn: {first_name} {last_name}",
        f"sn: {last_name}",
        f"givenName: {first_name}",
        f"mail: {email}",
        f"uid: {username}",
        f"userPassword: {password_hashed}",
    ]
    # For debugging, show entry printed to console
    print("\n".join(lines), "\n")
    return "\n".join(lines) + "\n\n"

def generate_ldif_file(num_users, base_dn, output_file="users.ldif"):
    with open(output_file, 'w') as f:
        f.write("version: 1\n\n")
        for i in range(1, num_users + 1):
            username   = f"user{i}"
            first_name = "Test"
            last_name  = f"User{i}"
            email      = f"user{i}@example.com"
            f.write(generate_ldif_user_entry(username, first_name, last_name, email, base_dn))
    print(f"Generated {num_users} entries in {output_file}")

if __name__ == "__main__":
    generate_ldif_file(10, "dc=example,dc=com", "new_users.ldif")