# -*- coding: utf-8 -*-
import bcrypt
import hashlib
import os

def hash_password(password, algorithm):
    if algorithm == 1:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed
    elif algorithm == 2:
        hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 3:
        hashed = hashlib.md5(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 4:
        hashed = hashlib.sha1(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 5:
        hashed = hashlib.sha512(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 6:
        hashed = hashlib.sha3_256(password.encode('utf-8')).hexdigest()
        return hashed
    else:
        return "Invalid option!"

def main():
    os.system("clear")  # Clear the screen
    print("\033[1;31;40mHasher V1.0\033[0m")
    print("\033[1;33;40mhttps://github.com/xNovem\033[0m")
    print("\033[1;33;40m===================\033[0m")
    print("\033[1;33;40m1. Bcrypt\033[0m")
    print("\033[1;33;40m2. SHA-256\033[0m")
    print("\033[1;33;40m3. MD5\033[0m")
    print("\033[1;33;40m4. SHA-1\033[0m")
    print("\033[1;33;40m5. SHA-512\033[0m")
    print("\033[1;33;40m6. SHA3-256\033[0m")
    # Add other encryption methods here

    selected_option = int(raw_input("\033[1;36;40mPlease select an encryption method (1-6): \033[0m"))

    if selected_option in range(1, 7):
        user_password = raw_input("\033[1;36;40mPlease enter your password: \033[0m")
        hashed_password = hash_password(user_password, selected_option)
        print("Password Has Been Hashed -------->", hashed_password)
    else:
        print("\033[1;31;40mInvalid option!\033[0m")

if __name__ == "__main__":
    main()
