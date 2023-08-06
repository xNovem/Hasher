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
        hashed = hashlib.blake2s(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 7:
        hashed = hashlib.sha3_256(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 8:
        hashed = hashlib.shake_256(password.encode('utf-8')).hexdigest(64)
        return hashed
    elif algorithm == 9:
        hashed = hashlib.sha224(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 10:
        hashed = hashlib.sha384(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 11:
        hashed = hashlib.blake2b(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 12:
        hashed = hashlib.sha3_512(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 13:
        hashed = hashlib.shake_128(password.encode('utf-8')).hexdigest(32)
        return hashed
    elif algorithm == 14:
        hashed = hashlib.sha3_224(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 15:
        hashed = hashlib.blake2b(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 16:
        hashed = hashlib.sha3_384(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 17:
        hashed = hashlib.shake_256(password.encode('utf-8')).hexdigest(128)
        return hashed
    elif algorithm == 18:
        hashed = hashlib.sha3_512(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 19:
        hashed = hashlib.blake2s(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 20:
        hashed = hashlib.sha1(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 21:
        hashed = hashlib.md5(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 22:
        hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 23:
        hashed = hashlib.blake2s(password.encode('utf-8')).hexdigest()
        return hashed
    elif algorithm == 24:
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
    print("\033[1;33;40m6. BLAKE2s\033[0m")
    print("\033[1;33;40m7. SHA3-256\033[0m")
    print("\033[1;33;40m8. SHAKE-256\033[0m")
    print("\033[1;33;40m9. SHA-224\033[0m")
    print("\033[1;33;40m10. SHA-384\033[0m")
    print("\033[1;33;40m11. BLAKE2b\033[0m")
    print("\033[1;33;40m12. SHA3-512\033[0m")
    print("\033[1;33;40m13. SHAKE-128\033[0m")
    print("\033[1;33;40m14. SHA3-224\033[0m")
    print("\033[1;33;40m15. BLAKE2b\033[0m")
    print("\033[1;33;40m16. SHA3-384\033[0m")
    print("\033[1;33;40m17. SHAKE-256\033[0m")
    print("\033[1;33;40m18. SHA3-512\033[0m")
    print("\033[1;33;40m19. BLAKE2s\033[0m")
    print("\033[1;33;40m20. SHA-1\033[0m")
    print("\033[1;33;40m21. MD5\033[0m")
    print("\033[1;33;40m22. SHA-256\033[0m")
    print("\033[1;33;40m23. BLAKE2s\033[0m")
    print("\033[1;33;40m24. SHA3-256\033[0m")
    # Add other encryption methods here

    selected_option = int(raw_input("\033[1;36;40mPlease select an encryption method (1-24): \033[0m"))

    if selected_option in range(1, 25):
        user_password = raw_input("\033[1;36;40mPlease enter your password: \033[0m")
        hashed_password = hash_password(user_password, selected_option)
        print("\033[1;32;40mPassword Has Been Hashed --------> \033[0m", hashed_password)
    else:
        print("\033[1;31;40mInvalid option!\033[0m")

if __name__ == "__main__":
    main()
