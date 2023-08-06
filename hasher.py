import bcrypt
import hashlib

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
    else:
        return "Geçersiz seçenek!"

def main():
    print("Hasher V1.0")
    print("https://github.com/xNovem")
    print("===================")
    print("1. Bcrypt")
    print("2. SHA-256")
    print("3. MD5")
    print("4. SHA-1")
    print("5. SHA-512")
    print("6. BLAKE2s")
    print("7. SHA3-256")
    print("8. SHAKE-256")
    print("9. SHA-224")
    print("10. SHA-384")
    print("11. BLAKE2b")
    print("12. SHA3-512")
    print("13. SHAKE-128")
    print("14. SHA3-224")
    print("15. BLAKE2b")

    selected_option = int(input("Lütfen bir şifreleme yöntemi seçin (1-15): "))

    if selected_option in range(1, 16):
        user_password = input("Lütfen şifrenizi girin: ")
        hashed_password = hash_password(user_password, selected_option)
        print("Hashlenmiş şifre:", hashed_password)
    else:
        print("Geçersiz seçenek!")

if __name__ == "__main__":
    main()
