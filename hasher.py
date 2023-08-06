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
    # Diğer şifreleme yöntemleri buraya eklenmeli

def main():
    os.system("clear")  # Sayfayı temizle
    print("\033[1;31;40mHasher V1.0\033[0m")
    print("\033[1;33;40mhttps://github.com/xNovem\033[0m")
    print("\033[1;33;40m===================\033[0m")
    print("\033[1;33;40m1. Bcrypt\033[0m")
    print("\033[1;33;40m2. SHA-256\033[0m")
    print("\033[1;33;40m3. MD5\033[0m")
    print("\033[1;33;40m4. SHA-1\033[0m")
    print("\033[1;33;40m5. SHA-512\033[0m")
    # Diğer şifreleme yöntemleri buraya eklenmeli

    selected_option = int(raw_input("\033[1;36;40mLütfen bir şifreleme yöntemi seçin (1-15): \033[0m"))

    if selected_option in range(1, 16):
        user_password = raw_input("\033[1;36;40mLütfen şifrenizi girin: \033[0m")
        hashed_password = hash_password(user_password, selected_option)
        print("\033[1;32;40mHashlenmiş şifre:\033[0m", hashed_password)
    else:
        print("\033[1;31;40mGeçersiz seçenek!\033[0m")

if __name__ == "__main__":
    main()
