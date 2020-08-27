# Password Manager
# Created by CaptainFlint
# August 26, 2020
# Version 1.0

import os
import binascii
import secrets
import hashlib
import string
import platform
from os import path
from time import sleep
from getpass import getpass
from Crypto.Cipher import Salsa20 


## Useful Methods

def generate_digit_code(length):
    """generate_digit_code(int) -> str
    Generates a string of digits of specified length
    using a cryptographically secure PRNG.
    length: (int) Length of digit code."""
    code = ""
    for i in range(length):
        code += secrets.choice(string.digits)
    return code

def generate_alpha_code(length,lower=0):
    """generate_alpha_code(int,int) -> str
    Generates a string of letters of specified length
    with cryptographically secure PRNG.
    If lower is 0, the string is lowercase. If it is 1,
    it is uppercase. Otherwise, there is a mix of upper
    and lower case.
    length: (int) Length of code
    lower: (int) 0 if all lower, 1 if all upper, anything if mix"""
    code = ""
    gen_base = ""
    if lower == 0:
        gen_base = string.ascii_lowercase
    elif lower == 1:
        gen_base = string.ascii_uppercase
    else:
        gen_base = string.ascii_lowercase + string.ascii_uppercase

    for i in range(length):
        code += secrets.choice(gen_base)
    return code

def generate_hex_code(length):
    """generate_hex_code(int) -> str
    Generates a random hex string with cryptographically
    secure PRNG
    length: (int) length of code"""
    code = ""
    for i in range(length):
        code += secrets.choice(string.hexdigits)
    return code

def generate_passcode(length,min_lower=0,min_upper=0,min_digits=0,min_punct=0):
    """generate_passcode(int,int,int,int,int) -> str
    Generates a random string password of specified length
    of lowercase and uppercase letters, digits, and punctuation
    using a cryptographically secure random number generator.
    Customizable for restrictions on types of characters.
    length: (int) length of password
    min_lower:  (int) min number of lowercase letters
    min_upper:  (int) min number of uppercase letters. -1 if not included.
    min_digits: (int) min number of digits. -1 if not included.
    min_punct:  (int) min number of punctuation. -1 if not included."""
    code = ""
    gen_base = string.ascii_lowercase
    for i in range(min_lower):
        code += secrets.choice(string.ascii_lowercase)
    if (min_upper >= 0):
        gen_base += string.ascii_uppercase
        for i in range(min_upper):
            code += secrets.choice(string.ascii_uppercase)
    if (min_digits >= 0):
        gen_base += string.digits
        code += generate_digit_code(min_digits)
    if (min_punct >= 0):
        gen_base += string.punctuation
        for i in range(min_punct):
            code += secrets.choice(string.punctuation)
    remLen = length - len(code)
    for i in range(remLen):
        code += secrets.choice(gen_base)
    return shuffle(code)

def shuffle(text):
    """shuffle(str) -> str
    Shuffles the specified string using
    a cryptographically secure PRNG."""
    textList = list(text)
    for i in range(len(text)-1,0,-1):
        j = secrets.randbelow(i+1)
        temp = textList[i]
        textList[i] = textList[j]
        textList[j] = temp
    return "".join(textList)

def generate_XKCD_password(length):
    """generate_XKCD_password(int) -> str
    Generates a XKCD style password of specified
    length according to https://xkcd.com/936/
    Wordlist is diceware.txt wordlist"""
    code = ""
    
    wordFile = open('diceware.txt','r')
    words = [word.strip() for word in wordFile]
    wordFile.close()

    for i in range(length):
        code += secrets.choice(words) + " "

    return code[:-1]

def hash(passcode,salt):
    """hash(str,bytes) -> bytes
    Hashes the specified passcode with the specified salt.
    passcode: (str) passcode to be hashed.
    salt: (bytes) salt used in hash. Should be at least 16 bytes."""
    key = hashlib.pbkdf2_hmac("sha256",passcode.encode("utf-8"),salt,100000)
    return key,salt

def encrypt(text,mast_pass,salt):
    """encrypt(str,str,bytes) -> bytes
    Encryptes the specifed string using the 
    master password and salt.
    text: (str) string to be encrypted
    mast_pass: (str) password used for encryption
    salt: (bytes) salt used for encryption. Should be at least 16 bytes"""
    key = hashlib.pbkdf2_hmac("sha256",mast_pass.encode("utf-8"),salt,100000)
    nonce = os.urandom(8)
    cipher = Salsa20.new(key,nonce)
    return nonce + cipher.encrypt(text)

def decrypt(ciphertext,mast_pass,salt):
    """decrypt(bytes,str,bytes) -> bytes
    Decrypts the specified byte string using the
    master passcode and salt. Outputs the decrypted
    byte string."""
    key = hashlib.pbkdf2_hmac("sha256",mast_pass.encode("utf-8"),salt,100000)
    nonce = ciphertext[:8]
    ciph_text = ciphertext[8:]
    cipher = Salsa20.new(key,nonce)
    return cipher.decrypt(ciph_text)

def get_salt(bits):
    """get_salt(int) -> bytes
    Outputs a random salt using a cryptographically
    secure PRNG."""
    return os.urandom(bits)

# Password Manager Class
    
class PasswordManager:
    """Represents the password manager for the program. To use,
    just create an instance of the class."""

    def __init__(self,file="data.txt",funny=True):
        self.filename = file
        self.mast_hash = ""
        self.mast_salt = ""
        self.fun = funny
        self.accounts = []
        self.run()

    def run(self):
        self.print_welcome()
        if not path.exists(self.filename):
            self.create_master_account()
            f = open(self.filename,"w")
            f.write(self.mast_hash.hex()+"\n")
            f.write(self.mast_salt.hex()+"\n")
            f.close()
        f = open(self.filename,"r")
        data = f.readlines()
        f.close()

        self.mast_hash = binascii.unhexlify(data[0].strip())
        self.mast_salt = binascii.unhexlify(data[1].strip())

        passTry = getpass("Please enter your master password: ")
        while not self.match(passTry):
            passTry = getpass("Incorrect. Please try again: ")
        print("Password Correct.\n")
        del passTry

        if len(data) > 2:
            self.load_accounts(data)
        while True:
            self.print_available()
            select = self.get_selection(len(self.accounts))
            passTry = getpass("\nPlease enter your master password: ")
            while not self.match(passTry):
                passTry = getpass("Incorrect. Please try again: ")
            print("Password Correct.\n")

            if select == 0:
                choice = input("Press 1 to Create New, 2 to update master account: ")
                while not choice.strip() in ["1","2"]:
                    choice = input("Press 1 to Create New, 2 to update master account: ")
                if choice.strip() == "1":
                    name = input("Enter the service name: ")
                    user = input("Enter the username: ")
                    passw = self.get_password()
                    salt = get_salt(24)
                    encr_user = encrypt(user.encode("utf-8"),passTry,salt)
                    encr_pass = encrypt(passw.encode("utf-8"),passTry,salt)
                    self.accounts.append(ServiceAccount(name,encr_user,encr_pass,salt))
                    del name, user, passw, salt
                else:
                    self.create_master_account()

            else:
                account = self.accounts[select-1]
                choice = input("Do you want to (v)iew or (e)dit "+account.get_name()+"? ")
                while not (choice.strip().lower() in ["v","e"]):
                    choice = input("Do you want to (v)iew or (e)dit "+account.get_name()+"? ")
                if choice.strip().lower() == "v":
                    self.display_account(account,passTry)
                elif choice.strip().lower() == "e":
                    choice = input("Press 1 to edit, 2 to delete "+account.get_name()+": ")
                    while not choice.strip() in ["1","2"]:
                        choice = input("Press 1 to edit, 2 to delete "+account.get_name()+": ")
                    if choice.strip() == "1":
                        user = input("Enter the username: ")
                        passw = self.get_password()
                        salt = get_salt(24)
                        encr_user = encrypt(user.encode("utf-8"),passTry,salt)
                        encr_pass = encrypt(passw.encode("utf-8"),passTry,salt)
                        account.update(account.get_name(),encr_user,encr_pass,salt)
                        del user,passw,salt
                    else:
                        doubleCheck = input("Are you sure you want to delete "+account.get_name()+"? (Y/N) ")
                        while not doubleCheck.strip().lower() in ["y","n"]:
                            doubleCheck = input("Y/N: ")
                        if doubleCheck.strip().lower() == "y":
                            del self.accounts[select-1]
                            print(account.get_name() + " deleted.")
                            del account
                        else:
                            print("Cancelled.")
            del passTry

            end = input("\nType C to continue, Q to quit. ")
            while not (end.strip().lower() in ["c","q"]):
                end = input("Type C to continue, Q to quit. ")
            if (end.strip().lower() == "q"):
                break
        f = open("data.txt","w")
        f.write(self.mast_hash.hex()+"\n")
        f.write(self.mast_salt.hex())
        for account in self.accounts:
            f.write("\n"+account.get_salt().hex())
            f.write(" "+account.get_name().encode("utf-8").hex())
            f.write(" "+account.get_user().hex())
            f.write(" "+account.get_password().hex())
        f.close()
        if self.fun:
            print("\nBoring conversation anyway!")

    def generate_passcode(self):
        select = self.get_options()
        print()
        if select == 0:
            return self.generate_numeric_code()
        elif select == 1:
            return self.generate_generic_code()
        elif select == 2:
            return self.generate_XKCD_code()

    def get_options(self):
        print("\nOptions:")
        print("-----------------")
        print("[0] Numeric Code")
        print("[1] Generic Code")
        print("[2] XKCD Style Code\n")
        select = self.get_selection(2)
        return select

    def get_password(self):
        choice = input("Press 1 to create password, 2 to randomly generate: ")
        while not (choice.strip() in ["1","2"]):
            choice = input("Press 1 to create password, 2 to randomly generate: ")
        if choice.strip()  == "1":
            pass1 = getpass("\nEnter the password: ")
            pass2 = getpass("Confirm password: ")
            while not (pass1 == pass2):
                print("\nPasswords do not match.")
                pass1 = getpass("\nEnter the password: ")
                pass2 = getpass("Confirm password: ")
            del pass2
            return pass1
        elif choice.strip() == "2":
            return self.generate_passcode()

        return ""

    def display_account(self,account,mast_pass):
        salt = account.get_salt()
        name = account.get_name()
        user = account.get_user()
        password = account.get_password()

        print(name+" Login:")
        user_decrypt = decrypt(user,mast_pass,salt).decode("utf-8")
        pass_decrypt = decrypt(password,mast_pass,salt).decode("utf-8")
        print("Username: "+user_decrypt)
        print("Password: "+pass_decrypt)
        del mast_pass


    def get_selection(self,length):
        select = input("Select any from the list above: ")
        while not self.valid_selection(select,length):
            select = input("Invalid. Select any from the list above: ")
        selection = int(select)
        return selection

    def valid_selection(self,select,length):
        if not select.strip().isdigit():
            return False
        index = int(select.strip())
        return 0 <= index and index <= length

    def load_accounts(self,data):
        for i in range(2,len(data)):
            data[i] = data[i].strip()
            infoList = data[i].split()
            salt = binascii.unhexlify(infoList[0])
            name = binascii.unhexlify(infoList[1]).decode("utf-8")
            user = binascii.unhexlify(infoList[2])
            password = binascii.unhexlify(infoList[3])
            self.accounts.append(ServiceAccount(name,user,password,salt))

    def match(self,password):
        passHash = hash(password,self.mast_salt)[0]
        return passHash == self.mast_hash

    def print_welcome(self):
        print("Welcome to this unsecure Password Manager 1.0!\n")
        sleep(1)
        if not self.fun:
            return
        print("Negative, Negative. We have a reactor leak here now. Give")
        print("us a few moments to lock it down. Large leak, very dangerous.\n")
        sleep(1)

    def create_master_account(self):
        print("Select a master password. This will be the")
        print("password you will use to access the data in this")
        print("password manager. Make sure your password is secure")
        print("and that you remember it. There is no backdoor!")
        print("If you forget, all information stored here will be lost.")
        # print("As of version 1.0, the master password cannot be changed.")
        print()
        sleep(0.5)
        pass1 = ""
        while True:
            pass1 = getpass("Please enter your new master password: ")
            while len(pass1) < 4 or pass1 in ["password","pass","123456"]:
                pass1 = getpass("Password too weak. Try again: ")
            pass2 = getpass("Confirm master password: ")
            if (pass1 == pass2):
                del pass2
                break
            else:
                print("Passwords do not match.\n")
        print("\nSuccess! Account created.\n")
        
        self.mast_salt = get_salt(32)
        self.mast_hash = hash(pass1,self.mast_salt)[0]
        
        del pass1

    def print_available(self):
        print("Available Logins:")
        print("-----------------")
        print("[0] Update")
        for i in range(len(self.accounts)):
            print("[{}] ".format(i+1)+str(self.accounts[i]))
        print()

    def keep_or_discard(self):
        opt = input("(K)eep or  (D)iscard? ")
        opt = opt.strip().lower()
        if (opt == "k"):
            print("\nPassword Saved!")
            return True
        return False
    
    def get_valid_choice(self,length,prompt):
        choice = input(prompt)
        while True:
            if choice.strip().lower() == "n":
                return "n"
            if choice.strip().isdigit():
                select = int(choice.strip())
                if 0 <= select and select <= length:
                    return str(select)
            choice = input("Invalid. "+prompt)

    def generate_numeric_code(self):
        lenText = input("Enter the length: ").strip()
        while not lenText.isdigit():
            lenText = input("Enter the length: ").strip()
        length = int(lenText)
        while True:
            code = generate_digit_code(length)
            print("Generated code: "+code)
            if self.keep_or_discard():
                break
        return code

    def get_min_value(self,choice):
        if choice == "n":
            return -1
        else:
            return int(choice)


    def generate_generic_code(self):
        lenText = input("Enter the length: ").strip()
        while not lenText.isdigit():
            lenText = input("Enter the length: ").strip()
        length = int(lenText)
        lowercase = self.get_valid_choice(length,"Enter the smallest number of lowercase letters (N for none): ")
        num_lower = self.get_min_value(lowercase)

        newLength = length-num_lower if num_lower >= 0 else length
        uppercase = self.get_valid_choice(newLength,"Enter the smallest number of capital letters (N for none): ")
        num_upper = self.get_min_value(uppercase)
        
        newLength = newLength-num_upper if num_upper >= 0 else newLength
        digits = self.get_valid_choice(newLength,"Enter the smallest number of digits (N for none): ")
        num_digits = self.get_min_value(digits)

        newLength = newLength-num_digits if num_digits >= 0 else newLength
        punct = self.get_valid_choice(newLength,"Enter the smallest number of punctuation (N for none): ")
        num_punct = self.get_min_value(punct)

        while True:
            code = generate_passcode(length,num_lower,num_upper,num_digits,num_punct)
            print("Generated code: "+code)
            if self.keep_or_discard():
                break
        return code

    def generate_XKCD_code(self):
        lenText = input("Enter the length: ").strip()
        while not lenText.isdigit():
            lenText = input("Enter the length: ").strip()
        length = int(lenText)
        while True:
            code = generate_XKCD_password(length)
            print("Generated code: "+code)
            if self.keep_or_discard():
                break
        return code

class ServiceAccount:
    """Represents an account in the password manager."""
    
    def __init__(self,name,encr_user,encr_pass,salt):
        self.name = name
        self.user = encr_user
        self.password = encr_pass
        self.salt = salt

    def __str__(self):
        return self.name

    def update(self,name,encr_user,encr_pass,salt):
        self.__init__(name,encr_user,encr_pass,salt)
    
    def get_salt(self):
        return self.salt

    def get_name(self):
        return self.name

    def get_user(self):
        return self.user

    def get_password(self):
        return self.password

a = PasswordManager()
# Clear the terminal so that information does not remain visible.
if platform.system() == "Windows":
    os.system("cls")
else:
    os.system("clear")
