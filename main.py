from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os


print("Welcome to password Manager")
print("***************************")
master_pwd = input("Please Enter Your Master Password : ")

salt_file = "salt.bin"

if os.path.exists(salt_file):
    with open(salt_file,"rb") as file:
        salt = file.read()
else:
    salt = os.urandom(16)
    with open(salt_file,"wb") as file:
        file.write(salt)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000,
    backend=default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
fernet = Fernet(key)


def write_password(a,b,c):

    encrypted_password = fernet.encrypt(c.encode()).decode()

    with open("passwords.txt","a") as file:
        entry = f"{a}|{b}|{encrypted_password} \n"
        
        file.write(entry)

def read_password():
    with open('passwords.txt',"r") as file:
        for line in file:
            
            a,b,c = line.strip().split("|")

            try:
                decrypted_password = fernet.decrypt(c.encode()).decode()
            except InvalidToken:
                decrypted_password = "Invalid Master Password"


            print(f"Account: {a} , Username: {b} , Password: {decrypted_password}")

while True:
    option = input("Please Specify Your Action (READ , WRITE) Enter Q to Exit : ").lower()

    if option == "q":
        if os.path.exists("key.txt"):
            os.remove("key.txt")
        break; 
    elif option == "read":
        read_password()
    elif option == "write":
        Title = input("Please Enter Account Name : ")
        Username = input("Enter Username : ")
        Password = input("Enter Password : ")
        write_password(Title,Username,Password)
    else:
        break;