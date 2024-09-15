#!/usr/bin/python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import sys
import time
import json
import getpass
import argparse
import subprocess
import shutil

def derive_key(password: bytes, salt: bytes) -> bytes:
    # Derive a key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key length
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_aes_gcm(data, output_file, password):
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password.encode(), salt)

    # Serialize the array of objects to JSON
    serialized_data= json.dumps(data).encode()


    nonce = os.urandom(12)  # Generate a random nonce (IV)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(serialized_data) + encryptor.finalize()


    # Concatenate salt, nonce, tag, and ciphertext
    encrypted_data= salt + nonce + encryptor.tag + ciphertext

    with open(output_file, 'wb') as f:
        f.write(encrypted_data)  # Write to file


def decrypt_aes_gcm(data_file, password):
    with open(data_file, 'rb') as f:
        encrypted_data = f.read()

    salt = encrypted_data[:16]  # Extract salt
    nonce = encrypted_data[16:28]  # Extract nonce
    tag = encrypted_data[28:44]  # Extract tag
    ciphertext = encrypted_data[44:]  # Extract ciphertext

    key = derive_key(password.encode(), salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data= decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data.decode('utf-8')


def connect_ssh(username, password, hostname):

    def test_sshpass_connection(hostname, user, password):
        try:
            result = subprocess.run(
                ['sshpass', '-p', password, 'ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', user + '@' + hostname, 'exit'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0 and 'Host key verification failed' in result.stderr:
                print('[ ] Host key verification failed. Add the host key to known_hosts.')
                return False
        except Exception as e:
            print(f'Error occurred: {e}')
            return False

        return True

    if test_sshpass_connection(hostname, username, password):
        print("[ ] Connecting to \'" + hostname + "\'...\n")
        result = subprocess.run(['sshpass', '-p', password, 'ssh', username + '@' + hostname])


def display_help():

    help_message = """
-- SSH credentials manager (by @SomoIT) --

usage: tool.py [-h] [-s [HOSTNAME] | -l | -a | -r [HOSTNAME] | -k | HOSTNAME]

optional arguments:
  -h --help               Show this help message and exit
  -s --ssh [HOSTNAME]     Connect to machine via SSH using stored credentials
  -l --list               List credentials
  -a --add                Add a new credential
  -d --default            Change default credentials used for SSH connections if there are no specific credentials for the hostname
  -r --remove [HOSTNAME]  Remove a credential from storage
  -k --new_key            Change master password that secures the credentials

If no options are provided, supplying a hostname directly will default to `-s HOSTNAME` for SSH connection

"""
    sys.stdout.write(help_message)

def option_ssh(args):

        if shutil.which('sshpass') is None:
            print('[-] "sshpass" is not installed. Install it to use the -ssh option')
            return

        if args.ssh == '':
            ssh_hostname = input("Enter host to connect to: ")
        else:
            ssh_hostname = args.ssh

        search_credential = None
        for credential in data:
            if credential['hostname'] == ssh_hostname:
                search_credential = credential
                break

        if search_credential == None:
            print("[ ] Hostname not found in list. Using default credentials")
            search_credential = data[0]

        connect_ssh(search_credential['username'],search_credential['password'],ssh_hostname)

def option_list():

    print()

    print(f"{'Hostname':<15} {'Username':<15} {'Comment'}")
    print("-"*85)

    for credential in data:
        print(f"{credential['hostname']:<15} {credential['username']:<15} {credential['comment']}")

    print()

def option_add():
    global data

    add_hostname = input("[?] Enter hostname: ")
    add_username = input("[?] Enter username: ")
    add_password = getpass.getpass("[?] Enter password: ")
    add_comment = input("[?] Enter comment: ")
    data.append({"hostname": add_hostname, "username": add_username, "password": add_password, "comment": add_comment})
    encrypt_aes_gcm(data,data_file,password)
    print("[+] Added new credential to database")


def option_default():
    global data

    default_username = input("[?] Enter new default username: ")
    default_password = getpass.getpass("[?] Enter new default password: ")

    data[0]['username'] = default_username
    data[0]['password'] = default_password
    encrypt_aes_gcm(data,data_file,password)
    print("[+] Changes to default credential saved into database")



def option_remove(args):
    global data

    if args.remove == '':
        remove_hostname = input("[?] Enter host to remove (enter to list): ")
        if remove_hostname == '':
            option_list()
            remove_hostname = input("[?] Enter host to remove: ")
    else:
        remove_hostname = args.remove

    if remove_hostname == "default":
        print("[ ] Default credentials cannot be removed")
    else:
        filtered_data = list(filter(lambda credential: credential["hostname"] != remove_hostname, data))
        if len(filtered_data) < len(data):
            data = filtered_data
            encrypt_aes_gcm(data,data_file,password)
            print("[+] Element(s) removed")
        else:
            print("[-] Element not found")


def option_new_key():
    new_password = getpass.getpass("[+] Enter new master key: ")
    new_password2 = getpass.getpass("[+] Reenter new master key: ")

    if new_password != new_password2:
        print("[-] Both passwords are not equal. No changes were made")
    else:
        encrypt_aes_gcm(data,data_file,new_password)
        print("[+] Master password was modified")


def create_or_decrypt_data(file):

    if not os.path.exists(file):
        data= []
        print("[ ] No database (" + file + ") file found. Creating a new one...")
        password = getpass.getpass("[?] Enter master password : ")
        password2 = getpass.getpass("[?] Reenter master password : ")
        print("[ ] Now lets configure the default credentials (Used if no hostname matches when using --ssh option)")
        default_username = input("[?] Enter default username: ")
        default_password = getpass.getpass("[?] Enter default password: ")
        data.append({"hostname": "default", "username": default_username, "password": default_password, "comment": "Used if no hostname matches when using --ssh option"})
        encrypt_aes_gcm(data,data_file,password)
        os.chmod(data_file, 0o740)
        print("[+] Database was created succesfully")
    else:
        password = getpass.getpass("[?] Enter master password: ")
        try:
            data=json.loads(decrypt_aes_gcm(file, password))
        except:
            print("[-] Error decrypting (incorrect master password?)")
            exit(1)
        else:
            print("[+] Database decrypted succesfully")

    return data,password


data = None
data_file = os.path.dirname(os.path.abspath(__file__)) + '/.data.enc'

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="SSH credentials manager",add_help=False)
    group = parser.add_mutually_exclusive_group()

    group.add_argument('-s', '--ssh', metavar='HOSTNAME', const='', nargs='?')
    group.add_argument('-l', '--list', action='store_true')
    group.add_argument('-a', '--add', action='store_true')
    group.add_argument('-r', '--remove', metavar='HOSTNAME', const='', nargs='?')
    group.add_argument('-d', '--default', action='store_true')
    group.add_argument('-k', '--new_key', action='store_true')
    group.add_argument('-h', '--help', action='store_true')
    group.add_argument('hostname', nargs='?')

    args = parser.parse_args()

    no_options_provided = not (args.ssh or args.list or args.add or args.default or args.remove or args.new_key or args.help or args.hostname)
    if no_options_provided:
        print("Error: No options provided. Please specify an option or a hostname.")
        exit(1)

    if args.help:
        display_help()
        exit()

    if args.hostname:
        args.ssh = args.hostname

    data,password = create_or_decrypt_data(data_file)

    if args.ssh is not None:
        option_ssh(args)
    elif args.list:
        option_list()
    elif args.add:
        option_add()
    elif args.remove is not None:
        option_remove(args)
    elif args.default:
        option_default()
    elif args.new_key:
        option_new_key()
    else:
        print("[-] No valid option specified")



