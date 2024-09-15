# SSP - SSH Safe Pass

`SSP (SSH Safe Pass)` is a Python-based tool that securely stores and manages SSH credentials. It allows easy connections to remote machines via SSH using stored credentials, and provides functionality to add, remove, and update credentials. The credentials are encrypted using a master password and secured with AES-256 in GCM mode.

## Features

- **Secure storage**: Credentials are stored using **AES-256 encryption in GCM mode**, ensuring both confidentiality and integrity.
- **SSH connection**: Connect to remote machines using stored credentials with a single command.
- **Credential management**: Add, remove, and list SSH credentials, and set default credentials for hosts.
- **Master password management**: Update the master password that encrypts your credentials.

## Security

SSP uses **AES-256 encryption in GCM mode** to securely store SSH credentials. GCM provides both strong encryption and integrity verification, ensuring a high level of security for sensitive data.

## First Run

On the first run, if no credentials database is found, the tool will prompt you to create a new one. You will be asked to set a **master password** that will be used to encrypt the credentials. Afterward, you will configure the default SSH credentials that will be used if no specific credentials are found for a hostname.

Example first run:

```bash
$ ssp -l
[ ] No database file found. Creating a new one...
[?] Enter master password:
[?] Reenter master password:
[ ] Now let's configure the default credentials (Used if no hostname matches when using --ssh option)
[?] Enter default username:
[?] Enter default password:
[+] Database was created successfully
```



## Installation

1. Clone the repository:

   `git clone https://github.com/somoit-net/ssh-safe-pass.git
   cd ssp-ssh-safe-pass`


  
3.  Install the required dependencies:
        
    `pip3 install -r requirements.txt` 
    


## Usage

### Command-Line Arguments

```
$ ssp.py -h

-- SSP - SSH Safe Pass (by @SomoIT) --

usage: ssp.py [-h] [-s [HOSTNAME] | -l | -a | -r [HOSTNAME] | -k | HOSTNAME]

optional arguments:
  -h --help               Show this help message and exit
  -s --ssh [HOSTNAME]     Connect to machine via SSH using stored credentials
  -l --list               List credentials
  -a --add                Add a new credential
  -d --default            Change default credentials used for SSH connections if there are no specific credentials for the hostname
  -r --remove [HOSTNAME]  Remove a credential from storage
  -k --new_key            Change master password that secures the credentials
```

### Basic Usage

-   **Connect to a host via SSH**:
    
    To connect to a host using stored credentials, either specify the hostname directly:
    
    `ssp example.com` 
    
    Or use the `-s`  or `-ssh` option:   
   
    `ssp -s example.com` 
    
-   **List stored credentials**:
    
    View all stored SSH credentials:
       
    `ssp -l` 
    
-   **Add new credentials**:
    
    Add new SSH credentials for a host:
        
    `ssp -a` 
    
-   **Remove stored credentials**:
    
    Remove the credentials for a specific host:
    
    `ssp -r [example.com]` 
    
-   **Change default credentials**:
    
    Update the default credentials used for SSH connections if no specific credentials are found for the host:
        
    `ssp -d` 
    
-   **Change master password**:
    
    Change the master password used to encrypt all the credentials data: 
        
    `ssp -k` 
    
