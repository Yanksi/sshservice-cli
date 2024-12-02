# This script sets the environment properly so that a user can access CSCS
# login nodes via ssh. 

#    Copyright (C) 2023, ETH Zuerich, Switzerland
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, version 3 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    AUTHORS Massimo Benini

import getpass
import requests
import os
import sys
import time
import json
import pyotp
from pathlib import Path
import psutil
# from progress.bar import IncrementalBar

#Variables:
api_get_keys = 'https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key'
ssh_folder = Path(os.path.expanduser("~")) / '.ssh'
priv_key_name = 'cscs-key'

#Methods:
def get_user_credentials(fname=None):
    credentials = {}
    if fname is not None and fname.exists():
        print("Reading credentials from file: " + str(fname))
        with open(fname, 'r') as f:
            credentials = json.load(f)
            if 'otp_secret' in credentials:
                credentials['otp'] = pyotp.TOTP(credentials['otp_secret']).now()
    user = input("Username: ") if 'username' not in credentials else credentials['username']
    pwd = getpass.getpass() if 'password' not in credentials else credentials['password']
    otp = getpass.getpass("Enter OTP (6-digit code):") if 'otp' not in credentials else credentials['otp']
    return user, pwd, otp

def get_keys(username, password, otp):
    print("Fetching keys from CSCS...")
    headers = {'Content-Type': 'application/json', 'Accept':'application/json'}
    data = {
        "username": username,
        "password": password,
        "otp": otp
    }
    try:
        resp = requests.post(api_get_keys, data=json.dumps(data), headers=headers, verify=True)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        try:
            d_payload = e.response.json()
        except:
            raise SystemExit(e)
        if "payload" in d_payload and "message" in d_payload["payload"]:
            print("Error: "+d_payload["payload"]["message"])
        raise SystemExit(e)
    else:
        public_key = resp.json()['public']
        if not public_key:
            sys.exit("Error: Unable to fetch public key.")
        private_key = resp.json()['private']
        if not private_key:
            sys.exit("Error: Unable to fetch private key.")
        return public_key, private_key

def save_keys(public,private):
    if not public or not private:
        sys.exit("Error: invalid keys.")
    try:
        with open(os.path.expanduser("~")+'/.ssh/cscs-key-cert.pub', 'w') as file:
            file.write(public)
    except IOError as er:
        sys.exit('Error: writing public key failed.', er)
    try:
        with open(os.path.expanduser("~")+'/.ssh/cscs-key', 'w') as file:
            file.write(private)
    except IOError as er:
        sys.exit('Error: writing private key failed.', er)
    try:
        os.chmod(os.path.expanduser("~")+'/.ssh/cscs-key-cert.pub', 0o644)
    except Exception as ex:
        sys.exit('Error: cannot change permissions of the public key.', ex)
    try:
        os.chmod(os.path.expanduser("~")+'/.ssh/cscs-key', 0o600)
    except Exception as ex:
        sys.exit('Error: cannot change permissions of the private key.', ex)

def set_passphrase():
    user_input = input('Do you want to add a passphrase to your key? [y/n] (Default y) \n')

    yes_choices = ['yes', 'y']
    no_choices = ['no', 'n']

    if user_input.lower() in no_choices:
        passphrase = False
    else:
        passphrase = True
        cmd = 'ssh-keygen -f ~/.ssh/cscs-key -p'
        while (os.system(cmd) != 0):
            print("Please set the same passphrase twice...")
    return passphrase

def key_invalid_after(priv_key_f):
    curr_time = int(time.time())
    if not priv_key_f.exists():
        return 0
    modified_time = int(os.path.getmtime(priv_key_f))
    return max(86400 - (curr_time - modified_time), 0) # number of seconds left for the key to expire

def main(credentials_file=None):
    credential_folder = Path(__file__).parent
    # check if a file called pid exists in the same folder as the script
    # if it does, then the script is already running
    pid_file = credential_folder / 'pid'
    if pid_file.exists():
        # kill the previous process
        with open(pid_file, 'r') as f:
            pid = int(f.read())
            ps = psutil.Process(pid)
            # check if the process is actually a the previous process
            cmdline = ps.cmdline()
            if len(cmdline) == 2 and 'python' in cmdline[0] and 'cscs-keygen.py' in cmdline[1]:
                print("The script is already running. Terminating the previous process...")
                ps.terminate()
                
    # write the current process id to the pid file
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))
    while True:
        time_left = key_invalid_after(ssh_folder / priv_key_name)
        if time_left > 0:
            print("The key is still valid for " + str(time_left) + " seconds.")
            time.sleep(time_left + 10) # sleep for 10 seconds more than the time left
        user, pwd, otp = get_user_credentials(credentials_file)
        public, private = get_keys(user, pwd, otp)
        save_keys(public, private)
#     message = """        

# Usage:

# 1. Add the key to the SSH agent"""+substrg+"""
# ssh-add -t 1d ~/.ssh/cscs-key

# 2. Connect to the login node using CSCS keys:
# ssh -A your_usernamen@<CSCS-LOGIN-NODE>

# Note - if the key is not added to the SSH agent as mentioned in the step-1 above then use the command:
# ssh -i ~/.ssh/cscs-key <CSCS-LOGIN-NODE>

# """
#     print(message)

if __name__ == "__main__":
    exit(main(Path(__file__).parent / 'credential.json'))
