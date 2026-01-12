# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "progress==1.6",
#     "psutil",
#     "pyotp",
#     "requests==2.25.1",
#     "keyring",
# ]
# ///

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
import argparse
import keyring
# from progress.bar import IncrementalBar

#Variables:
api_get_keys = 'https://sshservice.cscs.ch/api/v1/auth/ssh-keys/signed-key'
service_id = 'cscs-keygen'
ssh_folder = Path(os.path.expanduser("~")) / '.ssh'
priv_key_name = 'cscs-key'

#Methods:
def get_user_credentials(fname=None):
    credentials = {}
    if fname is not None and fname.exists():
        print("Reading credentials from file: " + str(fname))
        try:
            with open(fname, 'r') as f:
                credentials = json.load(f)
        except Exception:
            pass

    user = credentials.get('username')
    if not user:
        user = input("Username: ")
        # Save username to file
        if fname:
            try:
                with open(fname, 'w') as f:
                    json.dump({'username': user}, f, indent=4)
            except Exception as e:
                print(f"Warning: Could not save username: {e}")

    pwd = keyring.get_password(service_id, user)
    if not pwd:
        if 'password' in credentials:
            pwd = credentials['password']
            keyring.set_password(service_id, user, pwd)
            print("Migrated password to keyring.")
        else:
            pwd = getpass.getpass()
            keyring.set_password(service_id, user, pwd)

    otp_secret = keyring.get_password(service_id + "_otp", user)
    otp = None
    
    if otp_secret:
        otp = pyotp.TOTP(otp_secret).now()
    else:
        if 'otp_secret' in credentials:
            otp_secret = credentials['otp_secret']
            keyring.set_password(service_id + "_otp", user, otp_secret)
            otp = pyotp.TOTP(otp_secret).now()
            print("Migrated OTP secret to keyring.")
        else:
            while not otp:
                inp = getpass.getpass("Enter OTP (6-digit code) or OTP Secret to store:")
                clean_inp = inp.strip()
                if len(clean_inp) == 6 and clean_inp.isdigit():
                    otp = clean_inp
                elif clean_inp:
                    try:
                        otp = pyotp.TOTP(clean_inp).now()
                        keyring.set_password(service_id + "_otp", user, clean_inp)
                        print("OTP Secret stored in keyring.")
                    except:
                        print("Invalid input. Please enter a valid 6-digit OTP code or a valid OTP Secret.")
                else:
                    print("Input cannot be empty.")

    # Clean up secrets from file if they existed
    if fname and fname.exists() and ('password' in credentials or 'otp_secret' in credentials):
        print("Cleaning up secrets from file...")
        try:
            with open(fname, 'w') as f:
                json.dump({'username': user}, f, indent=4)
        except Exception as e:
            print(f"Warning: Could not clean up file: {e}")

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

def key_invalid_after(priv_key_f):
    curr_time = int(time.time())
    if not priv_key_f.exists():
        return 0
    modified_time = int(os.path.getmtime(priv_key_f))
    return max(86400 - (curr_time - modified_time), 0) # number of seconds left for the key to expire

def main(credentials_file=None, once=False, force=False):
    credential_folder = Path(__file__).parent
    # check if a file called pid exists in the same folder as the script
    # if it does, then the script is already running
    if not once: # if the script is running only once, then there is no need to check for other instances
        pid_file = credential_folder / 'pid'
        if pid_file.exists():
            # kill the previous process
            with open(pid_file, 'r') as f:
                pid = int(f.read())
                if psutil.pid_exists(pid):
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
        if time_left > 0 and not force:
            print("The key is still valid for " + str(time_left) + " seconds.")
            if once:
                break
            time.sleep(time_left + 10) # sleep for 10 seconds more than the time left
        user, pwd, otp = get_user_credentials(credentials_file)
        public, private = get_keys(user, pwd, otp)
        save_keys(public, private)
        if force:
            break

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
    parser = argparse.ArgumentParser(description='Generate CSCS keys')
    parser.add_argument('--once', action='store_true', help='Run the script only once')
    parser.add_argument('--force', action='store_true', help='Force the script to run even if the key is still valid')
    parser.add_argument('--credentials', type=str, help='Path to the credentials file', default=Path(__file__).parent / 'credential.json')
    args = parser.parse_args()
    exit(main(args.credentials, args.once, args.force))

