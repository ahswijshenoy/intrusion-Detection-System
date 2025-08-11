**Intrusion Detection System**

Step 1: Run the powershell as an administrator (Windows)

python -m venv venv

.\venv\Scripts\Activate

pip install flask bcrypt email-validator user-agents

python .\app.py

Step 2: Check if the website health is working in another powershell terminal

Invoke-RestMethod -Method GET http://127.0.0.1:5000/health

Step 3: Open the website which will most be 

http://127.0.0.1:5000

Step 4: Register on the website, make sure the credentials are being saved to the Database

Step 5: Login and play around with the functionalities// Check the alerts from powershell terminal.

Anything that is highlighted in red is the attack

Anything that is highlighted in white means the function has worked successfully /registering/logging and more


