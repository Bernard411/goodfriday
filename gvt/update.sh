
#!/bin/bash

# Set your GitHub username and password (replace with your actual credentials)
USERNAME="Bernard411"
PASSWORD="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"

# Change directory to your website directory on PythonAnywhere
cd /path/to/your/website/directory

# Configure Git to use the provided credentials
git config credential.helper 'store --file ~/.git-credentials'
echo "https://${USERNAME}:${PASSWORD}@github.com" > ~/.git-credentials

# Pull changes from the GitHub repository using the stored credentials
git pull origin main

# Restart your PythonAnywhere application if necessary
# This step depends on how you deploy your website on PythonAnywhere
# You may need to restart a WSGI server or any other application server you are using
# For example:
# touch /var/www/mywebsite_pythonanywhere_com_wsgi.py

echo "Website updated successfully!"