from flask import Flask, render_template, url_for, flash, redirect
from forms import RegistrationForm, LoginForm
import Receiver
from time import sleep

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'

receiver = None


@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', file_list=Receiver.IP_FILE_LIST)


def main():
    global receiver, app
    receiver = Receiver.Receiver()
    app.run(host='0.0.0.0', port=5000)



if __name__ == '__main__':
    main()
