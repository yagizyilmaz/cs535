from flask import Flask, render_template, url_for, flash, redirect
from forms import RegistrationForm, ConnectForm, SendFileForm
import Sender
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
sender = None
connected = False





@app.route("/home", methods=['GET', 'POST'])
def home():
    if connected:
        form = SendFileForm()
        if form.validate_on_submit():
            if os.path.exists(form.filepath.data):
                sender.send_file(form.filepath.data)
                flash(f'Sending the file: {form.filepath.data}', 'success')
            else:
                flash(f"File doesn't exist: {form.filepath.data}", 'danger')

        return render_template('home.html', form=form)
    else:
        form = ConnectForm()
        return render_template('login.html', title='Login', form=form)

@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        flash(f'Account created for {form.username.data}', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)

@app.route("/", methods=['GET', 'POST'])
@app.route("/connect", methods=['GET', 'POST'])
def login():
    global sender, connected
    if not connected:
        form = ConnectForm()
        if form.validate_on_submit():
            sender = Sender.Sender(form.ip_addr.data)
            # if form.email.data == 'admin@blog.com' and form.password.data == 'password':
            flash(f'You have been connected to CNC: {form.ip_addr.data}!', 'success')
            connected = True
            return redirect(url_for('home'))
            # else:
            #     flash('Login Unsuccessful. Please check username and password', 'danger')
        return render_template('login.html', title='Login', form=form)
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
