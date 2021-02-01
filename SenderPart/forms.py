from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


class ConnectForm(FlaskForm):
    ip_addr = StringField('CNC IP',
                        validators=[DataRequired()])
    submit = SubmitField('Login')


class SendFileForm(FlaskForm):
    filepath = StringField('Filepath to be sent:',
                        validators=[DataRequired()])
    submit = SubmitField('Send File')
