from flask_wtf import FlaskForm
from wtforms import SelectField
from wtforms.validators import DataRequired

class select_user(FlaskForm):
    username = SelectField('User', validators=[DataRequired()])
