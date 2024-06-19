from flask import Blueprint

#API Blueprint 
bp = Blueprint('api', __name__)

from app.api import user_view

