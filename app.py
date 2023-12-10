import json

from flask import Flask, request, make_response, session
import bcrypt
from sqlalchemy.exc import IntegrityError
from config import app, db
from database.models import User
import pandas as pd


# route for sign up
@app.route("/")
def index():
    return make_response("This is Production Server")


@app.route('/signup', methods=["POST"])
def signup():
    if request.method == "POST":
        rq = request.get_json()
        username = rq['username']
        password = rq['password']

        # password hashing/salting using bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        new_user = User(
            username=username,
            password=hashed_password.decode('utf-8'),
        )
        if new_user:
            try:

                db.session.add(new_user)
                db.session.commit()
                session['user_id'] = new_user.id
                print(new_user.__dict__)
                return make_response(new_user.to_dict(), 201)
            except IntegrityError:
                return {'errors': ['Username already exists. Please try again with different username.']}, 401
        else:
            return {'errors': ['Invalid username or password. Please try again.']}, 401


# route for login
@app.route('/login', methods=["POST"])
def login():
    if request.method == "POST":
        rq = request.get_json()
        # find the user with the corresponding username
        user = User.query.filter(User.username.like(f"%{rq['username']}%")).first()

        # check the password with the hashed password in our database
        if user and bcrypt.checkpw(rq['password'].encode('utf-8'), user.password.encode('utf-8')):
            session['user_id'] = user.id
            return make_response(user.to_dict(), 200)
        else:
            return {'errors': ['Invalid username or password. Please try again.']}, 401


# route for logout
@app.route('/logout', methods=["DELETE"])
def logout():
    if request.method == "DELETE":
        session['user_id'] = None
        response = make_response('', 204)
        return response


# route for authorization
@app.route('/authorize')
def authorize():
    user_id = session.get('user_id')
    if not user_id:
        return {'errors': 'You must be logged in to do that. Please log in or sign up.'}, 401
    else:
        user = User.query.filter(User.id == user_id).first()
        if user:
            return make_response(user.to_dict(), 200)


@app.route("/csv_analysis", methods=['POST'])
def csv_analysis():
    if request.method == 'POST':
        f = request.files['file']
        f.save("client_files/" + f.filename)

        df = pd.read_csv("client_files/" + f.filename)
        print(df.columns)
        print(type(df.columns))

        return make_response(json.dumps({
            "filename": f.filename,
            "columns": df.columns.tolist()
        }), 200)
    else:
        return {'error': "Error with Server"}


@app.route("/select_column", methods=['POST'])
def column_selected():
    if request.method == "POST":
        rq = request.get_json()
        #  operation

        return make_response("Selected Column is " + rq['column'])

        # find the user with the corresponding username


# run the server using this command: python app.py
if __name__ == '__main__':
    app.run(port=5555, debug=True)
