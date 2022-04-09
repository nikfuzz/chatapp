from crypt import methods
from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO
from app_info import get_secret_key, get_users_instance
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = get_secret_key()
socketio = SocketIO(app)
bcrypt = Bcrypt(app)

@app.route('/')
def chats():
    if session and session['username']:
        users = get_users_instance()
        users = users.find({'username': {"$ne": session['username']}}, {'_id': 1, 'username': 1})
        return render_template('chats.html', users=users)
    return redirect('/login') 

@app.route('/conversation')
def sessions():
    print(request.args['receiver'])
    # todo: establish a socket
    if request.args['receiver']:
        return render_template('session.html', receiver=request.args['receiver'])
    redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # if we have submitted the registration form
    if request.method == 'POST':

        # if either username or password is blank return apt message
        if not request.form.get('username').strip():
            message = "Enter a username"
            return render_template('register.html', message=message)

        if not request.form.get('password').strip():
            message = "Enter a password"
            return render_template('register.html', message=message)

        Users = get_users_instance()

        # check if the username already exists
        username = request.form.get('username').strip()
        existing_user = Users.find_one({"username": username})

        if existing_user:
            message = "Username already exists"
            return render_template('register.html', message=message)

        # generate a hashed password
        password_hash = bcrypt.generate_password_hash(request.form.get('password').strip())

        # new user instance
        new_user = {
            "username": username,
            "password": password_hash
        }

        Users.insert_one(new_user)
        print("User registered: ", new_user)
        # once the user gets registered redirect to home
        # todo: redirect to login success page
        return redirect('/')


    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == "POST":
        
         # if either username or password is blank return apt message
        if not request.form.get('username'):
            message = "Enter a username"
            return render_template('login.html', message=message)

        if not request.form.get('password'):
            message = "Enter a password"
            return render_template('login.html', message=message)

        username = request.form.get('username')
        password = request.form.get('password')

        Users = get_users_instance()
        user_instance = Users.find_one({'username': username})

        print(user_instance)

        if not user_instance:
            message = "No such user"
            return render_template('login.html', message=message)

        if not bcrypt.check_password_hash(user_instance['password'], password):
            message = "incorrect password"
            return render_template('login.html', message=message)

        session['username'] = user_instance['username']

        return redirect('/')
        

    return render_template('login.html')

def messageReceived(methods=['GET', 'POST']):
    print('message was received!!!')

@socketio.on('my event')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    print('received my event: '+ str(json))
    socketio.emit('my response', json, callback=messageReceived)

if __name__ == '__main__':
    socketio.run(app, debug=True)