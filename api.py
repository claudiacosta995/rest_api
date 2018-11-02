from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
app = Flask(__name__)
TOKEN = None
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'

db = SQLAlchemy(app)

class User(db.Model):
    """Class Model for User
    
    Arguments:
        db {database itself} -- this is te object representing our database instanse
    """

    __tablename__ = "user_table"
    username = db.Column(db.String(50), primary_key=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    occurences = db.relationship('Occurences', backref='author')

class Occurences( db.Model):
    __tablename__ = "occurences"
    identifier = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.String(50), db.ForeignKey('user_table.username'))

    description = db.Column(db.String(120))
    category = db.Column(db.String(50))
    latitude = db.Column(db.String(120))
    longitude= db.Column(db.String(120))
    date_create = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    date_update = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    state = db.Column(db.String, default = "Por Validar")


db.create_all()
def token_required(f):
    """
        Decorator for verify the authentication
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None


        token = TOKEN 

        if not token:
            return jsonify({'message' : 'Token is missing! '}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


#API PART
@app.route("/occurrencies", methods=["GET", "POST"])
@token_required
def get_and_post(current_user):
    """
        This function is called when accessing /occurrencies
        Can be accessed by two methods:
            - Get - Return json data type with all occurrencies
            - Post - Insert a occurrence in the database
    """

    data = jwt.decode(TOKEN, app.config['SECRET_KEY'])
    current_user = User.query.filter_by(username=data['username']).first()
    if request.method == 'POST':
        attributes_list = ['category', 'description', 'latitude', 'longitude']

        for attrs in attributes_list:
            try:
                request.form[attrs]
            except:
                return jsonify({"message": "Keyerror: {} not found.".format(attrs)}), 404
        
        occurence = Occurences()
            
        occurence.author_id = data['username']
        occurence.description = request.form['description']
        
        category = request.form['category'].lower()
        allowed_categories = ['construction', 'special_event', 'incident', 'weather_condition', 'road_condition']

        if category not in allowed_categories:
            return jsonify({"Error": "category '{}' not allowed".format(category)}), 401
        occurence.category = category
        
        occurence.latitude = request.form['latitude']
        occurence.longitude = request.form['longitude']

        db.session.add(occurence)
        db.session.commit()
        return jsonify({"message": "Occurence created"}), 201
        
    else:
        try:
            occurences = Occurences.query.all()
        except:
            return jsonify({"error":"Occurences not found"}), 404
        output = []
        for occurence in occurences:
            tmp = {}
            tmp['id'] = occurence.identifier

            tmp['author'] = occurence.author_id
            tmp['category'] = occurence.category
            tmp['description'] = occurence.description
            tmp['latitude'] = occurence.latitude
            tmp['longitude'] = occurence.longitude
            tmp['state'] = occurence.state
            tmp['date_create'] = occurence.date_create
            tmp['date_update'] = occurence.date_update
            output.append(tmp)
        return jsonify({"Occurrences": output})

@app.route("/occurrencies/author/<author>", methods=["GET"])
@token_required
def get_occurence_by_author(current_user, author):
    """
        This funcion is called when accessed /occurrencies/author/(some author)
        Returns: Json dataset with the occurrences of a given author name, if not exists return nothing
    """

    try:
        data = Occurences.query.filter_by(author_id=author)
    except:
        return jsonify({"error":"No occurencies found."}), 404
    output = []
    for occurence in data:
        tmp = {}
        tmp['id'] = occurence.identifier

        tmp['author'] = occurence.author_id
        tmp['category'] = occurence.category
        tmp['description'] = occurence.description
        tmp['latitude'] = occurence.latitude
        tmp['longitude'] = occurence.longitude
        tmp['state'] = occurence.state
        tmp['date_create'] = occurence.date_create
        tmp['date_update'] = occurence.date_update
        output.append(tmp)
    return jsonify({"Occurencies for {}".format(author): output})




@app.route("/occurrencies/category/<_category>", methods=["GET"])
@token_required
def get_occurence_by_category(current_user, _category):
    """
        This funcion is called when accessed /occurrencies/category/(some category)
        Returns: Json dataset with the occurrences of a given category name, if not exists return nothing
    """
    try:
        data = Occurences.query.filter_by(category=_category)
    except:
        return jsonify({"error":"No occurencies found."}), 404
    output = []
    for occurence in data:
        tmp = {}
        tmp['id'] = occurence.identifier

        tmp['author'] = occurence.author_id
        
        tmp['category'] = occurence.category
        tmp['description'] = occurence.description
        tmp['latitude'] = occurence.latitude
        tmp['longitude'] = occurence.longitude
        tmp['state'] = occurence.state
        tmp['date_create'] = occurence.date_create
        tmp['date_update'] = occurence.date_update
        output.append(tmp)
    return jsonify({"Occurencies for category {}".format(_category): output})

@app.route("/occurrencies/<_id>", methods=["PUT"])
@token_required
def update(current_user, _id):
    """
        This function is called when acessing /occurrencies/(some id) and updates a occurence by id to validado or resolvido.
            - validado (can only be updated by admin)
            - resolvido (can only be updated by the author of the occurrency)
        
    """

    try:
        state = request.form['state']
    except:
        return jsonify({"error": "Keyerror: state not found."}), 404

    if state == "validado":
        if current_user.admin is True:
            occurence = Occurences.query.filter_by(identifier=_id).first()
            occurence.state = "validado"
            occurence.date_update = datetime.datetime.utcnow()
            db.session.commit()
            return jsonify({"message": "Occurence updated."})
        else: 
            return jsonify({"error":"No permission, you need to be admin."})
    elif state == "resolvido":
        
        occurence = Occurences.query.filter_by(identifier=_id).first()
        if current_user.username == occurence.author_id:
            occurence.state = "resolvido"
            
            db.session.commit()
            return jsonify({"message": "Occurence updated."})

        else:
            return jsonify({"error": "No permission. You are not the author of this occurence."})

    else:
        return jsonify({"error": "Value error for state column."})
    


#USERS PART
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    """
        This function is called when acessing /user and returns all users presents in the database
    """

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<username>', methods=['GET'])
@token_required
def get_one_user(current_user, username):
    """
        This function is called when acessing /user/(some username) and gets the information about the username passed in the url.
    """

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['username'] = user.username
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
def create_user():
    """
        This function is called when acessing /user and this cretes a user. The first user inserted in the database will be admin. Others will not.
    """

    admin_condition = False
    if len(User.query.all()) == 0:
        admin_condition = True
    try:
        request.form["username"]
    except:
        return jsonify({"message": "Keyerror: username not found."}), 404
    try: 
        request.form["password"]
    except:
        return jsonify({"message": "Keyerror: password not found."}), 404
    
    hashed_password = generate_password_hash(request.form['password'], method='sha256')
    try:
        new_user = User(username=request.form["username"], password=hashed_password, admin=admin_condition)
    except:
        return jsonify({"message":"User already registered."}), 44

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'}), 200

    

@app.route('/user/<username>', methods=['PUT'])
@token_required
def promote_user(current_user, username):
    """
        This function is called when aceessing /user/(username) and this updates the a user to admin. Needs to be admin to use this function
    """

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/login', methods=["GET"])
def login():
    """
        This function does the login part
    """

    global TOKEN
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({"message":"Wrong Credentials."})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'username' : user.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'])
        TOKEN = token
        return jsonify({'message':"Login Accepted"})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})







if __name__ == '__main__':
    app.run(debug=True)