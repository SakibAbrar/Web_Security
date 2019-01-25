from flask import Flask, request, jsonify, make_response
#sqlite3 database
from flask_sqlalchemy import SQLAlchemy

#unique id genrator module
import  uuid

#token er jonno
import jwt

#session token
import datetime

from functools import wraps

from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///home/sakib/PycharmProjects/untitled/user.db'


db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    moderator = db.Column(db.Boolean)
    email = db.Column(db.String(50))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key = True, unique=True)
    text = db.Column(db.String(50))
    approved = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


#token docoration an access
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return  jsonify({'message' : 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


#working
#get all users only for admin
@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Can not perform that function!'})

    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['admin'] = user.admin
        user_data['moderator'] = user.moderator
        user_data['email'] = user.email
        output.append(user_data);

    return jsonify({'users': output})

#working
#profile view
@app.route('/user/<public_id>/profile', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'No user found'})

    output = []
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['admin'] = user.admin
    user_data['moderator'] = user.moderator
    user_data['email'] = user.email
    output.append(user_data);

    return jsonify({'user' : output })

#working
#creating account
@app.route('/new_account', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method = 'sha256')
    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False, moderator=False, email=data['email'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New user created!'})


#working
#updating own profiles
@app.route('/user/<user_id>/profile/update', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    data = request.get_json()
    user = User.query.filter_by(public_id=user_id).first()
    #todo update not working
    if current_user.public_id is user.public_id:
        user.name = data['name']
        hashed_password = generate_password_hash(data['password'], method='sha256')
        user.password = hashed_password
        user.email = data['email']
        db.session.commit()
        return jsonify({'message' : 'Profile updated!'})


    return jsonify({'message' : 'Access denied!'})

#working
#user promotion to admin
@app.route('/user/makeadmin/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Can not perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    #if he is an admin he must be a moderator
    user.admin  = True
    user.moderator = True

    db.session.commit()
    return jsonify({'message' : 'The user has been promoted to admin'})


#working
#admin demotion to user by another admin
@app.route('/user/removeadmin/<public_id>', methods=['PUT'])
@token_required
def demote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Can not perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    #if he is an admin he must be a moderator
    user.admin  = False
    user.moderator = False

    db.session.commit()
    return jsonify({'message' : 'The user has been demoted to normal user'})


#working
#deleting an user
@app.route('/user/<public_id>/delete', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Can not perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found'})

    if current_user.public_id is public_id:
        return jsonify({'message' : 'Can not delete your own profile while being an admin'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted'})


#working
#login korbo with token
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


#working
#moderator upgradation
@app.route('/moderator/upgrade/<public_id>', methods=['PUT'])
@token_required
def make_moderator(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Access denied!'})

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({'message' : 'User not found!'})

    user.moderator = True;
    db.session.commit()

    return jsonify({'message' : 'User was upgraded to moderator'})

#working
#moderator degrade
@app.route('/moderator/downgrade/<public_id>', methods=['PUT'])
@token_required
def remove_moderator(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Access denied!'})

    user = User.query.filter_by(public_id = public_id).first()

    if not user:
        return jsonify({'message' : 'User not found!'})

    #if user is an admin he cant be removed as moderator
    if not user.admin:
        user.moderator = False;
    else:
        return jsonify({'message' : 'permission denied'})

    db.session.commit()

    return jsonify({'message' : 'User was downgraded to normal user'})



@app.route('/logout')
def logout():
    return ''
    #todo get a return type


############### post aka to-do database's route ##############


#just for admin to check on all  posts together. No one else can do that
@app.route('/allposts', methods=['GET'])
@token_required
def get_all_posts(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Access denied!'})

    output =[]

    posts = Post.query.all()

    for post in posts:
        post_data = {}
        post_data['id'] = post.id
        post_data['text'] = post.text
        post_data['approved'] = post.approved
        output.append(post_data)

    if not output:
        jsonify({'message' : 'No posts to show'})

    return jsonify({'Posts' : output})


#working
#just for users to check on all of their own posts together. only admin can view others'
@app.route('/user/<user_id>/posts', methods=['GET'])
@token_required
def get_user_posts(current_user, user_id):

    output =[]

    if not current_user.admin:
        if not current_user.user_id is user_id:
            return jsonify({'message' : 'Access denied!'})

    posts = Post.query.filter_by(user_id=user_id).all()

    for post in posts:
        post_data = {}
        post_data['id'] = post.id
        post_data['text'] = post.text
        post_data['approved'] = post.approved
        output.append(post_data)

    if not output:
        jsonify({'message' : 'No posts to show'})

    return jsonify({'Posts' : output})

#working
#just for users to check on all of their own posts together. only admin can view others'
@app.route('/user/<user_id>/post/<post_id>', methods=['GET'])
@token_required
def get_user_single_posts(current_user, user_id, post_id):

    output =[]

    post = Post.query.filter_by(user_id=user_id, id=post_id).first()

    if not current_user.admin:
        if not current_user.user_id is post.user_id:
            return jsonify({'message' : 'Access denied!'})


    post_data = {}
    post_data['id'] = post.id
    post_data['text'] = post.text
    post_data['approved'] = post.approved

    if not post_data:
        jsonify({'message' : 'No posts to show'})

    return jsonify({'Posts' : post_data})


#working
#see homepage like view. approved posts only. for admins too
@app.route('/posts', methods=['GET'])
@token_required
def get_approved_posts(current_user):

    output =[]

    posts = Post.query.filter_by(approved=True).all()

    for post in posts:

        post_data = {}
        post_data['id'] = post.id
        post_data['text'] = post.text
        post_data['approved'] = post.approved
        output.append(post_data)

    if not output:
        jsonify({'message' : 'No posts to show'})

    return jsonify({'Posts' : output})

#working
#unapproved post can be seen only by admins and moderators
@app.route('/posts/unapproved', methods=['GET'])
@token_required
def get_unapproved_posts(current_user):

    if not current_user.moderator:
        return jsonify({'message' : 'Access denied!'})

    output =[]

    posts = Post.query.filter_by(approved=False).all()

    for post in posts:

        post_data = {}
        post_data['id'] = post.id
        post_data['text'] = post.text
        post_data['approved'] = post.approved
        output.append(post_data)

    if not output:
        jsonify({'message' : 'No unapproved posts to show.'})

    return jsonify({'Posts' : output})


#to show any approved post to any logged-in user
@app.route('/post/<post_id>', methods=['GET'])
@token_required
def get_one_post(current_user, post_id):
    post = Post.query.filter_by(id=post_id, approved=True).first()

    if not post:
        return jsonify({'message' : 'No post found!'})

    post_data = {}
    post_data['id'] = post.id
    post_data['text'] = post.text
    post_data['approved'] = post.approved

    return jsonify({'post' : post_data})

#working
#post create kora jabe eta diye
@app.route('/post/new', methods=['POST'])
@token_required
def create_post(current_user):
    data = request.get_json()

    if not current_user.moderator:
        new_post = Post(text=data['text'], approved=False, user_id=current_user.public_id)
    else:
        new_post = Post(text=data['text'], approved=True, user_id=current_user.public_id)


    db.session.add(new_post)
    db.session.commit();
    return jsonify({'message' : 'New post added'})


#working
#approving posts
@app.route('/post/<post_id>/approve', methods=['PUT'])
@token_required
def approve_post(current_user, post_id):
    if current_user.moderator:
        post = Post.query.filter_by(id=post_id).first()
        if not post:
            return jsonify({'message': 'There is no such post!'})
        post.approved = True
        db.session.commit()
        return jsonify({'message' : 'The post has been approved!'})

    return jsonify({'message' : 'The request was not successful!'})


#working
#update korbo eta diye
@app.route('/post/<post_id>/update', methods=['PUT'])
@token_required
def update_post(current_user, post_id):
    data = request.get_json()
    post = []

    post = Post.query.filter_by(id=post_id, user_id=current_user.public_id).first()

    if current_user.moderator:
        post.approved = True
    else:
        post.approved = False


    if not post:
        return jsonify({'message' : 'No such post was found or access denied!'})


    post.text = data['text']
    db.session.commit()

    return jsonify({'message' : 'The post has been successfully updated!'})


#working
#deleting any post
@app.route('/post/<post_id>/delete', methods=['DELETE'])
@token_required
def delete_post(current_user, post_id):
    post = Post.query.filter_by(id=post_id).first()

    if not current_user.moderator:
        if not post.user_id is current_user.public_id:
            return jsonify({'message' : 'You are not authorized to delete post.'})

    if not post:
        return jsonify({'message' : 'No such post found!'})

    db.session.delete(post)
    db.session.commit()

    return jsonify({'message' : 'The post was successfully deleted!'})





if __name__ == '__main__':
    app.run(debug = True)


