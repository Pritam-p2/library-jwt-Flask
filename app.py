from flask import Flask,request,jsonify,make_response
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash, check_password_hash  
import jwt
import datetime
from functools import wraps 



app = Flask(__name__) 
 
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'

db = SQLAlchemy(app) 
app.app_context().push() 
class User(db.Model): 
    id = db.Column(db.Integer, primary_key=True) 
    public_id = db.Column(db.String(50), unique=True) 
    name = db.Column(db.String(50)) 
    password = db.Column(db.String(80)) 
    type = db.Column(db.String(50))
    admin = db.Column(db.Boolean,default= False) 
    book_borrowed = db.relationship('BookBorrow', backref='book_borrowed', lazy=True) 
    borrowed_user = db.relationship('BookBorrow', backref='borrowed_user', lazy=True) 

class Book(db.Model): 
    id = db.Column(db.Integer, primary_key=True) 
    title = db.Column(db.String(50)) 
    author = db.Column(db.String(50)) 
    category = db.Column(db.String(50)) 
    borrowed_book = db.relationship('BookBorrow', backref='borrowed_book', lazy=True)  

class BookBorrow(db.Model):
    id =  db.Column(db.Integer, primary_key=True) 
    book_id = db.Column(db.Integer(),db.ForeignKey('book.id'))
    user_id = db.Column(db.Integer(),db.ForeignKey('user.id'))


def token_required(f): 
    @wraps(f) 
    def decorated(*args, **kwargs): 
        token = None 
 
        if 'x-access-token' in request.headers: 
            token = request.headers['x-access-token'] 
 
        if not token: 
            return jsonify({'message' : 'Token is missing!'}), 401 
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256']) 
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401 
        return f(current_user, *args, **kwargs) 

    return decorated 

# create admin,no token used              #checked
@app.route('/admin',methods=['POST'])
def create_admin():
    data = request.get_json()
    x=data['name']
    hashed_password = generate_password_hash(data['password'],method='sha256')
    new_admin=User(public_id=data['public_id'],name=data['name'],password=hashed_password,type=data['type'],admin=True)
    db.session.add(new_admin)
    db.session.commit()
    return jsonify({'message': f'new admin {x} added'})


# admin view all users         checked
@app.route('/user',methods = ['GET'])
@token_required
def get_all_user(current_user):
    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function'})
    users = User.query.all()
    output = []
    for user in users:  
        user_data = {}
        user_data['public_id']= user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        user_data['type'] = user.type
        output.append(user_data)
    return jsonify({'users':output})
    
# admin view user by public_id          checked
@app.route('/user/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found!'})
    user_data={}
    user_data['public_id']= user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    user_data['admin'] = user.admin
    return jsonify({'user': user_data})
 

# admin creates user            checked
@app.route('/user',methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function'})
    data = request.get_json()
    x=data['name']
    hashed_password = generate_password_hash(data['password'],method='sha256')
    new_user=User(public_id=data['public_id'],name=data['name'],password=hashed_password,type=data['type'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': f'new user {x} added'})

# admin updates users by public_id            checked
@app.route('/user/<public_id>',methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function'})
    user = User.query.filter_by(public_id= public_id).first()
    if not user:
        return jsonify({'message':'No user found!'})
    data = request.get_json() 
    user.name=data['name']
    x= data['name']
    user.type=data['type']
    user.password = data['password']
    user.public_id=data['public_id']        
    db.session.commit()
    return jsonify({'message':f'user updated for {x}'})

# user delete by admin                  checked
@app.route('/user/<public_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    if not current_user.admin:
        return jsonify({'message':'Cannot perform that function'})
    user = User.query.filter_by(public_id= public_id).first()
    if not user:
        return jsonify({'message':'No user found!'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message':"the user has been deleted!"})
     
# user login        checked
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'}) 
    user = User.query.filter_by(name= auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password,auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY']) 
        return jsonify({'token': token })
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


# active users and admin can view all books        checked
@app.route('/books', methods=['GET']) 
@token_required
def get_all_books(current_user): 
    books = Book.query.all() 
    output = [] 
    for book in books: 
        book_data = {} 
        book_data['id'] = book.id 
        book_data[ 'title'] = book.title 
        book_data[ 'author'] = book.author 
        book_data[ 'category'] = book.category 
        output.append(book_data) 
    return jsonify({'message' : output}) 


# users search books by author                  checked
@app.route('/books/author/<book_author>', methods=['GET']) 
@token_required   
def get_book_by_author(current_user,book_author): 
    books_by_author = Book.query.filter_by(author=book_author).all()
    if books_by_author !=[]:
        output=[]
        for book in books_by_author:
            book_data = {} 
            book_data['id'] = book.id 
            book_data[ 'title'] = book.title 
            book_data[ 'author'] = book.author 
            book_data[ 'category'] = book.category 
            output.append(book_data)
        return jsonify(output)
    else:
        return jsonify({"message":"books not found with this author"})


# users search books by category                    checked
@app.route('/books/category/<book_category>', methods=['GET']) 
@token_required   
def get_book_by_category(current_user,book_category): 
    books_by_title = Book.query.filter_by(category=book_category).all()
    if books_by_title !=[]:
        output=[]
        for book in books_by_title:
            book_data = {} 
            book_data['id'] = book.id 
            book_data[ 'title'] = book.title 
            book_data[ 'author'] = book.author 
            book_data[ 'category'] = book.category 
            output.append(book_data)
        return jsonify(output)
    else:
        return jsonify({"message":"books not found with under this category"})



# users can search books by title                   checked
@app.route('/books/title/<book_title>', methods=['GET']) 
@token_required   
def get_book_by_title(current_user,book_title): 
    books_by_title = Book.query.filter_by(title=book_title).first()
    if books_by_title !=[]:
        book_data = {} 
        book_data['id'] = books_by_title.id 
        book_data[ 'title'] = books_by_title.title 
        book_data[ 'author'] = books_by_title.author 
        book_data[ 'category'] = books_by_title.category 
        return jsonify(book_data)
    else:
        return jsonify({"message":"book not found with this title"})
    




# admin can add a book             checked
@app.route('/books', methods=['POST']) 
@token_required 
def add_book(current_user):
    try: 
        if current_user.admin:
            data = request.get_json()    
            new_book = Book( title=data['title'], author=data['author'],category=data['category']) 
            db.session.add(new_book) 
            db.session.commit() 
            return jsonify({'message' : "New book added!"}) 
    except:
        return jsonify({'message' : "Something went wrong!"}) 




# admin can delete a book                   checked
@app.route('/books/<book_id>', methods=[ 'DELETE']) 
@token_required 
def delete_book(current_user, book_id):
    try:
        if current_user.admin:
            book = Book.query.filter_by(id=book_id).first() 
            if not book: 
                return jsonify({'message' : 'Book not found with this id!'}) 
            db.session.delete(book) 
            db.session.commit() 
            
    except:  
        return jsonify({'message' : 'something went wrong!'})
    return jsonify({'message' : 'Book deleted!'})   


# borrow book
@app.route('/books/<book_id>', methods=['GET'])
@token_required
def borrow_book(current_user,book_id):
    data = request.get_json()    
    book = Book.query.filter_by(id=book_id).first()
    if not book:
        return jsonify({"message":"book not available"})
    borrow = BookBorrow( book_id=book_id, user_id=current_user.id) 
    db.session.add(borrow) 
    db.session.commit() 
    return jsonify({"message":"order complete"})

# admin view all orders
@app.route('/books/orders', methods=['GET'])
@token_required
def book_orders(current_user):
    try:
        if current_user.admin:   
            books = BookBorrow.query.all()
            output=[]
            for book in books:
                a={}
                a['id']=book.id
                a['book_id']=book.book_id
                a['user_id']=book.user_id
            output.append(a)
            return jsonify(output)
    except:
        return({"message":"something went wrong!"})


if __name__== '__main__':
    app.run(debug=True)    