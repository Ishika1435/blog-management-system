from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify, session   #JSONIFY-Converts a Python dictionary to a valid JSON HTTP response. This is required because TinyMCE expects a JSON response.
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone 
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename                  #Prevents unsafe file names (like ../../etc/passwd).
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import os                                                       # Used for file path manipulations.
from bs4 import BeautifulSoup
import requests
import math
from dotenv import load_dotenv
load_dotenv()
import cloudinary
import cloudinary.uploader

cloudinary.config(
    cloud_name="dlsguyoe5",  # use yours from Cloudinary dashboard
    api_key="256972578483481",
    api_secret="6_BrW8aUJUeh"
)


#Create minimal app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db=SQLAlchemy(app)                                                  #For database
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'                      #Redirects users to the /login page if they try to access a protected page
app.secret_key = os.environ.get('SECRET_KEY')        # features like session[] won’t work securely if secret key not used, prevents data tampering by the user
migrate = Migrate(app,db)                                       #To modify data
UPLOAD_FOLDER = os.path.join('static', 'uploads')               #Creates folder if not already exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)                           #ensures you don’t get an error if the folder already exists.
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
REDIRECT_URI = os.environ.get('REDIRECT_URI')

#Class Blog - create columns for database

class Blog(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(100), nullable = False)
    description = db.Column(db.String(200))
    content = db.Column(db.Text, nullable = False) 
    views = db.Column(db.Integer, default = 0)
    cover_image = db.Column(db.String(120))
    author = db.Column(db.String(50), nullable = False) 
    date_posted = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(50), nullable = False, default = 'Others')
    read_time = db.Column(db.Integer)

    def __repr__(self):
        return f"{self.id} - {self.title}"          #How object is presented when printed


#Homepage - shows the blogs

@app.route("/", methods=['GET', 'POST'])
def home():
    category = request.args.get('category')

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        author = current_user.username
        content = request.form.get('content')
        category = request.form['category']

        if not content.strip() or content.strip() == '<p><br></p>':
            return "Content is empty!", 400

        # Fix image paths
        soup = BeautifulSoup(content, 'html.parser')
        for img in soup.find_all('img'):
            src = img.get('src', '')
            if src and not src.startswith('/'):
                img['src'] = '/' + src
        content = str(soup)

        # Read time calculation
        read_time = calculate_read_time(content)

        # Handle cover image
        cover_image = request.files.get('cover_image')
        image_filename = None
        if cover_image and allowed_file(cover_image.filename):
            filename = secure_filename(cover_image.filename)
            image_path = os.path.join(UPLOAD_FOLDER, filename)
            cover_image.save(image_path)
            image_filename = filename

        # Create and save blog
        blog = Blog(
            title=title,
            description=description,
            author=author,
            content=content,
            user_id=current_user.id,
            category=category,
            cover_image=image_filename,
            #catergories=category,  # <-- Check your model field name here!
            read_time=read_time
        )
        db.session.add(blog)
        db.session.commit()

    # Fetch blogs based on category filter
    if category:
        blogs = Blog.query.filter_by(category=category).order_by(Blog.date_posted.desc()).all()
    else:
        blogs = Blog.query.order_by(Blog.date_posted.desc()).all()

    categories = list(set([blog.category for blog in blogs if blog.category]))
    latest_blogs = Blog.query.order_by(Blog.date_posted.desc()).limit(6).all()
    popular_blogs = Blog.query.order_by(Blog.views.desc()).limit(6).all()

    return render_template(
        'index.html',
        selected_category=category,
        blogs=blogs,
        categories=categories,
        latest_blogs=latest_blogs,
        popular_blogs=popular_blogs
    )

#To check if the cover image type is allowed or not 
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS #checks if the file has a . and then spilts the name and then checks the ending part and if it is allowed or not

#Time

def calculate_read_time(content):
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()
    words = text.split()
    word_count = len(words)
    read_time = max(1, math.ceil(word_count / 200))
    print(f"[DEBUG] Word count: {word_count}, Read time: {read_time}")
    return read_time



#Category page 

@app.route("/category")
def category():
    category = request.args.get('category')
    if category:                                                             #If category is selected - then the blogs of that catogory are shown
        category_blogs = Blog.query.filter_by(category=category).order_by(Blog.date_posted.desc()).all()
    else:
        category_blogs = Blog.query.order_by(Blog.date_posted.desc()).all()
    print("Matching blogs:", category_blogs)
    return render_template("category.html", selected_category = category, blogs=category_blogs)

#Postpage - to create a new post

@app.route("/product")
@login_required
def products():
    return render_template('post.html')


#Readpage - when the user clicks to read a blog

@app.route("/read/<int:id>", methods = ['GET', 'POST'])         #It takes the parameter of blog id to find the blog
def read(id):
    blog = Blog.query.get_or_404(id)
    blog.views = (blog.views or 0) + 1
    db.session.commit()

    if request.method == "POST":
        if not current_user.is_authenticated:               # Current user must be logged in to comment, if not msg is flashed
            flash("You must be logged in to comment")
            return redirect(url_for('login'))
        
        content = request.form['comment']
        comment= Comment(content=content, user_id=current_user.id,blog_id=blog.id)
        db.session.add(comment)
        db.session.commit()
        flash('Comment added!')

    #Pagination for comment - 5 per page

    page=request.args.get('page',1,type=int)        #gets the page number from the URL query, or defaults to 1 if it's not provided.

    #Starts query on comment model - only fetches comments that match the current blog post - sorts comment by recently posted - paginate 5 comments per page and gives page number from the url

    comments = Comment.query.filter_by(blog_id=blog.id)\
                .order_by(Comment.date_posted.desc())\
                .paginate(page=page, per_page=5)
    
    return render_template('read.html', blog=blog, comments=comments)

@app.route('/latest')
def latest():
    page=request.args.get('page',1,type=int)         #gets the page number from the URL query, or defaults to 1 if it's not provided.
    latest_blogs = Blog.query.order_by(Blog.date_posted.desc()).paginate(page=page, per_page=12)
    return render_template('latest.html', latest_blogs=latest_blogs)

@app.route('/popular')
def popular():
    page=request.args.get('page',1,type=int) 
    popular_blogs = Blog.query.order_by(Blog.views.desc()).paginate(page=page, per_page=12)
    return render_template('popular.html', popular_blogs=popular_blogs)



# Class User - creates a table for user info

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(150), nullable = True)
    email = db.Column(db.String(150), unique = True, nullable = False)
    password_hash =db.Column(db.String(256), nullable=True)
    google_id = db.Column(db.String(255), unique=True)
    profile_pic = db.Column(db.Text,  nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


#This tells Flask-Login how to retrieve a user from the database using their ID when they're logged in.

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Search - function
@app.route('/search' ) 
def search():
    q = request.args.get('query')   #read from query string
    
    if q:
        #search by title, author, category
        results = Blog.query.filter((Blog.title.ilike(f'%{q}%'))|(Blog.author.ilike(f'%{q}%'))|(Blog.category.ilike(f'%{q}%'))).order_by(Blog.date_posted.desc()).all()
    else:
        results = Blog.query.order_by(Blog.date_posted.desc()).all()

    return render_template('index.html', blogs=results)

# Register function - for signup 
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return redirect(url_for('signup'))

        #Check if user already exists 
        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose a different one")
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash("Email already exists. Please use a different one")
            return redirect(url_for('register'))
        
        #token = generate_verification_token(email)
        #verify_url = url_for('verify_email', token=token, _external=True)
        #html = render_template('verify_email.html', verify_url=verify_url)
        #subject = 'Please verify email'
        
        #To create and save new user
        new_user=User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash('Registeration successful! You are logged in.')
        return redirect(url_for('home'))
    
    return render_template("register.html")

#step 1 - redirect to google
@app.route("/auth/google")
def login_with_google():
        google_url = (
        "https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid%20email%20profile"
        f"&prompt=select_account"
        )
        return redirect(google_url)

#step 2 - callback from google
@app.route("/auth/callback")
def google_callback():
    code = request.args.get('code')  # use args not arg

    # Step 1: Exchange code for access token
    token_resp = requests.post("https://oauth2.googleapis.com/token", data={
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }).json()

    # Step 2: Get user info from Google
    user_info = requests.get("https://www.googleapis.com/oauth2/v2/userinfo", headers={
        "Authorization": f"Bearer {token_resp['access_token']}"
    }).json()

    google_id = user_info["id"]
    name = user_info["name"]
    email = user_info["email"]
    picture = user_info["picture"]

    # Step 3: Check if user exists in the database
    user = User.query.filter_by(google_id=google_id).first()

    # Step 4: If not, add them
    if not user:
        user = User(username=name, email=email, google_id=google_id, profile_pic=picture)
        db.session.add(user)
        db.session.commit()

    # Step 5: Store in session
    session["user"] = {"name": name, "email": email, "picture": picture}
    login_user(user)

    return redirect("/dashboard")

#DASH-BOARD 
@app.route('/dashboard')
def dashboard():
    if "user" not in session:
        return redirect("/")

    user = session["user"]
    return render_template('dashboard.html', user=user)


#If user has already signed up - then login 

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        username=request.form['username']
        password=request.form['password']

        user = User.query.filter_by(username=username).first()          #gets the first user from the database whose username matches the one provided.

        if user and user.check_password(password):              #Checks username and password for login 
            login_user(user)
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')  

# To edit a blog - only for author

@app.route('/edit/<int:id>', methods=['GET','POST'])  
@login_required
def edit(id):
    blog = Blog.query.get_or_404(id)
    
    if blog.user_id != current_user.id:
        flash('You are not authorized to edit this post.')
        return redirect(url_for('my_blogs'))
    
    if request.method == 'POST':
        blog.title = request.form['title']
        blog.description = request.form['description']
        blog.content = request.form['content']
        image = request.files.get('cover_image')  # ✅ use separate variable

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_path = os.path.join(UPLOAD_FOLDER, filename)
            image.save(image_path)  # ✅ Save the image to disk
            blog.cover_image = filename  # ✅ Save just the filename to the database

        
        # Recalculate reading time
        blog.read_time = calculate_read_time(blog.content)

        db.session.commit()
        flash('Post updated successfully!')
        return redirect(url_for('my_blogs'))
    
    return render_template('edit.html', blog=blog)


#To delete a blog - restricted to author only

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    blog = Blog.query.get_or_404(id)
    if blog.user_id != current_user.id:
        flash('You are not authorized to delete this post.')
        return redirect(url_for('my_blogs'))
    
    db.session.delete(blog)
    db.session.commit()
    flash('Post Deleted Sucessfully.')
    return redirect(url_for('my_blogs'))

#Page having all the blogs posted by the user 

@app.route('/myblogs')
@login_required
def my_blogs():
    user_blogs = Blog.query.filter_by(user_id=current_user.id).order_by(Blog.date_posted.desc()).all()
    return render_template('myblogs.html', user_blogs=user_blogs)

#Function to logout - uses the function - logout_user()

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('home'))

@app.route('/profile/update', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        file = request.files.get('profile_picture')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)                            #makes the name secure
            file_path = os.path.join('static/profile_pics', filename)               #joins the file path - to profile pics in the static 
            file.save(file_path)                                                 #Saves the image in that path
            current_user.profile_pic = filename                                  #sets the user profile_pic to the file
            db.session.commit()                                                         #and commit it in the database
            flash("Profile picture updated!", "success")
            return redirect(url_for('user_info', username=current_user.username))

    return render_template('update_pfp.html')
#Database table for comment 

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable='False')     #Foreign key is a column in one table that creates a relationship with another table by referring to the primary key of that table
    blog_id = db.Column(db.Integer, db.ForeignKey('blog.id'), nullable='False')

    user = db.relationship('User', backref='comments')
    blog = db.relationship('Blog', backref='comments')

#To delete a comment - only restricted to the user who posted the comment 

@app.route('/delete_comment/<int:comment_id>', methods = ['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    if comment.user_id!=current_user.id:
        abort(403)                                      #Immediately stops the request and returns a 403 Forbidden error to the user.

    db.session.delete(comment)
    db.session.commit()
    flash("Comment Deleted!")
    return redirect(url_for('read', id=comment.blog_id))

#Page showing information of particular user - from comment 

@app.route('/user_info/<string:username>')
def user_info(username):
    page = request.args.get('page', 1, type=int)
    user=User.query.filter_by(username=username).first_or_404()
    blogs=Blog.query.filter_by(user_id = user.id).order_by(Blog.date_posted.desc()).paginate(page=page, per_page=12)
    return render_template('user_profile.html', user=user, blogs = blogs)


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#handling image uploads from TinyMCE and returning the image URL back to TinyMCE so it can insert it into the content.
@app.route('/upload_image',methods = ['POST'])
def upload_image():
    if 'file' not in request.files:                                         #Checks if request contains a file
        return jsonify({'error': 'No file uploaded'}), 400                      #If not returns a json error - 404=Bad request
    
    file = request.files['file']                                            #Extracts the uploaded file.
    if file.filename=='':                                               #If filename is blank (user uploaded nothing), again returns an error.
        return jsonify({'error': 'Empty filename'}),400
    
    if file and allowed_file(file.filename):
        try:
            upload_result = cloudinary.uploader.upload(file)
            image_url = upload_result['secure_url']
            return jsonify({'location': image_url})  # TinyMCE uses "location"
        except Exception as e:
            print("Upload failed:", e)
            return jsonify({'error': 'Upload failed'}), 500

    return jsonify({'error': 'Invalid file type'}), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)






