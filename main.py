from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
from flask import Flask, render_template, redirect, url_for, flash,request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from datetime import date

from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm,LoginForm,CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="postlar")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    commentlar = db.relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


    postlar = db.relationship("BlogPost", back_populates="author")

    commentlar= db.relationship("Comment", back_populates="comment_author")


#Çocuk nesnede genelde

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="commentlar")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="commentlar")
    text = db.Column(db.Text, nullable=False)
# #Line below only required once, when creating DB.









gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)






with app.app_context():
    db.create_all()


class User_login:
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id






@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


i=0
@app.route('/',methods=["GET","POST"])
def get_all_posts():
    posts = BlogPost.query.all()
    global i
    if current_user.is_authenticated:
        if current_user.id>=0:
            i=current_user.id
    return render_template("index.html", all_posts=posts,i=i)


@app.route('/register',methods=["POST","GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = request.form['name']
        email = request.form['email']
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        with app.app_context():
            new_user = User(email=email,
                            password=hash_and_salted_password,
                            name=name)
            db.session.add(new_user)
            db.session.commit()
        return redirect(url_for('get_all_posts'))

    return render_template("register.html",form=form)





@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form['email']
        password_text = request.form['password']
        user = User.query.filter_by(email=email).first()
        print(user)
        if user and check_password_hash(pwhash=user.password, password=password_text):
            login_user(user)
            return redirect(url_for("get_all_posts"))
        elif user and check_password_hash(pwhash=user.password, password=password_text) == False:
            flash("This Password Not Exist")
        else:
            flash("This Email Not Exist")


    return render_template("login.html",form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

@app.route("/post/<int:post_id>",methods=["GET","POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form=CommentForm()
    all_comments = db.session.query(Comment).all()





    if form.validate_on_submit():
        with app.app_context():
            if current_user.is_authenticated:

                comments= Comment(text=form.body.data,
                                  author_id=requested_post.author.id,
                                  post_id=post_id)
                db.session.add(comments)
                db.session.commit()
            else:
                flash(category="error",message="Please Firstly Register And Login")
                return redirect(url_for("register"))
    return render_template("post.html", post=requested_post,form=form,comments=all_comments,posta_id=post_id)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=["GET","POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        with app.app_context():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        with app.app_context():
            db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,current_user=current_user.id)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    with app.app_context():
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True,port=5000)
