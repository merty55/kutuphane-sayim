import os
import io
from functools import wraps
from flask import Flask, render_template, request, send_file, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
import pandas as pd

app = Flask(__name__)
app.config['SECRET_KEY'] = 'bafra-kutuphane-sayim-2025'

# Neon.tech Online Veritabanı
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://neondb_owner:npg_5NZFl8WKfuJe@ep-noisy-rain-at1cl5ca.c-9.us-east-1.aws.neon.tech/neondb?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ===================== MODELLER =====================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kitap_barkod = db.Column(db.String(50), nullable=False)
    kitap_adi = db.Column(db.String(300), nullable=False)
    yazar = db.Column(db.String(200), nullable=True)
    bolumu = db.Column(db.String(200), nullable=True)
    statusu = db.Column(db.String(100), nullable=True)
    odunc_durumu = db.Column(db.String(200), nullable=True)
    created_by = db.Column(db.String(50), nullable=True)

class MasterBook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kitap_barkod = db.Column(db.String(50), unique=True, index=True)
    kitap_adi = db.Column(db.String(300))
    yazar = db.Column(db.String(200))
    bolumu = db.Column(db.String(200))
    statusu = db.Column(db.String(100))
    odunc_durumu = db.Column(db.String(200))

# ===================== FONKSİYONLAR =====================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = User.query.filter_by(username=request.form.get("username", "").strip()).first()
        if u and u.check_password(request.form.get("password", "")) and u.is_active:
            session['user_id'] = u.id
            return redirect(url_for('index'))
        error = "Hatalı giriş."
    return render_template("login.html", error=error)

@app.route("/")
@login_required
def index():
    user = User.query.get(session['user_id'])
    return render_template("index.html", current_username=user.username, is_admin=user.is_admin)

@app.route("/books")
@login_required
def books():
    books_data = Book.query.all()
    return render_template("books.html", books=books_data, total_books=len(books_data))

@app.route("/add", methods=["GET", "POST"])
@login_required
def add_book():
    error = success = warning = None
    if request.method == "POST":
        barcode = request.form.get("kitap_barkod", "").strip()
        action = request.form.get("action")
        
        # Artık doğrudan MasterBook tablosuna soruyoruz
        master = MasterBook.query.filter_by(kitap_barkod=barcode).first()
        
        if action == "lookup":
            if master:
                new_book = Book(kitap_barkod=barcode, kitap_adi=master.kitap_adi, yazar=master.yazar, bolumu=master.bolumu, statusu=master.statusu, odunc_durumu=master.odunc_durumu, created_by=User.query.get(session['user_id']).username)
                db.session.add(new_book)
                db.session.commit()
                success = "Kitap bulundu ve eklendi."
            else:
                error = "Kayıt bulunamadı, elle giriniz."
    return render_template("add_book.html", error=error, success=success)

@app.route("/upload-master", methods=["POST"])
@login_required
def upload_master():
    file = request.files.get("file")
    if file:
        df = pd.read_excel(file)
        MasterBook.query.delete()
        for _, row in df.iterrows():
            db.session.add(MasterBook(kitap_barkod=str(row["KitapBarkod"]).strip(), kitap_adi=str(row["KitapAdı"]).strip(), yazar=str(row["Yazar"]).strip(), bolumu=str(row["Bölümü"]).strip(), statusu=str(row["Statüsü"]).strip(), odunc_durumu=str(row["YerNumarası"]).strip()))
        db.session.commit()
        return redirect(url_for("index", upload_success="Tüm liste kalıcı olarak yüklendi."))
    return redirect(url_for("index", upload_error="Dosya seçilmedi."))

# ===================== BAŞLATMA =====================
with app.app_context():
    db.create_all()
    if not User.query.filter_by(is_admin=True).first():
        admin = User(username="admin", is_admin=True)
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)