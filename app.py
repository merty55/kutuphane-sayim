import os
import csv
import io
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    url_for,
    session,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text, func
import pandas as pd

app = Flask(__name__)

# GÜVENLİK: Oturumlar için gizli anahtar (bunu kendine göre değiştirmen iyi olur)
app.config['SECRET_KEY'] = 'bafra-kutuphane-sayim-2025'

# Veritabanı ayarı (aynı klasörde kutuphane_v2.db oluşacak)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kutuphane_v2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---- GENEL LİSTE DOSYASI YOLU ----
MASTER_LIST_PATH = os.path.join(os.path.dirname(__file__), "genel_liste.csv")


# ===================== MODELLER =====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kitap_barkod = db.Column(db.String(50), unique=True, nullable=False)
    kitap_adi = db.Column(db.String(300), nullable=False)
    bolumu = db.Column(db.String(200), nullable=True)
    statusu = db.Column(db.String(100), nullable=True)
    odunc_durumu = db.Column(db.String(200), nullable=True)  # YerNumarası
    created_by = db.Column(db.String(50), nullable=True)     # EKLEYEN KULLANICI

    def __repr__(self):
        return f"<Book {self.kitap_barkod} - {self.kitap_adi}>"


# ===================== YARDIMCI FONKSİYONLAR =====================

def find_book_from_master(barcode: str):
    """
    Barkod okuyucudan gelen değerin ilk 12 hanesine göre
    genel_liste.csv içinde satır arar.
    Bulursa tüm alanları içeren bir dict döner, bulamazsa None.
    Alanlar:
      - KitapBarkod
      - KitapAdı
      - Bölümü
      - Statüsü
      - YerNumarası
    """
    if not barcode:
        return None

    code = barcode.strip()
    if len(code) >= 12:
        key = code[:12]
    else:
        key = code

    if not os.path.exists(MASTER_LIST_PATH):
        return None

    with open(MASTER_LIST_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_code = (row.get("KitapBarkod") or "").strip()
            if row_code == key:
                return {
                    "KitapBarkod": (row.get("KitapBarkod") or "").strip(),
                    "KitapAdı": (row.get("KitapAdı") or "").strip(),
                    "Bölümü": (row.get("Bölümü") or "").strip(),
                    "Statüsü": (row.get("Statüsü") or "").strip(),
                    "YerNumarası": (row.get("YerNumarası") or "").strip(),
                }

    return None


def get_current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return User.query.get(uid)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_admin:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


# ===================== KULLANICI GİRİŞ / ÇIKIŞ =====================

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            error = "Kullanıcı adı veya şifre hatalı."
        elif not user.is_active:
            error = "Bu kullanıcı pasif durumda. Lütfen yönetici ile iletişime geçin."
        else:
            session['user_id'] = user.id
            session['is_admin'] = bool(user.is_admin)
            return redirect(url_for('index'))

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))


# ===================== ŞİFRE DEĞİŞTİR =====================

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = get_current_user()
    error = None
    success = None

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        new_password2 = request.form.get("new_password2", "")

        if not user.check_password(current_password):
            error = "Mevcut şifrenizi yanlış girdiniz."
        elif not new_password or len(new_password) < 4:
            error = "Yeni şifre en az 4 karakter olmalıdır."
        elif new_password != new_password2:
            error = "Yeni şifre ile şifre tekrarı eşleşmiyor."
        else:
            user.set_password(new_password)
            db.session.commit()
            success = "Şifreniz başarıyla güncellendi."

    return render_template(
        "change_password.html",
        error=error,
        success=success,
        current_username=user.username if user else "",
    )


# ===================== KULLANICI YÖNETİMİ (ADMIN) =====================

@app.route("/users")
@login_required
@admin_required
def users():
    all_users = User.query.order_by(User.username).all()
    success = request.args.get("success")
    error = request.args.get("error")
    current_user = get_current_user()

    return render_template(
        "users.html",
        users=all_users,
        success=success,
        error=error,
        current_username=current_user.username if current_user else "",
    )


@app.route("/create-user", methods=["POST"])
@login_required
@admin_required
def create_user():
    username = request.form.get("new_username", "").strip()
    password = request.form.get("new_password", "").strip()
    is_admin = True if request.form.get("new_is_admin") == "on" else False

    if not username or not password:
        return redirect(url_for(
            "index",
            user_error="Kullanıcı adı ve şifre zorunludur.",
            user_success=""
        ))

    existing = User.query.filter_by(username=username).first()
    if existing:
        return redirect(url_for(
            "index",
            user_error="Bu kullanıcı adı zaten kayıtlı.",
            user_success=""
        ))

    new_user = User(username=username, is_admin=is_admin, is_active=True)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for(
        "index",
        user_success="Yeni kullanıcı başarıyla oluşturuldu.",
        user_error=""
    ))


@app.route("/toggle-user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def toggle_user(user_id):
    current_user = get_current_user()
    user = User.query.get_or_404(user_id)

    # Kendini pasif yapmana izin verme
    if user.id == current_user.id:
        return redirect(url_for(
            "users",
            error="Kendi hesabınızı pasif duruma alamazsınız.",
            success=""
        ))

    # Eğer pasife alınacak kullanıcı admin ise ve son admin ise, engelle
    if user.is_admin and user.is_active:
        admin_count = User.query.filter_by(is_admin=True, is_active=True).count()
        if admin_count <= 1:
            return redirect(url_for(
                "users",
                error="Sistemde en az bir aktif yönetici bulunmalıdır.",
                success=""
            ))

    user.is_active = not user.is_active
    db.session.commit()

    durum = "aktif edildi" if user.is_active else "pasife alındı"
    return redirect(url_for(
        "users",
        success=f"{user.username} kullanıcısı {durum}.",
        error=""
    ))


@app.route("/delete-user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    current_user = get_current_user()
    user = User.query.get_or_404(user_id)

    # Kendini silemezsin
    if user.id == current_user.id:
        return redirect(url_for(
            "users",
            error="Kendi hesabınızı silemezsiniz.",
            success=""
        ))

    # Son admin ise silme
    if user.is_admin:
        admin_count = User.query.filter_by(is_admin=True, is_active=True).count()
        if admin_count <= 1:
            return redirect(url_for(
                "users",
                error="Sistemde en az bir yönetici kalmalıdır. Bu kullanıcı silinemez.",
                success=""
            ))

    db.session.delete(user)
    db.session.commit()

    return redirect(url_for(
        "users",
        success=f"{user.username} kullanıcısı silindi.",
        error=""
    ))


# ===================== ANA SAYFA & DİĞER SAYFALAR =====================

@app.route("/")
@login_required
def index():
    user = get_current_user()
    is_admin = bool(user and user.is_admin)

    upload_success = request.args.get("upload_success")
    upload_error = request.args.get("upload_error")
    user_success = request.args.get("user_success")
    user_error = request.args.get("user_error")

    return render_template(
        "index.html",
        upload_success=upload_success,
        upload_error=upload_error,
        user_success=user_success,
        user_error=user_error,
        is_admin=is_admin,
        current_username=user.username if user else "",
    )


@app.route("/books")
@login_required
def books():
    all_books = Book.query.order_by(Book.id).all()

    # Kullanıcıya göre kaç kitap eklenmiş?
    raw_counts = (
        db.session.query(Book.created_by, func.count(Book.id))
        .group_by(Book.created_by)
        .all()
    )
    user_counts = []
    for username, count in raw_counts:
        user_counts.append({
            "username": username or "Belirtilmemiş",
            "count": count
        })

    return render_template(
        "books.html",
        books=all_books,
        success=None,
        error=None,
        user_counts=user_counts,
    )


@app.route("/add", methods=["GET", "POST"])
@login_required
def add_book():
    error = None
    success = None
    warning = None

    kitap_barkod = ""
    kitap_adi = ""
    bolumu = ""
    statusu = ""
    odunc_durumu = ""  # YerNumarası

    last_kitap_barkod = None
    last_kitap_adi = None
    last_bolumu = None
    last_statusu = None
    last_odunc_durumu = None

    total_books = Book.query.count()
    current_user = get_current_user()

    if request.method == "POST":
        action = request.form.get("action", "save")

        kitap_barkod = request.form.get("kitap_barkod", "").strip()
        kitap_adi = request.form.get("kitap_adi", "").strip()
        bolumu = request.form.get("bolumu", "").strip()
        statusu = request.form.get("statusu", "").strip()
        odunc_durumu = request.form.get("odunc_durumu", "").strip()

        if action == "lookup":
            if not kitap_barkod:
                error = "Önce KitapBarkod alanını doldurmalısın."
                return render_template(
                    "add_book.html",
                    error=error,
                    success=success,
                    warning=warning,
                    kitap_barkod=kitap_barkod,
                    kitap_adi=kitap_adi,
                    bolumu=bolumu,
                    statusu=statusu,
                    odunc_durumu=odunc_durumu,
                    last_kitap_barkod=last_kitap_barkod,
                    last_kitap_adi=last_kitap_adi,
                    last_bolumu=last_bolumu,
                    last_statusu=last_statusu,
                    last_odunc_durumu=last_odunc_durumu,
                    total_books=total_books,
                )

            existing = Book.query.filter_by(kitap_barkod=kitap_barkod).first()
            if existing:
                error = "Bu KitapBarkod zaten kayıtlı!"
                warning = "Kitabı kontrol ediniz."

                kitap_adi = existing.kitap_adi
                bolumu = existing.bolumu or ""
                statusu = existing.statusu or ""
                odunc_durumu = existing.odunc_durumu or ""

                last_kitap_barkod = existing.kitap_barkod
                last_kitap_adi = existing.kitap_adi
                last_bolumu = existing.bolumu
                last_statusu = existing.statusu
                last_odunc_durumu = existing.odunc_durumu

                return render_template(
                    "add_book.html",
                    error=error,
                    success=success,
                    warning=warning,
                    kitap_barkod=kitap_barkod,
                    kitap_adi=kitap_adi,
                    bolumu=bolumu,
                    statusu=statusu,
                    odunc_durumu=odunc_durumu,
                    last_kitap_barkod=last_kitap_barkod,
                    last_kitap_adi=last_kitap_adi,
                    last_bolumu=last_bolumu,
                    last_statusu=last_statusu,
                    last_odunc_durumu=last_odunc_durumu,
                    total_books=total_books,
                )

            info = find_book_from_master(kitap_barkod)
            if not info:
                error = "Genel listede bu KitapBarkod'a karşılık gelen kayıt bulunamadı. Alanları elle doldurup 'Kaydet' diyebilirsin."
                return render_template(
                    "add_book.html",
                    error=error,
                    success=success,
                    warning=warning,
                    kitap_barkod=kitap_barkod,
                    kitap_adi=kitap_adi,
                    bolumu=bolumu,
                    statusu=statusu,
                    odunc_durumu=odunc_durumu,
                    last_kitap_barkod=last_kitap_barkod,
                    last_kitap_adi=last_kitap_adi,
                    last_bolumu=last_bolumu,
                    last_statusu=last_statusu,
                    last_odunc_durumu=last_odunc_durumu,
                    total_books=total_books,
                )

            kitap_adi = info.get("KitapAdı", "") or ""
            bolumu = info.get("Bölümü", "") or ""
            statusu = info.get("Statüsü", "") or ""
            odunc_durumu = info.get("YerNumarası", "") or ""

            def normalize(text: str) -> str:
                text = (text or "").strip()
                parts = text.split()
                return " ".join(parts).casefold()

            status_norm = normalize(statusu)
            ok_norm = normalize("ESER KOLEKSİYONDA")
            is_ok = ok_norm in status_norm

            if not is_ok:
                warning = "Kitabı kontrol ediniz."

            book = Book(
                kitap_barkod=kitap_barkod,
                kitap_adi=kitap_adi,
                bolumu=bolumu,
                statusu=statusu,
                odunc_durumu=odunc_durumu,
                created_by=current_user.username if current_user else None,
            )
            db.session.add(book)
            db.session.commit()
            total_books = Book.query.count()

            success = "Kitap otomatik olarak eklendi."

            last_kitap_barkod = kitap_barkod
            last_kitap_adi = kitap_adi
            last_bolumu = bolumu
            last_statusu = statusu
            last_odunc_durumu = odunc_durumu

            # Barkod kutusu yeni okutma için boş gelsin
            kitap_barkod = ""

            return render_template(
                "add_book.html",
                error=error,
                success=success,
                warning=warning,
                kitap_barkod=kitap_barkod,
                kitap_adi=kitap_adi,
                bolumu=bolumu,
                statusu=statusu,
                odunc_durumu=odunc_durumu,
                last_kitap_barkod=last_kitap_barkod,
                last_kitap_adi=last_kitap_adi,
                last_bolumu=last_bolumu,
                last_statusu=last_statusu,
                last_odunc_durumu=last_odunc_durumu,
                total_books=total_books,
            )

        # Elle kaydet
        if not kitap_barkod or not kitap_adi:
            error = "En azından KitapBarkod ve KitapAdı alanları zorunludur!"
            return render_template(
                "add_book.html",
                error=error,
                success=success,
                warning=warning,
                kitap_barkod=kitap_barkod,
                kitap_adi=kitap_adi,
                bolumu=bolumu,
                statusu=statusu,
                odunc_durumu=odunc_durumu,
                last_kitap_barkod=last_kitap_barkod,
                last_kitap_adi=last_kitap_adi,
                last_bolumu=last_bolumu,
                last_statusu=last_statusu,
                last_odunc_durumu=last_odunc_durumu,
                total_books=total_books,
            )

        existing = Book.query.filter_by(kitap_barkod=kitap_barkod).first()
        if existing:
            error = "Bu KitapBarkod zaten kayıtlı!"
            warning = "Kitabı kontrol ediniz."

            last_kitap_barkod = existing.kitap_barkod
            last_kitap_adi = existing.kitap_adi
            last_bolumu = existing.bolumu
            last_statusu = existing.statusu
            last_odunc_durumu = existing.odunc_durumu

            return render_template(
                "add_book.html",
                error=error,
                success=success,
                warning=warning,
                kitap_barkod=kitap_barkod,
                kitap_adi=kitap_adi,
                bolumu=bolumu,
                statusu=statusu,
                odunc_durumu=odunc_durumu,
                last_kitap_barkod=last_kitap_barkod,
                last_kitap_adi=last_kitap_adi,
                last_bolumu=last_bolumu,
                last_statusu=last_statusu,
                last_odunc_durumu=last_odunc_durumu,
                total_books=total_books,
            )

        book = Book(
            kitap_barkod=kitap_barkod,
            kitap_adi=kitap_adi,
            bolumu=bolumu,
            statusu=statusu,
            odunc_durumu=odunc_durumu,
            created_by=current_user.username if current_user else None,
        )
        db.session.add(book)
        db.session.commit()
        total_books = Book.query.count()

        success = "Kitap elle girilerek eklendi."

        last_kitap_barkod = kitap_barkod
        last_kitap_adi = kitap_adi
        last_bolumu = bolumu
        last_statusu = statusu
        last_odunc_durumu = odunc_durumu

        kitap_barkod = ""

        return render_template(
            "add_book.html",
            error=error,
            success=success,
            warning=warning,
            kitap_barkod=kitap_barkod,
            kitap_adi=kitap_adi,
            bolumu=bolumu,
            statusu=statusu,
            odunc_durumu=odunc_durumu,
            last_kitap_barkod=last_kitap_barkod,
            last_kitap_adi=last_kitap_adi,
            last_bolumu=last_bolumu,
            last_statusu=last_statusu,
            last_odunc_durumu=last_odunc_durumu,
            total_books=total_books,
        )

    # GET isteği
    return render_template(
        "add_book.html",
        error=error,
        success=success,
        warning=warning,
        kitap_barkod=kitap_barkod,
        kitap_adi=kitap_adi,
        bolumu=bolumu,
        statusu=statusu,
        odunc_durumu=odunc_durumu,
        last_kitap_barkod=last_kitap_barkod,
        last_kitap_adi=last_kitap_adi,
        last_bolumu=last_bolumu,
        last_statusu=last_statusu,
        last_odunc_durumu=last_odunc_durumu,
        total_books=total_books,
    )


@app.route("/delete_last/<kitap_barkod>", methods=["POST"])
@login_required
def delete_last(kitap_barkod):
    error = None
    success = None
    warning = None

    total_books = Book.query.count()

    if not kitap_barkod:
        error = "Silinecek KitapBarkod bulunamadı."
        return render_template(
            "add_book.html",
            error=error,
            success=success,
            warning=warning,
            kitap_barkod="",
            kitap_adi="",
            bolumu="",
            statusu="",
            odunc_durumu="",
            last_kitap_barkod=None,
            last_kitap_adi=None,
            last_bolumu=None,
            last_statusu=None,
            last_odunc_durumu=None,
            total_books=total_books,
        )

    book = Book.query.filter_by(kitap_barkod=kitap_barkod).first()

    if not book:
        error = "Bu KitapBarkod ile kayıtlı kitap bulunamadı."
        return render_template(
            "add_book.html",
            error=error,
            success=success,
            warning=warning,
            kitap_barkod="",
            kitap_adi="",
            bolumu="",
            statusu="",
            odunc_durumu="",
            last_kitap_barkod=None,
            last_kitap_adi=None,
            last_bolumu=None,
            last_statusu=None,
            last_odunc_durumu=None,
            total_books=total_books,
        )

    db.session.delete(book)
    db.session.commit()
    total_books = Book.query.count()

    success = f"{kitap_barkod} KitapBarkod'lu kitap silindi."

    return render_template(
        "add_book.html",
        error=error,
        success=success,
        warning=warning,
        kitap_barkod="",
        kitap_adi="",
        bolumu="",
        statusu="",
        odunc_durumu="",
        last_kitap_barkod=None,
        last_kitap_adi=None,
        last_bolumu=None,
        last_statusu=None,
        last_odunc_durumu=None,
        total_books=total_books,
    )


@app.route("/reset-count", methods=["POST"])
@login_required
def reset_count():
    error = None
    success = None

    try:
        deleted_count = Book.query.count()
        Book.query.delete()
        db.session.commit()
        success = f"Sayım sıfırlandı. Silinen kayıt sayısı: {deleted_count}."
    except Exception as e:
        db.session.rollback()
        error = f"Sayım sıfırlanırken bir hata oluştu: {e}"

    all_books = Book.query.order_by(Book.id).all()

    # Kullanıcı bazlı sayılar da tekrar hesaplanmalı
    raw_counts = (
        db.session.query(Book.created_by, func.count(Book.id))
        .group_by(Book.created_by)
        .all()
    )
    user_counts = []
    for username, count in raw_counts:
        user_counts.append({
            "username": username or "Belirtilmemiş",
            "count": count
        })

    return render_template("books.html", books=all_books, success=success, error=error, user_counts=user_counts)


@app.route("/export-books")
@login_required
def export_books():
    books = Book.query.order_by(Book.id).all()

    data = []
    for b in books:
        data.append({
            "ID": b.id,
            "KitapBarkod": b.kitap_barkod,
            "KitapAdı": b.kitap_adi,
            "Bölümü": b.bolumu,
            "Statüsü": b.statusu,
            "YerNumarası": b.odunc_durumu,
            "EkleyenKullanıcı": b.created_by,
        })

    columns = ["ID", "KitapBarkod", "KitapAdı", "Bölümü", "Statüsü", "YerNumarası", "EkleyenKullanıcı"]
    df = pd.DataFrame(data, columns=columns)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="KitapListesi")
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="kitap_listesi.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.route("/download-template")
@login_required
def download_template():
    columns = [
        "KitapBarkod",
        "KitapAdı",
        "Bölümü",
        "Statüsü",
        "YerNumarası",
    ]
    df = pd.DataFrame(columns=columns)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="genel_liste")
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name="genel_liste_sablon.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.route("/upload-master", methods=["POST"])
@login_required
def upload_master():
    file = request.files.get("file")
    if not file or file.filename == "":
        return redirect(url_for("index", upload_error="Lütfen bir Excel dosyası seçin.", upload_success=""))

    try:
        df = pd.read_excel(file)

        required_cols = [
            "KitapBarkod",
            "KitapAdı",
            "Bölümü",
            "Statüsü",
            "YerNumarası",
        ]

        for col in required_cols:
            if col not in df.columns:
                return redirect(url_for(
                    "index",
                    upload_error="Excel dosyasında şu sütunlar tam olarak bu isimlerle bulunmalıdır: KitapBarkod, KitapAdı, Bölümü, Statüsü, YerNumarası.",
                    upload_success=""
                ))

        df = df[required_cols]
        df = df.dropna(subset=["KitapBarkod", "KitapAdı"])

        for col in required_cols:
            df[col] = df[col].astype(str).str.strip()

        df.to_csv(MASTER_LIST_PATH, index=False, encoding="utf-8")

        return redirect(url_for(
            "index",
            upload_success=f"Ana liste başarıyla yüklendi. Toplam {len(df)} kayıt kaydedildi.",
            upload_error=""
        ))

    except Exception as e:
        return redirect(url_for(
            "index",
            upload_error=f"Excel dosyası okunurken bir hata oluştu: {e}",
            upload_success=""
        ))


# ===================== KİTAP ARA (GENEL LİSTEDE KİTAP ADINA GÖRE) =====================

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    """
    genel_liste.csv içindeki KitapAdı sütununda,
    kullanıcının yazdığı kelimeyi (büyük-küçük harf duyarsız) arar.
    Eşleşen satırları tablo halinde göstermek için search.html'e gönderir.
    """
    error = None
    results = []
    query = ""

    user = get_current_user()

    # Genel liste yoksa uyar
    if not os.path.exists(MASTER_LIST_PATH):
        error = "Genel liste (genel_liste.csv) bulunamadı. Önce ana listeden dosya yükleyin."
        return render_template(
            "search.html",
            error=error,
            results=results,
            query=query,
            current_username=user.username if user else "",
        )

    if request.method == "POST":
        query = request.form.get("query", "").strip()

        if not query:
            error = "Lütfen aramak istediğiniz kelimeyi yazın."
        else:
            try:
                df = pd.read_csv(MASTER_LIST_PATH, dtype=str)
                df = df.fillna("")

                mask = df["KitapAdı"].astype(str).str.contains(query, case=False, na=False)
                filtered = df[mask]

                if filtered.empty:
                    error = "Aramanıza uygun kitap bulunamadı."
                else:
                    results = filtered.to_dict(orient="records")

            except Exception as e:
                error = f"Genel liste okunurken bir hata oluştu: {e}"

    return render_template(
        "search.html",
        error=error,
        results=results,
        query=query,
        current_username=user.username if user else "",
    )


# ===================== KAMERA İLE BARKOD EKLEME İÇİN JSON API =====================

@app.route("/api/scan-add-book", methods=["POST"])
@login_required
def api_scan_add_book():
    """
    Kamera ile taranan barkodları AJAX üzerinden alan endpoint.
    Sayfa yenilenmez, kamera sürekli açık kalır; her barkodda buraya istek atılır.
    """
    data = request.get_json(silent=True) or {}
    barcode = (data.get("barcode") or data.get("kitap_barkod") or "").strip()

    if not barcode:
        return jsonify({
            "success": False,
            "status": "error",
            "message": "Barkod değeri alınamadı."
        }), 400

    current_user = get_current_user()

    # 1) Bu barkod zaten kayıtlı mı?
    existing = Book.query.filter_by(kitap_barkod=barcode).first()
    if existing:
        total_books = Book.query.count()
        return jsonify({
            "success": True,
            "status": "exists",
            "message": "Bu KitapBarkod zaten kayıtlı!",
            "book": {
                "kitap_barkod": existing.kitap_barkod,
                "kitap_adi": existing.kitap_adi,
                "bolumu": existing.bolumu or "",
                "statusu": existing.statusu or "",
                "odunc_durumu": existing.odunc_durumu or "",
            },
            "total_books": total_books,
            "warning": "Kitabı kontrol ediniz."
        }), 200

    # 2) Genel listeden bilgileri bul
    info = find_book_from_master(barcode)
    if not info:
        return jsonify({
            "success": False,
            "status": "not_found",
            "message": "Genel listede bu barkoda karşılık gelen kayıt bulunamadı."
        }), 404

    kitap_adi = info.get("KitapAdı", "") or ""
    bolumu = info.get("Bölümü", "") or ""
    statusu = info.get("Statüsü", "") or ""
    odunc_durumu = info.get("YerNumarası", "") or ""

    def normalize(text: str) -> str:
        text = (text or "").strip()
        parts = text.split()
        return " ".join(parts).casefold()

    status_norm = normalize(statusu)
    ok_norm = normalize("ESER KOLEKSİYONDA")
    is_ok = ok_norm in status_norm

    warning = None
    if not is_ok:
        warning = "Kitabı kontrol ediniz."

    # 3) Kitabı veritabanına kaydet
    book = Book(
        kitap_barkod=barcode,
        kitap_adi=kitap_adi,
        bolumu=bolumu,
        statusu=statusu,
        odunc_durumu=odunc_durumu,
        created_by=current_user.username if current_user else None,
    )
    db.session.add(book)
    db.session.commit()
    total_books = Book.query.count()

    return jsonify({
        "success": True,
        "status": "added",
        "message": "Kitap otomatik olarak eklendi.",
        "book": {
            "kitap_barkod": book.kitap_barkod,
            "kitap_adi": book.kitap_adi,
            "bolumu": book.bolumu or "",
            "statusu": book.statusu or "",
            "odunc_durumu": book.odunc_durumu or "",
        },
        "total_books": total_books,
        "warning": warning
    }), 200


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # SQLite tablosuna is_active sütunu ekli mi emin ol (mevcut DB'yi bozmamak için)
        try:
            db.session.execute(text("ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Book tablosuna created_by sütunu ekli mi emin ol
        try:
            db.session.execute(text("ALTER TABLE book ADD COLUMN created_by VARCHAR(50)"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Eğer hiç admin yoksa, ilk admin hesabını oluştur
        if not User.query.filter_by(is_admin=True).first():
            admin = User(username="admin", is_admin=True, is_active=True)
            admin.set_password("admin123")  # İlk giriş için
            db.session.add(admin)
            db.session.commit()
            print("İlk admin kullanıcısı oluşturuldu. Kullanıcı adı: admin, Şifre: admin123")

    app.run(host="0.0.0.0", port=5000, debug=True)
