from flask import Flask, render_template, send_file, request, render_template_string, redirect, url_for
import pandas as pd
import os

app = Flask(__name__)
app.secret_key = 'gizli_anahtar'

# 🔴 Dosya tabanlı okunanlar listesi
OKUNANLAR_DOSYASI = "okunanlar.txt"

def oku_okunanlar():
    if not os.path.exists(OKUNANLAR_DOSYASI):
        return []
    with open(OKUNANLAR_DOSYASI, "r") as f:
        return [line.strip() for line in f.readlines()]

def ekle_okunan(barkod):
    with open(OKUNANLAR_DOSYASI, "a") as f:
        f.write(barkod + "\n")

def sifirla_okunanlar():
    if os.path.exists(OKUNANLAR_DOSYASI):
        os.remove(OKUNANLAR_DOSYASI)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/sablon-bos-indir')
def sablon_bos_indir():
    return send_file("sablon_bos.xlsx", as_attachment=True)

@app.route('/sablon-indir')
def sablon_indir():
    if os.path.exists("sablon.xlsx"):
        return send_file("sablon.xlsx", as_attachment=True)
    else:
        return "⚠️ Henüz yüklenmiş bir dosya yok."

@app.route('/dosya-sil')
def dosya_sil():
    if os.path.exists("sablon.xlsx"):
        os.remove("sablon.xlsx")
    sifirla_okunanlar()
    return redirect(url_for('home'))

@app.route('/yukle', methods=['POST'])
def yukle():
    dosya = request.files['dosya']
    if dosya:
        dosya.save("sablon.xlsx")
        df = pd.read_excel("sablon.xlsx")
        html_tablo = df.to_html(classes='table table-bordered', index=False)
        return render_template_string(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Yüklenen Kitap Listesi</title>
            <style>
                table, th, td {{
                    border: 1px solid black;
                    border-collapse: collapse;
                    padding: 5px;
                }}
            </style>
        </head>
        <body>
            <h2>📚 Yüklenen Kitap Listesi</h2>
            {html_tablo}
            <br><br>
            <a href="/">⬅️ Geri Dön</a>
        </body>
        </html>
        """)
    else:
        return "⚠️ Dosya yüklenemedi!"

@app.route('/sayim', methods=['GET', 'POST'])
def sayim():
    try:
        df = pd.read_excel("sablon.xlsx")
    except FileNotFoundError:
        return "❌ Hata: sablon.xlsx dosyası bulunamadı. Lütfen önce dosya yükleyin."

    kitap = None
    mesaj = None
    okunanlar = oku_okunanlar()

    if request.method == "POST":
        barkod = request.form.get("barkod")
        if len(barkod) == 13:
            barkod = barkod[:12]

        if barkod in okunanlar:
            mesaj = "⚠️ Bu barkod zaten okutuldu!"
        else:
            satir = df[df["Barkod"].astype(str) == barkod]
            if not satir.empty:
                kitap = satir.iloc[0].to_dict()
                ekle_okunan(barkod)
                okunanlar.append(barkod)  # Görüntüleme için listeyi güncelle
            else:
                mesaj = "🚫 Bu barkod sistemde bulunamadı."

    return render_template("sayim.html", kitap=kitap, mesaj=mesaj, okunanlar=okunanlar)

app.run(host='0.0.0.0', port=81, debug=False)
