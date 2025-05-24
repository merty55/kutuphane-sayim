from flask import Flask, render_template, send_file, request, render_template_string, redirect, url_for
import pandas as pd
import os

app = Flask(__name__)

# 📦 Uygulama başında bir kere yükle
if os.path.exists("sablon.xlsx"):
    df = pd.read_excel("sablon.xlsx")
else:
    df = pd.DataFrame()

# 📌 Okunan barkodları tutacak global liste
okunanlar = []


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/sablon-indir')
def sablon_indir():
    return send_file("sablon.xlsx", as_attachment=True)


@app.route('/sablon-bos-indir')
def sablon_bos_indir():
    return send_file("sablon_bos.xlsx", as_attachment=True)


@app.route('/yukle', methods=['POST'])
def yukle():
    global df
    dosya = request.files['dosya']
    if dosya:
        df = pd.read_excel(dosya)
        df.to_excel("sablon.xlsx", index=False)
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
            {df.to_html(classes='table table-bordered', index=False)}
            <br><br>
            <a href="/">⬅️ Geri Dön</a>
        </body>
        </html>
        """)
    else:
        return "⚠️ Dosya yüklenemedi!"


@app.route('/sayim', methods=['GET', 'POST'])
def sayim():
    global df, okunanlar
    kitap = None
    mesaj = None

    if df.empty:
        return "⚠️ Hata: sablon.xlsx dosyası yüklenmemiş. Lütfen önce dosya yükleyin."

    if request.method == "POST":
        barkod = request.form.get("barkod")
        if len(barkod) == 13:
            barkod = barkod[:12]

        satir = df[df['Barkod'].astype(str) == barkod]
        if not satir.empty:
            kitap = satir.iloc[0].to_dict()
            okunanlar.append(barkod)
        else:
            mesaj = "⚠️ Bu barkod sistemde bulunamadı."

    return render_template("sayim.html",
                           kitap=kitap,
                           mesaj=mesaj,
                           okunanlar=okunanlar)


@app.route('/temizle-okunanlar')
def temizle_okunanlar():
    global okunanlar
    okunanlar = []
    return redirect(url_for('sayim'))


@app.route('/sil-son-okunan')
def sil_son_okunan():
    global okunanlar
    if okunanlar:
        okunanlar.pop()
    return redirect(url_for('sayim'))


@app.route('/temizle-hepsi')
def temizle_hepsi():
    global okunanlar
    okunanlar = []
    if os.path.exists("sablon.xlsx"):
        os.remove("sablon.xlsx")
    return "✅ Yüklenen dosya ve okunan liste silindi. <a href='/'>Ana sayfaya dön</a>"


# 🟢 Çalıştır
app.run(host='0.0.0.0', port=81, debug=False)
