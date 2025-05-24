from flask import Flask, render_template, send_file, request, redirect, url_for
import pandas as pd
import os
import sys

# Use current working directory (safer for Render, avoids __file__ issues)
BASE_DIR = os.getcwd()

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))

# Helper function for file paths
def get_path(filename):
    return os.path.join(BASE_DIR, filename)

# Load initial data
if os.path.exists(get_path("sablon.xlsx")):
    df = pd.read_excel(get_path("sablon.xlsx"))
else:
    df = pd.DataFrame()

if os.path.exists(get_path("oduncteki.xlsx")):
    oduncteki_df = pd.read_excel(get_path("oduncteki.xlsx"))
else:
    oduncteki_df = pd.DataFrame()

if os.path.exists(get_path("cezaevi.xlsx")):
    cezaevi_df = pd.read_excel(get_path("cezaevi.xlsx"))
else:
    cezaevi_df = pd.DataFrame()

okunanlar = []
cezaevi_okunanlar = []

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/sablon-indir')
def sablon_indir():
    return send_file(get_path("sablon_bos.xlsx"), as_attachment=True)

@app.route('/yukle', methods=['POST'])
def yukle():
    global df
    dosya = request.files.get('dosya')
    if dosya:
        df = pd.read_excel(dosya)
        df.to_excel(get_path("sablon.xlsx"), index=False)
        return redirect(url_for('home'))
    return "⚠️ Ana şablon yüklenemedi!"

@app.route('/oduncteki-sablon-indir')
def oduncteki_sablon_indir():
    return send_file(get_path("oduncteki_bos_sablon.xlsx"), as_attachment=True)

@app.route('/oduncteki-yukle', methods=['POST'])
def oduncteki_yukle():
    global oduncteki_df
    dosya = request.files.get('dosya')
    if dosya:
        oduncteki_df = pd.read_excel(dosya)
        oduncteki_df.to_excel(get_path("oduncteki.xlsx"), index=False)
        return redirect(url_for('home'))
    return "⚠️ Ödünç şablon yüklenemedi!"

@app.route('/cezaevi-sablon-indir')
def cezaevi_sablon_indir():
    return send_file(get_path("cezaevi_bos_sablon.xlsx"), as_attachment=True)

@app.route('/cezaevi-yukle', methods=['POST'])
def cezaevi_yukle():
    global cezaevi_df
    dosya = request.files.get('dosya')
    if dosya:
        cezaevi_df = pd.read_excel(dosya)
        cezaevi_df.to_excel(get_path("cezaevi.xlsx"), index=False)
        return redirect(url_for('home'))
    return "⚠️ Cezaevi şablon yüklenemedi!"

@app.route('/sayim', methods=['GET', 'POST'])
def sayim():
    global df, oduncteki_df, okunanlar
    kitap = None
    mesaj = None

    if df.empty:
        return "⚠️ sablon.xlsx yüklenmemiş."

    if request.method == "POST":
        barkod = request.form.get("barkod")
        if barkod and len(barkod) == 13:
            barkod = barkod[:12]

        if not oduncteki_df.empty and barkod in oduncteki_df['Barkod'].astype(str).values:
            mesaj = "⚠️ Kitap ödünçte görünüyor."
            okunanlar.append((barkod, 'turuncu'))
        elif any(b == barkod for b, _ in okunanlar):
            mesaj = "⚠️ Barkod tekrar edilmiş."
            okunanlar.append((barkod, 'mavi'))
        else:
            satir = df[df['Barkod'].astype(str) == barkod]
            if not satir.empty:
                kitap = satir.iloc[0].to_dict()
                okunanlar.append((barkod, 'normal'))
            else:
                mesaj = "⚠️ Barkod bulunamadı."

    return render_template("sayim.html", kitap=kitap, mesaj=mesaj, okunanlar=okunanlar)

@app.route('/cezaevi', methods=['GET', 'POST'])
def cezaevi():
    global cezaevi_df, cezaevi_okunanlar
    kitap = None
    mesaj = None

    if cezaevi_df.empty:
        return "⚠️ cezaevi.xlsx yüklenmemiş."

    if request.method == "POST":
        barkod = request.form.get("barkod")
        if barkod and len(barkod) == 13:
            barkod = barkod[:12]

        if barkod in cezaevi_okunanlar:
            mesaj = "⚠️ Barkod zaten okutuldu."
        else:
            satir = cezaevi_df[cezaevi_df['Barkod'].astype(str) == barkod]
            if not satir.empty:
                kitap = satir.iloc[0].to_dict()
                cezaevi_okunanlar.append(barkod)
            else:
                mesaj = "⚠️ Barkod cezaevi listesinde bulunamadı."

    return render_template("Cezaevi.html", kitap=kitap, mesaj=mesaj, okunanlar=cezaevi_okunanlar)

@app.route('/cezaevi-bitir')
def cezaevi_bitir():
    global cezaevi_df, cezaevi_okunanlar

    if cezaevi_df.empty:
        return "⚠️ cezaevi.xlsx yüklenmemiş."

    tum_barkodlar = cezaevi_df['Barkod'].astype(str).tolist()
    okutulmayanlar = [b for b in tum_barkodlar if b not in cezaevi_okunanlar]

    if not okutulmayanlar:
        mesaj = "✅ Tüm kitaplar okutuldu!"
    else:
        mesaj = f"⚠️ Okutulmayanlar: {', '.join(okutulmayanlar)}"

    return mesaj + " <a href='/cezaevi'>Geri dön</a>"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    try:
        app.run(host='0.0.0.0', port=port, debug=False)
    except OSError as e:
        print(f"Port error: {e}")
        sys.exit(1)
