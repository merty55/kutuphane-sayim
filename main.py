from flask import Flask, render_template, send_file, request, redirect, url_for
import pandas as pd
import os
import sys

app = Flask(__name__)

def get_path(fname):
    return os.path.join(os.getcwd(), fname)

# 📦 Ana kitap listesi
try:
    if os.path.exists(get_path("sablon.csv")):
        df = pd.read_csv(
            get_path("sablon.csv"),
            sep=';',
            engine='python',
            encoding='utf-8'
        )
    else:
        df = pd.DataFrame()
except Exception as e:
    print(f"⚠️ sablon.csv yüklenirken hata: {e}")
    df = pd.DataFrame()

# 📦 Ödünçteki kitap listesi
try:
    if os.path.exists(get_path("oduncteki.csv")):
        oduncteki_df = pd.read_csv(
            get_path("oduncteki.csv"),
            sep=';',
            engine='python',
            encoding='utf-8'
        )
    else:
        oduncteki_df = pd.DataFrame()
except Exception as e:
    print(f"⚠️ oduncteki.csv yüklenirken hata: {e}")
    oduncteki_df = pd.DataFrame()

# 📦 Cezaevi kitap listesi
try:
    if os.path.exists(get_path("cezaevi.csv")):
        cezaevi_df = pd.read_csv(
            get_path("cezaevi.csv"),
            sep=';',
            engine='python',
            encoding='utf-8'
        )
    else:
        cezaevi_df = pd.DataFrame()
except Exception as e:
    print(f"⚠️ cezaevi.csv yüklenirken hata: {e}")
    cezaevi_df = pd.DataFrame()

okunanlar = []
cezaevi_okunanlar = []

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/sablon-indir')
def sablon_indir():
    return send_file(get_path("sablon_bos.csv"), as_attachment=True)

@app.route('/yukle', methods=['POST'])
def yukle():
    global df
    dosya = request.files.get('dosya')
    if not dosya:
        return "⚠️ Dosya seçilmedi!"
    try:
        df = pd.read_csv(dosya, sep=';', engine='python', encoding='utf-8')
        df.to_csv(get_path("sablon.csv"), sep=';', index=False, encoding='utf-8')
        return redirect(url_for('home'))
    except Exception as e:
        return f"⚠️ Ana şablon yüklenemedi: {e}"

@app.route('/oduncteki-sablon-indir')
def oduncteki_sablon_indir():
    return send_file(get_path("oduncteki_bos_sablon.csv"), as_attachment=True)

@app.route('/oduncteki-yukle', methods=['POST'])
def oduncteki_yukle():
    global oduncteki_df
    dosya = request.files.get('dosya')
    if not dosya:
        return "⚠️ Dosya seçilmedi!"
    try:
        oduncteki_df = pd.read_csv(dosya, sep=';', engine='python', encoding='utf-8')
        oduncteki_df.to_csv(get_path("oduncteki.csv"), sep=';', index=False, encoding='utf-8')
        return redirect(url_for('home'))
    except Exception as e:
        return f"⚠️ Ödünç şablon yüklenemedi: {e}"

@app.route('/cezaevi-sablon-indir')
def cezaevi_sablon_indir():
    return send_file(get_path("cezaevi_bos_sablon.csv"), as_attachment=True)

@app.route('/cezaevi-yukle', methods=['POST'])
def cezaevi_yukle():
    global cezaevi_df
    dosya = request.files.get('dosya')
    if not dosya:
        return "⚠️ Dosya seçilmedi!"
    try:
        cezaevi_df = pd.read_csv(dosya, sep=';', engine='python', encoding='utf-8')
        cezaevi_df.to_csv(get_path("cezaevi.csv"), sep=';', index=False, encoding='utf-8')
        return redirect(url_for('home'))
    except Exception as e:
        return f"⚠️ Cezaevi şablon yüklenemedi: {e}"

@app.route('/sayim', methods=['GET', 'POST'])
def sayim():
    global df, oduncteki_df, okunanlar
    kitap = None
    mesaj = None

    if df.empty:
        return "⚠️ sablon.csv yüklenmemiş."

    if request.method == "POST":
        barkod = request.form.get("barkod", "").strip()
        if len(barkod) == 13:
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
        return "⚠️ cezaevi.csv yüklenmemiş."

    if request.method == "POST":
        barkod = request.form.get("barkod", "").strip()
        if len(barkod) == 13:
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
        return "⚠️ cezaevi.csv yüklenmemiş."

    tum_barkodlar = cezaevi_df['Barkod'].astype(str).tolist()
    okutulmayan = [b for b in tum_barkodlar if b not in cezaevi_okunanlar]

    if not okutulmayan:
        mesaj = "✅ Tüm kitaplar okutuldu!"
    else:
        mesaj = f"⚠️ Okutulmayanlar: {', '.join(okutulmayan)}"

    return mesaj + " <a href='/cezaevi'>Geri dön</a>"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    try:
        app.run(host='0.0.0.0', port=port, debug=False)
    except OSError as e:
        print(f"Port error: {e}")
        sys.exit(1)
