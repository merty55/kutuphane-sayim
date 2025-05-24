from flask import Flask, render_template, send_file, request, redirect, url_for
import pandas as pd
import os
import sys

app = Flask(__name__)

# 📦 Yardımcı: Yol belirleyici
def get_path(filename):
    return os.path.join(os.getcwd(), filename)

# 📦 Ana kitap listesi (CSV)
if os.path.exists(get_path("sablon.csv")):
    df = pd.read_csv(get_path("sablon.csv"), encoding='utf-8')
else:
    df = pd.DataFrame()

# 📦 Ödünçteki kitap listesi (CSV)
if os.path.exists(get_path("oduncteki.csv")):
    oduncteki_df = pd.read_csv(get_path("oduncteki.csv"), encoding='utf-8')
else:
    oduncteki_df = pd.DataFrame()

# 📦 Cezaevi kitap listesi (CSV)
if os.path.exists(get_path("cezaevi.csv")):
    cezaevi_df = pd.read_csv(get_path("cezaevi.csv"), encoding='utf-8')
else:
    cezaevi_df = pd.DataFrame()

# 📦 Okunanlar listeleri
okunanlar = []           # [(barkod, renk)]
cezaevi_okunanlar = []    # [barkod]

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
    if dosya:
        df = pd.read_csv(dosya, encoding='utf-8')
        df.to_csv(get_path("sablon.csv"), index=False, encoding='utf-8')
        return redirect(url_for('home'))
    return "⚠️ Ana şablon yüklenemedi!"

@app.route('/oduncteki-sablon-indir')
def oduncteki_sablon_indir():
    return send_file(get_path("oduncteki_bos_sablon.csv"), as_attachment=True)

@app.route('/oduncteki-yukle', methods=['POST'])
def oduncteki_yukle():
    global oduncteki_df
    dosya = request.files.get('dosya')
    if dosya:
        oduncteki_df = pd.read_csv(dosya, encoding='utf-8')
        oduncteki_df.to_csv(get_path("oduncteki.csv"), index=False, encoding='utf-8')
        return redirect(url_for('home'))
    return "⚠️ Ödünç şablon yüklenemedi!"

@app.route('/cezaevi-sablon-indir')
def cezaevi_sablon_indir():
    return send_file(get_path("cezaevi_bos_sablon.csv"), as_attachment=True)

@app.route('/cezaevi-yukle', methods=['POST'])
def cezaevi_yukle():
    global cezaevi_df
    dosya = request.files.get('dosya')
    if dosya:
        cezaevi_df = pd.read_csv(dosya, encoding='utf-8')
        cezaevi_df.to_csv(get_path("cezaevi.csv"), index=False, encoding='utf-8')
        return redirect(url_for('home'))
    return "⚠️ Cezaevi şablon yüklenemedi!"

@app.route('/sayim', methods=['GET','POST'])
def sayim():
    global df, oduncteki_df, okunanlar
    kitap = None
    mesaj = None

    if df.empty:
        return "⚠️ sablon.csv yüklenmemiş."

    if request.method == 'POST':
        raw = request.form.get('barkod', '')
        # Gelen barkodu 12 haneye indir
        barkod = raw.strip()[:12]

        # DataFrame’de de aynı işlemi uygula
        df_barkodlar = df['Barkod'].astype(str).str.strip().str[:12]
        odun_barkodlar = oduncteki_df['Barkod'].astype(str).str.strip().str[:12] if not oduncteki_df.empty else pd.Series([])

        # Ödünçte mi?
        if not odun_barkodlar.empty and barkod in odun_barkodlar.values:
            mesaj = "⚠️ Kitap ödünçte görünüyor."
            okunanlar.append((barkod, 'turuncu'))
        # Tekrar okutulmuş mu?
        elif any(b == barkod for b, _ in okunanlar):
            mesaj = "⚠️ Barkod tekrar edilmiş."
            okunanlar.append((barkod, 'mavi'))
        else:
            matches = df[df_barkodlar == barkod]
            if not matches.empty:
                kitap = matches.iloc[0].to_dict()
                okunanlar.append((barkod, 'normal'))
            else:
                mesaj = "⚠️ Barkod bulunamadı."

    return render_template("sayim.html", kitap=kitap, mesaj=mesaj, okunanlar=okunanlar)

@app.route('/cezaevi', methods=['GET','POST'])
def cezaevi():
    global cezaevi_df, cezaevi_okunanlar
    kitap = None
    mesaj = None

    if cezaevi_df.empty:
        return "⚠️ cezaevi.csv yüklenmemiş."

    if request.method == 'POST':
        raw = request.form.get('barkod', '')
        barkod = raw.strip()[:12]

        df_barkod = cezaevi_df['Barkod'].astype(str).str.strip().str[:12]
        if barkod in cezaevi_okunanlar:
            mesaj = "⚠️ Barkod zaten okutuldu."
        else:
            matches = cezaevi_df[df_barkod == barkod]
            if not matches.empty:
                kitap = matches.iloc[0].to_dict()
                cezaevi_okunanlar.append(barkod)
            else:
                mesaj = "⚠️ Barkod cezaevi listesinde bulunamadı."

    return render_template("Cezaevi.html", kitap=kitap, mesaj=mesaj, okunanlar=cezaevi_okunanlar)

@app.route('/cezaevi-bitir')
def cezaevi_bitir():
    global cezaevi_df, cezaevi_okunanlar

    if cezaevi_df.empty:
        return "⚠️ cezaevi.csv yüklenmemiş."

    tum_barkodlar = cezaevi_df['Barkod'].astype(str).str.strip().str[:12].tolist()
    okutulmayan = [b for b in tum_barkodlar if b not in cezaevi_okunanlar]

    if not okutulmayan:
        mesaj = "✅ Tüm kitaplar okutuldu!"
    else:
        mesaj = f"⚠️ Okutulmayanlar: {', '.join(okutulmayan)}"

    return mesaj + " <a href='/cezaevi'>Geri dön</a>"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    try:
        app.run(host='0.0.0.0', port=port)
    except OSError as e:
        print(f"Port error: {e}")
        sys.exit(1)
