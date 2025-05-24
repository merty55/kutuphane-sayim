from flask import Flask, render_template, send_file, request, redirect, url_for
import pandas as pd
import os

app = Flask(__name__)

# 📦 GLOBAL veri
okunanlar = []
cezaevi_okunanlar = []


# 📦 Dosya kontrol
def load_dataframe(file):
    return pd.read_excel(file) if os.path.exists(file) else pd.DataFrame()


df = load_dataframe("sablon.xlsx")
oduncteki_df = load_dataframe("oduncteki.xlsx")
cezaevi_df = load_dataframe("cezaevi.xlsx")


@app.route('/')
def home():
    return render_template("index.html")


# 📥 ANA ŞABLON
@app.route('/sablon-indir')
def sablon_indir():
    return send_file("sablon_bos.xlsx", as_attachment=True)


@app.route('/yukle', methods=['POST'])
def yukle():
    global df
    dosya = request.files['dosya']
    if dosya:
        df = pd.read_excel(dosya)
        df.to_excel("sablon.xlsx", index=False)
        return redirect(url_for('home'))
    return "⚠️ Ana şablon yüklenemedi!"


# 📥 ÖDÜNÇ ŞABLON
@app.route('/oduncteki-sablon-indir')
def oduncteki_sablon_indir():
    return send_file("oduncteki_bos_sablon.xlsx", as_attachment=True)


@app.route('/oduncteki-yukle', methods=['POST'])
def oduncteki_yukle():
    global oduncteki_df
    dosya = request.files['dosya']
    if dosya:
        oduncteki_df = pd.read_excel(dosya)
        oduncteki_df.to_excel("oduncteki.xlsx", index=False)
        return redirect(url_for('home'))
    return "⚠️ Ödünçteki şablon yüklenemedi!"


# 📥 CEZAEVI ŞABLON
@app.route('/cezaevi-sablon-indir')
def cezaevi_sablon_indir():
    return send_file("cezaevi_bos_sablon.xlsx", as_attachment=True)


@app.route('/cezaevi-yukle', methods=['POST'])
def cezaevi_yukle():
    global cezaevi_df
    dosya = request.files['dosya']
    if dosya:
        cezaevi_df = pd.read_excel(dosya)
        cezaevi_df.to_excel("cezaevi.xlsx", index=False)
        return redirect(url_for('home'))
    return "⚠️ Cezaevi şablon yüklenemedi!"


# 📋 SAYIM
@app.route('/sayim', methods=['GET', 'POST'])
def sayim():
    global okunanlar
    kitap = None
    mesaj = None

    if df.empty:
        return "⚠️ Ana kitap listesi yüklenmemiş."

    if request.method == 'POST':
        barkod = request.form.get("barkod")
        if len(barkod) == 13:
            barkod = barkod[:12]

        if not oduncteki_df.empty and barkod in oduncteki_df['Barkod'].astype(
                str).values:
            mesaj = "⚠️ Kitap ödünçte! Kontrol edin."
            okunanlar.append((barkod, 'turuncu'))
        elif any(b == barkod for b, _ in okunanlar):
            mesaj = "⚠️ Barkod tekrarlandı!"
            okunanlar.append((barkod, 'mavi'))
        else:
            satir = df[df['Barkod'].astype(str) == barkod]
            if not satir.empty:
                kitap = satir.iloc[0].to_dict()
                okunanlar.append((barkod, 'normal'))
            else:
                mesaj = "⚠️ Barkod bulunamadı."

    return render_template("sayim.html",
                           kitap=kitap,
                           mesaj=mesaj,
                           okunanlar=okunanlar)


# 📋 CEZAEVI
@app.route('/cezaevi', methods=['GET', 'POST'])
def cezaevi():
    global cezaevi_okunanlar
    kitap = None
    mesaj = None

    if cezaevi_df.empty:
        return "⚠️ Cezaevi kitap listesi yüklenmemiş."

    if request.method == 'POST':
        barkod = request.form.get("barkod")
        if len(barkod) == 13:
            barkod = barkod[:12]

        if barkod in cezaevi_okunanlar:
            mesaj = "⚠️ Barkod tekrarlandı!"
        else:
            satir = cezaevi_df[cezaevi_df['Barkod'].astype(str) == barkod]
            if not satir.empty:
                kitap = satir.iloc[0].to_dict()
                cezaevi_okunanlar.append(barkod)
            else:
                mesaj = "⚠️ Barkod bulunamadı."

    return render_template("cezaevi.html",
                           kitap=kitap,
                           mesaj=mesaj,
                           okunanlar=cezaevi_okunanlar)


@app.route('/cezaevi-bitir')
def cezaevi_bitir():
    global cezaevi_df, cezaevi_okunanlar

    if cezaevi_df.empty:
        return "⚠️ Cezaevi kitap listesi yüklenmemiş."

    tum_barkodlar = cezaevi_df['Barkod'].astype(str).tolist()
    okutulmayanlar = [b for b in tum_barkodlar if b not in cezaevi_okunanlar]

    if not okutulmayanlar:
        mesaj = "✅ Tüm kitaplar okutuldu!"
    else:
        mesaj = f"⚠️ Okutulmayan kitaplar: {', '.join(okutulmayanlar)}"

    return mesaj + " <a href='/cezaevi'>Geri dön</a>"


# 🟢 ÇALIŞTIR
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=81, debug=False)
