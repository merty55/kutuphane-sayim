from flask import Flask, render_template, send_file, request, redirect, url_for
import pandas as pd
import os

app = Flask(__name__, template_folder='Kutuphane/templates')

# 📦 Ana kitap listesi
if os.path.exists("Kutuphane/sablon.xlsx"):
    df = pd.read_excel("Kutuphane/sablon.xlsx")
else:
    df = pd.DataFrame()

# 📦 Ödünçteki kitap listesi
if os.path.exists("Kutuphane/oduncteki.xlsx"):
    oduncteki_df = pd.read_excel("Kutuphane/oduncteki.xlsx")
else:
    oduncteki_df = pd.DataFrame()

# 📦 Cezaevi kitap listesi
if os.path.exists("Kutuphane/cezaevi.xlsx"):
    cezaevi_df = pd.read_excel("Kutuphane/cezaevi.xlsx")
else:
    cezaevi_df = pd.DataFrame()

# 📦 Okunanlar
okunanlar = []
cezaevi_okunanlar = []


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/sablon-indir')
def sablon_indir():
    return send_file("Kutuphane/sablon_bos.xlsx", as_attachment=True)


@app.route('/yukle', methods=['POST'])
def yukle():
    global df
    dosya = request.files['dosya']
    if dosya:
        df = pd.read_excel(dosya)
        df.to_excel("Kutuphane/sablon.xlsx", index=False)
        return redirect(url_for('home'))
    return "⚠️ Ana şablon yüklenemedi!"


@app.route('/oduncteki-sablon-indir')
def oduncteki_sablon_indir():
    return send_file("Kutuphane/oduncteki_bos_sablon.xlsx", as_attachment=True)


@app.route('/oduncteki-yukle', methods=['POST'])
def oduncteki_yukle():
    global oduncteki_df
    dosya = request.files['dosya']
    if dosya:
        oduncteki_df = pd.read_excel(dosya)
        oduncteki_df.to_excel("Kutuphane/oduncteki.xlsx", index=False)
        return redirect(url_for('home'))
    return "⚠️ Ödünç şablon yüklenemedi!"


@app.route('/cezaevi-sablon-indir')
def cezaevi_sablon_indir():
    return send_file("Kutuphane/cezaevi_bos_sablon.xlsx", as_attachment=True)


@app.route('/cezaevi-yukle', methods=['POST'])
def cezaevi_yukle():
    global cezaevi_df
    dosya = request.files['dosya']
    if dosya:
        cezaevi_df = pd.read_excel(dosya)
        cezaevi_df.to_excel("Kutuphane/cezaevi.xlsx", index=False)
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
        if len(barkod) == 13:
            barkod = barkod[:12]

        if not oduncteki_df.empty and barkod in oduncteki_df['Barkod'].astype(
                str).values:
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

    return render_template("sayim.html",
                           kitap=kitap,
                           mesaj=mesaj,
                           okunanlar=okunanlar)


@app.route('/cezaevi', methods=['GET', 'POST'])
def cezaevi():
    global cezaevi_df, cezaevi_okunanlar
    kitap = None
    mesaj = None

    if cezaevi_df.empty:
        return "⚠️ cezaevi.xlsx yüklenmemiş."

    if request.method == "POST":
        barkod = request.form.get("barkod")
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

    return render_template("Cezaevi.html",
                           kitap=kitap,
                           mesaj=mesaj,
                           okunanlar=cezaevi_okunanlar)


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
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
