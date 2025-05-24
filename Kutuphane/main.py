from flask import Flask, render_template, send_file, request, render_template_string, redirect, url_for
import pandas as pd
import os

app = Flask(__name__)

# 📦 Ana kitap listesi
if os.path.exists("sablon.xlsx"):
    df = pd.read_excel("sablon.xlsx")
else:
    df = pd.DataFrame()

# 📦 Ödünçteki kitap listesi (yüklenecek)
if os.path.exists("oduncteki.xlsx"):
    oduncteki_df = pd.read_excel("oduncteki.xlsx")
else:
    oduncteki_df = pd.DataFrame()

# 📦 Okunan barkodlar + renkleri
okunanlar = []  # [(barkod, renk)]


@app.route('/')
def home():
    return render_template("index.html")


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
        return "✅ Ödünçteki kitap listesi yüklendi. <a href='/'>Ana sayfaya dön</a>"
    else:
        return "⚠️ Dosya yüklenemedi!"


@app.route('/sayim', methods=['GET', 'POST'])
def sayim():
    global df, oduncteki_df, okunanlar
    kitap = None
    mesaj = None

    if df.empty:
        return "⚠️ sablon.xlsx yüklenmemiş. Lütfen önce dosya yükleyin."

    if request.method == "POST":
        barkod = request.form.get("barkod")
        if len(barkod) == 13:
            barkod = barkod[:12]

        # 📌 Barkod ödünçte mi?
        if not oduncteki_df.empty and barkod in oduncteki_df['Barkod'].astype(
                str).values:
            mesaj = "⚠️ Kitap Kullanıcı Üzerinde Ödünçte Gözükmektedir. Kontrol Edip İşlemi Düzeltiniz."
            okunanlar.append((barkod, 'turuncu'))

        # 📌 Barkod daha önce okutulmuş mu?
        elif any(b == barkod for b, _ in okunanlar):
            mesaj = "⚠️ Barkod Tekrar Etmiştir. Kitap Barkodunu Kontrol Ediniz."
            okunanlar.append((barkod, 'mavi'))

        # 📌 Normal ekleme
        else:
            satir = df[df['Barkod'].astype(str) == barkod]
            if not satir.empty:
                kitap = satir.iloc[0].to_dict()
                okunanlar.append((barkod, 'normal'))
            else:
                mesaj = "⚠️ Bu barkod sistemde bulunamadı."

    return render_template("sayim.html",
                           kitap=kitap,
                           mesaj=mesaj,
                           okunanlar=okunanlar)


# 📦 Cezaevi kitap listesi
if os.path.exists("cezaevi.xlsx"):
    cezaevi_df = pd.read_excel("cezaevi.xlsx")
else:
    cezaevi_df = pd.DataFrame()

# 📦 Cezaevi okunanlar listesi
cezaevi_okunanlar = []


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
        return "✅ Cezaevi kitap listesi yüklendi. <a href='/'>Ana sayfaya dön</a>"
    else:
        return "⚠️ Cezaevi dosyası yüklenemedi!"


@app.route('/cezaevi', methods=['GET', 'POST'])
def cezaevi():
    global cezaevi_df, cezaevi_okunanlar
    kitap = None
    mesaj = None

    if cezaevi_df.empty:
        return "⚠️ Cezaevi.xlsx yüklenmemiş. Lütfen önce dosya yükleyin."

    if request.method == "POST":
        barkod = request.form.get("barkod")
        if len(barkod) == 13:
            barkod = barkod[:12]

        # Barkod zaten okutulmuş mu?
        if barkod in cezaevi_okunanlar:
            mesaj = "⚠️ Bu barkod zaten okutulmuş."
        else:
            satir = cezaevi_df[cezaevi_df['Barkod'].astype(str) == barkod]
            if not satir.empty:
                kitap = satir.iloc[0].to_dict()
                cezaevi_okunanlar.append(barkod)
            else:
                mesaj = "⚠️ Bu barkod cezaevi listesinde bulunamadı."

    return render_template("cezaevi.html",
                           kitap=kitap,
                           mesaj=mesaj,
                           okunanlar=cezaevi_okunanlar)


@app.route('/cezaevi-bitir')
def cezaevi_bitir():
    global cezaevi_df, cezaevi_okunanlar

    if cezaevi_df.empty:
        return "⚠️ Cezaevi.xlsx yüklenmemiş."

    # 📌 Okutulmayanları bul
    tum_barkodlar = cezaevi_df['Barkod'].astype(str).tolist()
    okutulmayanlar = [b for b in tum_barkodlar if b not in cezaevi_okunanlar]

    if not okutulmayanlar:
        mesaj = "✅ Tüm kitaplar başarıyla okutuldu!"
    else:
        mesaj = f"⚠️ Okutulmayan kitaplar: {', '.join(okutulmayanlar)}"

    return mesaj + " <a href='/cezaevi'>Geri dön</a>"


# 🟢 Çalıştır
app.run(host='0.0.0.0', port=81, debug=False)
