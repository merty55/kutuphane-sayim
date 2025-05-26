from flask import Flask, render_template, send_file, request, redirect, url_for
import pandas as pd
import os
import sys

# ——— Proje kökünü bul
BASE_DIR = os.getcwd()

# ——— Flask’a templates klasörünü söyle
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))


# ——— Küçük yardımcı: köke göre tam yol
def get_path(fn: str) -> str:
    return os.path.join(BASE_DIR, fn)


# ——— CSV’lerin başlık satırları şu şekilde olmalı:
# Barkod;Eser Adı;Yazar;Yeri;Ödünç Verilebilirlik Durumu

# ——— Ana şablon dosyası (sablon.csv)
if os.path.exists(get_path("sablon.csv")):
    df = pd.read_csv(get_path("sablon.csv"),
                     sep=';',
                     engine='python',
                     encoding='utf-8')
else:
    df = pd.DataFrame()

# ——— Ödünçteki kitaplar
if os.path.exists(get_path("oduncteki.csv")):
    oduncteki_df = pd.read_csv(get_path("oduncteki.csv"),
                               sep=';',
                               engine='python',
                               encoding='utf-8')
else:
    oduncteki_df = pd.DataFrame()

# ——— Cezaevi kitap listesi
if os.path.exists(get_path("cezaevi.csv")):
    cezaevi_df = pd.read_csv(get_path("cezaevi.csv"),
                             sep=';',
                             engine='python',
                             encoding='utf-8')
else:
    cezaevi_df = pd.DataFrame()

# ——— Geçici tutulan okunan barkodlar
okunanlar = []  # liste[(barkod, renk)]
cezaevi_okunanlar = []  # liste[barkod]


# ——— Ana Sayfa
@app.route('/')
def home():
    return render_template("index.html")


# ——— Ana şablon indir
@app.route('/sablon-indir')
def sablon_indir():
    return send_file(get_path("sablon_bos.csv"), as_attachment=True)


# ——— Ana şablon yükle
@app.route('/yukle', methods=['POST'])
def yukle():
    global df
    dosya = request.files.get('dosya')
    if dosya:
        df = pd.read_csv(dosya, sep=';', engine='python', encoding='utf-8')
        df.to_csv(get_path("sablon.csv"),
                  sep=';',
                  index=False,
                  encoding='utf-8')
        return redirect(url_for('home'))
    return "⚠️ Ana şablon yüklenemedi!"


# ——— Ödünç Boş Şablon indir
@app.route('/oduncteki-sablon-indir')
def oduncteki_sablon_indir():
    return send_file(get_path("oduncteki_bos_sablon.csv"), as_attachment=True)


# ——— Ödünç şablon yükle
@app.route('/oduncteki-yukle', methods=['POST'])
def oduncteki_yukle():
    global oduncteki_df
    dosya = request.files.get('dosya')
    if dosya:
        oduncteki_df = pd.read_csv(dosya,
                                   sep=';',
                                   engine='python',
                                   encoding='utf-8')
        oduncteki_df.to_csv(get_path("oduncteki.csv"),
                            sep=';',
                            index=False,
                            encoding='utf-8')
        return redirect(url_for('home'))
    return "⚠️ Ödünç şablon yüklenemedi!"


# ——— Cezaevi Boş Şablon indir
@app.route('/cezaevi-sablon-indir')
def cezaevi_sablon_indir():
    return send_file(get_path("cezaevi_bos_sablon.csv"), as_attachment=True)


# ——— Cezaevi şablon yükle
@app.route('/cezaevi-yukle', methods=['POST'])
def cezaevi_yukle():
    global cezaevi_df
    dosya = request.files.get('dosya')
    if dosya:
        cezaevi_df = pd.read_csv(dosya,
                                 sep=';',
                                 engine='python',
                                 encoding='utf-8')
        cezaevi_df.to_csv(get_path("cezaevi.csv"),
                          sep=';',
                          index=False,
                          encoding='utf-8')
        return redirect(url_for('home'))
    return "⚠️ Cezaevi şablon yüklenemedi!"


# ——— Sayım ekranı
@app.route('/sayim', methods=['GET', 'POST'])
def sayim():
    global df, oduncteki_df, okunanlar
    kitap = None
    mesaj = None

    if df.empty:
        return "⚠️ sablon.csv yüklenmemiş."

    if request.method == "POST":
        barkod = request.form.get("barkod", "").strip()
        # eğer 13 hane okuduysa son haneyi drop et
        if len(barkod) == 13:
            barkod = barkod[:12]

        # ödünçte mi?
        if (not oduncteki_df.empty
                and barkod in oduncteki_df['Barkod'].astype(str).values):
            mesaj = "⚠️ Kitap ödünçte görünüyor."
            okunanlar.append((barkod, 'turuncu'))

        # tekrar mı?
        elif any(b == barkod for b, _ in okunanlar):
            mesaj = "⚠️ Barkod tekrar edilmiş."
            okunanlar.append((barkod, 'mavi'))

        # normal ekle
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


# ——— Sayım listesini SIFIRLA
@app.route('/sayim-sifirla', methods=['POST'])
def sayim_sifirla():
    global okunanlar
    okunanlar = []
    return redirect(url_for('sayim'))


# ——— Son okutulanı SİL
@app.route('/sayim-geri', methods=['POST'])
def sayim_geri():
    global okunanlar
    if okunanlar:
        okunanlar.pop()  # son elemanı sil
    return redirect(url_for('sayim'))


# ——— Cezaevi ekranı
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

    return render_template("cezaevi.html",
                           kitap=kitap,
                           mesaj=mesaj,
                           okunanlar=cezaevi_okunanlar)


# ——— Cezaevi bitir → okutulmayanları raporla
@app.route('/cezaevi-bitir')
def cezaevi_bitir():
    global cezaevi_df, cezaevi_okunanlar

    if cezaevi_df.empty:
        return "⚠️ cezaevi.csv yüklenmemiş."

    tüm = cezaevi_df['Barkod'].astype(str).tolist()
    eksik = [b for b in tüm if b not in cezaevi_okunanlar]
    if not eksik:
        mesaj = "✅ Tüm kitaplar okutuldu!"
    else:
        mesaj = "⚠️ Okutulmayanlar: " + ", ".join(eksik)
    return mesaj + " <a href='/cezaevi'>Geri dön</a>"


# ——— Uygulamayı başlat
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    try:
        app.run(host='0.0.0.0', port=port, debug=False)
    except OSError as e:
        print(f"Port error: {e}")
        sys.exit(1)
