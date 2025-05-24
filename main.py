from flask import Flask, render_template, send_file, request, redirect, url_for
import pandas as pd
import os
import sys

app = Flask(__name__)

# Yardımcı: yol belirleyici
def get_path(filename):
    return os.path.join(os.getcwd(), filename)

# 📦 Ana kitap listesi
df = pd.read_csv(get_path("sablon.csv"), encoding='utf-8') if os.path.exists(get_path("sablon.csv")) else pd.DataFrame()

# 📦 Ödünçteki kitap listesi
oduncteki_df = pd.read_csv(get_path("oduncteki.csv"), encoding='utf-8') if os.path.exists(get_path("oduncteki.csv")) else pd.DataFrame()

# 📦 Cezaevi kitap listesi
cezaevi_df = pd.read_csv(get_path("cezaevi.csv"), encoding='utf-8') if os.path.exists(get_path("cezaevi.csv")) else pd.DataFrame()

# Okunan barkodlar listesi
okunanlar = []  # [(barkod, renk)]
# Cezaevi için okunanlar
cezaevi_okunanlar = []

@app.route('/')
def home():
    return render_template('index.html')

# Ana şablon indirme
@app.route('/sablon-indir')
def sablon_indir():
    return send_file(get_path('sablon_bos.csv'), as_attachment=True)

# Ana şablon yükleme
@app.route('/yukle', methods=['POST'])
def yukle():
    global df
    dosya = request.files.get('dosya')
    if dosya:
        df = pd.read_csv(dosya, encoding='utf-8')
        df.to_csv(get_path('sablon.csv'), index=False, encoding='utf-8')
        return redirect(url_for('home'))
    return '⚠️ Ana şablon yüklenemedi!'

# Ödünç şablon indirme
@app.route('/oduncteki-sablon-indir')
def oduncteki_sablon_indir():
    return send_file(get_path('oduncteki_bos_sablon.csv'), as_attachment=True)

# Ödünç şablon yükleme
@app.route('/oduncteki-yukle', methods=['POST'])
def oduncteki_yukle():
    global oduncteki_df
    dosya = request.files.get('dosya')
    if dosya:
        oduncteki_df = pd.read_csv(dosya, encoding='utf-8')
        oduncteki_df.to_csv(get_path('oduncteki.csv'), index=False, encoding='utf-8')
        return redirect(url_for('home'))
    return '⚠️ Ödünç şablon yüklenemedi!'

# Cezaevi şablon indirme
@app.route('/cezaevi-sablon-indir')
def cezaevi_sablon_indir():
    return send_file(get_path('cezaevi_bos_sablon.csv'), as_attachment=True)

# Cezaevi şablon yükleme
@app.route('/cezaevi-yukle', methods=['POST'])
def cezaevi_yukle():
    global cezaevi_df
    dosya = request.files.get('dosya')
    if dosya:
        cezaevi_df = pd.read_csv(dosya, encoding='utf-8')
        cezaevi_df.to_csv(get_path('cezaevi.csv'), index=False, encoding='utf-8')
        return redirect(url_for('home'))
    return '⚠️ Cezaevi şablon yüklenemedi!'

# Sayım ekranı
@app.route('/sayim', methods=['GET', 'POST'])
def sayim():
    global df, oduncteki_df, okunanlar
    kitap = None
    mesaj = None

    if df.empty:
        return '⚠️ sablon.csv yüklenmemiş.'

    if request.method == 'POST':
        barkod = request.form.get('barkod', '').strip()
        if len(barkod) == 13:
            barkod = barkod[:-1]

        if not oduncteki_df.empty and barkod in oduncteki_df['Barkod'].astype(str).values:
            mesaj = '⚠️ Kitap ödünçte görünüyor.'
            okunanlar.append((barkod, 'turuncu'))
        elif any(b == barkod for b, _ in okunanlar):
            mesaj = '⚠️ Barkod tekrar edilmiş.'
            okunanlar.append((barkod, 'mavi'))
        else:
            satir = df[df['Barkod'].astype(str) == barkod]
            if not satir.empty:
                kitap = satir.iloc[0].to_dict()
                okunanlar.append((barkod, 'normal'))
            else:
                mesaj = '⚠️ Barkod bulunamadı.'

    return render_template('sayim.html', kitap=kitap, mesaj=mesaj, okunanlar=okunanlar)

# Tüm listeyi sıfırlama
@app.route('/sayim-sifirla', methods=['POST'])
def sayim_sifirla():
    global okunanlar
    okunanlar.clear()
    return redirect(url_for('sayim'))

# Son okutulanı silme
@app.route('/sayim-geri', methods=['POST'])
def sayim_geri():
    if okunanlar:
        okunanlar.pop()
    return redirect(url_for('sayim'))

# Cezaevi ekranı
@app.route('/cezaevi', methods=['GET', 'POST'])
def cezaevi():
    global cezaevi_df, cezaevi_okunanlar
    kitap = None
    mesaj = None

    if cezaevi_df.empty:
        return '⚠️ cezaevi.csv yüklenmemiş.'

    if request.method == 'POST':
        barkod = request.form.get('barkod', '').strip()
        if len(barkod) == 13:
            barkod = barkod[:-1]

        if barkod in cezaevi_okunanlar:
            mesaj = '⚠️ Barkod zaten okutuldu.'
        else:
            satir = cezaevi_df[cezaevi_df['Barkod'].astype(str) == barkod]
            if not satir.empty:
                kitap = satir.iloc[0].to_dict()
                cezaevi_okunanlar.append(barkod)
            else:
                mesaj = '⚠️ Barkod cezaevi listesinde bulunamadı.'

    return render_template('cezaevi.html', kitap=kitap, mesaj=mesaj, okunanlar=cezaevi_okunanlar)

# Cezaevi bitir
@app.route('/cezaevi-bitir')
def cezaevi_bitir():
    global cezaevi_df, cezaevi_okunanlar
    if cezaevi_df.empty:
        return '⚠️ cezaevi.csv yüklenmemiş.'
    tum_barkodlar = cezaevi_df['Barkod'].astype(str).tolist()
    okutulmayanlar = [b for b in tum_barkodlar if b not in cezaevi_okunanlar]
    mesaj = '✅ Tüm kitaplar okutuldu!' if not okutulmayanlar else f'⚠️ Okutulmayanlar: {\", \".join(okutulmayanlar)}'
    return mesaj + " <a href='/cezaevi'>Geri dön</a>"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
