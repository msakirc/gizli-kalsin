# gizli-kalsın (redact-guard)

[English](README.md) · **Türkçe**

**Claude Code ile şirket kodunda rahatça çalış. Şifrelerin, adreslerin, isimlerin ve kimlik numaraların bilgisayarında kalır.**

---

## Tek cümlede

redact-guard, bilgisayarının kapısında duran bir bekçidir: dışarı çıkan her şeydeki hassas bilgiyi bir takma adla değiştirir, Claude da sadece takma adları görür.

---

## Nasıl çalışır?

**1. Sen Claude'a bir dosya gösterirsin.**

```yaml
veritabani:
  adres: db-prod-01.sirketim.com.tr
  kullanici: ahmet.yilmaz
  sifre: Gizli!Sifre123
```

**2. Bekçi, dosya yola çıkmadan önce hassas bilgileri takma adlarla değiştirir. Claude bunu görür:**

```yaml
veritabani:
  adres: RDX_HOST_4f1c2a9be03d
  kullanici: RDX_USER_a7e2c91d4b0f
  sifre: RDX_SECRET_8353e04b5851
```

**3. Claude bir değişiklik yapınca, bekçi takma adı senin bilgisayarında gerçek değere geri çevirir ve dosyana öyle yazar.**

Hepsi bu kadar:

- Dışarı giden: **takma ad**
- Senin dosyan: **gerçek değer**
- Takma ad sözlüğü: **senin bilgisayarında, şifreli bir kasada**

Aynı şifre her yerde aynı takma adı alır. Claude "bu iki dosyada aynı şifre var" diye anlar ve işini doğru yapar.

Telefondan (Remote Control) çalışırken telefonun da takma adları görür.

---

## Gizlenen bilgiler

| Bilgi | Örnek | Claude'un gördüğü |
| --- | --- | --- |
| Şifreler | `sifre: Gizli!Sifre123` | `RDX_SECRET_...` |
| API anahtarları ve tokenlar | GitHub, GitLab, AWS, Slack, JWT | `RDX_SECRET_...` |
| Özel anahtarlar | PEM / PGP anahtar blokları | `RDX_PRIVKEY_...` |
| Şirket içi IP adresleri | `10.0.4.17`, `192.168.1.5` | `RDX_IPPRIV_...` |
| Dış IP adresleri | `85.105.1.20` | `RDX_IP_...` |
| Sunucu adresleri | `db-prod-01.sirketim.com.tr` | `RDX_HOST_...` |
| Kullanıcı adları | `ahmet.yilmaz`, Windows kullanıcı adın | `RDX_USER_...` |
| Git'teki isimler | `git log`, `git blame` | `RDX_PERSON_...` |
| E-posta adresleri | `ayse@sirketim.com.tr` | `RDX_EMAIL_...` |
| TC kimlik numarası | 11 haneli TCKN | `RDX_TCKN_...` |
| Vergi kimlik numarası | 10 haneli VKN | `RDX_VKN_...` |
| IBAN | `TR33 0006 1005 1978 6457 8413 26` | `RDX_IBAN_...` |
| Telefon numaraları | `0532 123 45 67` | `RDX_PHONE_...` |
| Kredi kartı numaraları | `4111 1111 1111 1111` | `RDX_CARD_...` |

Bekçi bunları her yerde arar: `.yaml`, Helm, `.env`, `.properties`, Kubernetes dosyaları, log dosyaları, komut çıktıları, git geçmişi ve senin yazdığın mesajlar.

Takma adlar her zaman harf ve rakam karışımıdır, VKN ya da TCKN'ye benzemez.

---

## Claude neler yapar?

- Dosyalarını okur ve düzenler.
- Projeni derler, testlerini çalıştırır.
- Log dosyalarını okur.
- Telefonundan gelen komutlarla çalışır.

## Claude'a kapalı olanlar

- **Veritabanları.** Veritabanı programları, dosyaları ve portları Claude'a kapalıdır.
- **Takma ad kasası.** Kasa, Claude'un ulaşamadığı ayrı bir klasördedir.
- **Bekçinin kendisi.** Bekçinin dosyaları ve ayarları Claude'a kilitlidir.

---

## Sekiz kat koruma

Her kat, bir öncekine ek güvencedir.

1. **Değiştirme:** dışarı giden her mesajda hassas bilgiler takma adla değiştirilir.
2. **Son kontrol:** mesaj yola çıkmadan bir kez daha taranır.
3. **Okunamayanı bekletme:** bekçinin okuyamadığı veri yerinde bekler.
4. **Yol kontrolü:** her mesajdan önce, trafiğin bekçiden geçtiği doğrulanır.
5. **Komut kontrolü:** veritabanına giden komutlar durdurulur.
6. **Ayar kilidi:** bekçinin dosyaları kilitlidir.
7. **Ayrı hesap:** bekçi kendi sistem hesabıyla çalışır, kasa o hesaptadır.
8. **Güvenlik duvarı:** veritabanı portları Claude'a kapatılır. Git kancası da takma ad içeren commit'leri yakalar.

---

## Kurulum (Windows 11)

1. Python 3.10 veya üstünü kur.
2. Bu depoyu bir klasöre indir, örneğin `D:\redact-guard`.
3. **Yönetici PowerShell** aç ve çalıştır:
   ```powershell
   cd D:\redact-guard
   powershell -ExecutionPolicy Bypass -File scripts\windows\install.ps1 -ApplySettings
   ```
4. Veritabanı portlarını Claude'a kapat:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\windows\firewall-block-db.ps1 -BlockClaudeDirect -RegisterRefreshTask
   ```
5. **Normal** bir PowerShell'de, proje klasöründen kontrol et:
   ```powershell
   D:\redact-guard\.venv\Scripts\python.exe -m redact_guard doctor
   ```
   `FAIL` satırı yoksa hazırsın.
6. Claude Code'u normal bir terminalde aç ve çalışmaya başla.

Linux, macOS ve diğer seçenekler için [İngilizce README](README.md)'ye bak.

---

## İpuçları

- **Şirketinin alan adını ekle:** `config/redact-guard.yaml` içinde `extra_internal_domains: [.sirketim.com.tr]` yaz; o alan adındaki her sunucu takma ad alır.
- **Müşteri ve kişi isimlerini ekle:** her satıra bir isim yazdığın bir dosyayı `names_file` ile göster; bu isimler her yerde takma ad alır.
- **Kendi desenlerini ekle:** şirketine özel numara biçimleri için `custom` listesine bir desen yaz (örneğin `ACME-123456`).
- **Kısa şifreler** (`root`, `admin` gibi) şifre olarak yazıldıkları yerde takma ad alır; Claude "projenin root klasörü" gibi cümleleri de anlamaya devam eder.
- **Claude log okurken** uygulamanın veritabanı satırlarını yazan log seviyelerini (örneğin Hibernate TRACE) kapalı tut.
- **Claude Code'u hep normal terminalde aç**, "Yönetici olarak çalıştır" ile değil.

---

## Yardım

- **`doctor` çalıştır.** Her satır durumu ve yapılacak adımı yazar.
- **Telefondan gönderdiğin mesajlar** `%LOCALAPPDATA%\redact-guard\hook.log` dosyasında görünür.
- **Uzun cevaplarda "check your network" yazısı görürsen** bekle; cevap gelir.

---

## Test

```bash
python -m pytest -q          # 360 test
bash tests/e2e/run_proxy.sh  # gerçek Claude Code ile uçtan uca test
```
