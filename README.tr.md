# redact-guard

[English](README.md) · **Türkçe**

Claude Code'u şirket kodunda kullan, ama **şifrelerin, IP'lerin, kullanıcı adların, TC kimlik numaraların ve diğer hassas bilgilerin hiçbiri okunabilir hâlde dışarı çıkmasın.** Claude yine de dosyalarını okuyup düzenleyebilsin.

---

## Çok basit anlatım: bu ne yapıyor?

Claude'a bir dosya gösterdiğinde, o dosya internetten Anthropic'e (Claude'u yapan şirkete) gider. Dosyanın içinde şifre varsa, şifre de gider.

**redact-guard araya giren bir bekçidir.** Bilgisayarından çıkan her şeyi kapıda durdurur, içindeki hassas bilgileri bulur ve her birinin yerine **takma ad** koyar. Sonra gönderir.

Senin bilgisayarındaki dosya:

```yaml
veritabani:
  adres: db-prod-01.sirketim.com.tr
  kullanici: ahmet.yilmaz
  sifre: Gizli!Sifre123
```

Claude'un gördüğü:

```yaml
veritabani:
  adres: RDX_HOST_4f1c2a9be03d
  kullanici: RDX_USER_a7e2c91d4b0f
  sifre: RDX_SECRET_8353e04b5851
```

Claude gerçek şifreyi **hiç görmez.** Sadece `RDX_SECRET_8353e04b5851` diye bir takma ad görür. Bu takma addan şifreyi çıkarmanın yolu yoktur: rastgele görünen bir koddur, şifrenin kendisi değildir.

**Peki Claude dosyayı nasıl düzenliyor?** Claude "şu satırı değiştir" dediğinde, cevap senin bilgisayarına geri gelir. Bekçi, takma adı **sadece senin bilgisayarında** tekrar gerçek değere çevirir ve dosyaya öyle yazar. Yani:

- **Dışarı giden:** her zaman takma ad.
- **Diskteki dosyan:** her zaman gerçek değer.
- **Takma ad sözlüğü:** sadece senin bilgisayarında, şifreli bir kasada. Claude'un çalıştırdığı hiçbir program bu kasayı açamaz.

Aynı şifre her yerde aynı takma adı alır. Böylece Claude "bu iki dosyada aynı şifre var" diye anlayabilir, ama şifrenin ne olduğunu bilemez.

---

## Neler gizlenir?

| Ne | Örnek | Claude'un gördüğü |
| --- | --- | --- |
| Şifreler, gizli anahtarlar | `sifre: Gizli!Sifre123`, `basicAuthenticationPassword=...` | `RDX_SECRET_...` |
| API anahtarları, tokenlar | GitHub, GitLab, AWS, Slack tokenları, JWT | `RDX_SECRET_...` |
| Özel anahtarlar | PEM / PGP private key blokları | `RDX_PRIVKEY_...` |
| IP adresleri | `10.0.4.17`, `192.168.1.5`, `85.105.1.20` | `RDX_IPPRIV_...` (şirket içi), `RDX_IP_...` |
| Sunucu ve şirket içi adresler | `db-prod-01.sirketim.com.tr`, `jdbc:postgresql://...` | `RDX_HOST_...` |
| Kullanıcı adları | `ahmet.yilmaz`, `SIRKET\ahmet`, Windows kullanıcı adın | `RDX_USER_...` |
| Git'teki isim ve e-postalar | `git log`, `git blame`, `.gitconfig` | `RDX_PERSON_...`, `RDX_EMAIL_...` |
| E-posta adresleri | `ayse@sirketim.com.tr` | `RDX_EMAIL_...` |
| TC kimlik numarası (TCKN) | 11 haneli, kontrol hanesi doğru olanlar | `RDX_TCKN_...` |
| Vergi kimlik numarası (VKN) | 10 haneli | `RDX_VKN_...` |
| IBAN | `TR33 0006 1005 1978 6457 8413 26` | `RDX_IBAN_...` |
| Telefon numaraları | `0532 123 45 67`, `+90 212 ...` | `RDX_PHONE_...` |
| Kredi kartı numaraları | Luhn kontrolünden geçen numaralar | `RDX_CARD_...` |

**Hangi dosyalarda?** Hepsinde: `.yaml`, Helm `values.yaml`, `.env`, `.properties`, Kubernetes manifestleri, `.NET` config'leri, Terraform state, log dosyaları, komut çıktıları, git geçmişi ve senin yazdığın mesajlar.

Takma adlar **asla 10 veya 11 haneli bir sayı gibi görünmez.** Yani bir takma ad yanlışlıkla VKN ya da TCKN sanılamaz.

**Telefondan (Remote Control) kullanırken** telefonuna giden ekran da aynı şekilde temizlenir: telefonunda da takma adları görürsün.

---

## Claude'un asla yapamayacakları

- **Veritabanı okumak.** `psql`, `mysql`, `sqlcmd`, `mongosh` gibi istemciler, veritabanı dosyaları, veritabanı portları ve veritabanı araçları engellenir. Windows'ta ayrıca bir güvenlik duvarı kuralı Claude'u veritabanı portlarından keser.
- **Takma ad kasasını okumak.** Kasa ve anahtarı, Claude'un çalıştığı kullanıcı hesabının açamadığı bir klasördedir.
- **Bekçiyi devre dışı bırakmak.** Claude bekçinin kurulu olduğu klasöre yazamaz. Bir proje kendi ayarlarıyla trafiği başka yere yönlendirmeye çalışırsa, mesaj gönderilmez.
- **Gerçek şifreyi terminal komutuna yazmak.** Takma adlar terminal komutlarında gerçek değere çevrilmez (sadece sunucu adı, kullanıcı adı ve klasör yolu gibi kimlik bilgileri çevrilir). Şifre gereken bir şey çalıştırılacaksa, Claude şifreyi bir dosyaya yazar ve program oradan okur.

---

## Neden "çok katmanlı"?

Tek bir kilide güvenmiyoruz. Her katman, öncekinin kaçırabileceğini yakalamak için var. Herhangi bir şüphede **göndermek yerine durdururuz.**

1. **Kapıda temizlik:** dışarı giden her şey taranır, hassas bilgiler takma adla değiştirilir.
2. **İkinci kontrol:** temizlenmiş mesaj bir kez daha taranır. Bilinen bir gerçek değer hâlâ içindeyse, mesaj **hiç gönderilmez.**
3. **Okunamayanı geçirme:** sıkıştırılmış ya da okunamayan veri taranamıyorsa, geçirilmez.
4. **Mesaj kontrolü:** her mesajdan önce, trafiğin gerçekten bekçiden geçtiği kriptografik olarak doğrulanır. Doğrulanamazsa mesaj gönderilmez.
5. **Komut kontrolü:** veritabanı istemcileri, veritabanı dosyaları, ham soket bağlantıları ve benzeri hileler engellenir.
6. **Ayar kilitleri:** Claude bekçinin kendi dosyalarına dokunamaz.
7. **İşletim sistemi izolasyonu:** bekçi ayrı bir sistem hesabıyla çalışır; kasa senin hesabından bile okunamaz.
8. **Güvenlik duvarı:** Claude'un veritabanı portlarına bağlanması ağ seviyesinde kapatılır. Ayrıca bir git kancası, içinde takma ad ya da bilinen şifre olan commit'leri durdurur.

---

## Dürüst uyarılar (lütfen oku)

Bu araç tanıyabildiği her şeyi gizler ve tanıyamadığını yakalamak için birden çok katman kullanır. Ama sihir değildir:

- **Tanımadığı biçimdeki bilgi kaçabilir.** Örneğin serbest metin içindeki bir kişi adı (git dışında) ya da hiçbir anahtar kelimeyle işaretlenmemiş, sıradan görünen bir şifre. Kendi projene özel anahtar adların varsa, ayar dosyasına ekleyebilirsin.
- **`root`, `admin` gibi sözlük kelimesi olan şifreler** sadece değer olarak geçtikleri yerde gizlenir (`sifre: root`). "Projenin root klasörü" gibi cümlelerdeki kelime gizlenmez, yoksa Claude cümleyi anlayamaz.
- **Claude'un başlattığı uygulamalar** (örneğin senin Spring uygulaman) veritabanına bağlanabilir; bu senin uygulamandır, Claude değil. Ama uygulamanın logunda veritabanı satırları yazıyorsa (örneğin Hibernate TRACE), Claude o logu okuduğunda o veriyi görür. Claude log okurken bu tür logları kapalı tut.
- **Şirket kurallarının yerini tutmaz.** Şirketin yapay zekâ kullanım kuralları neyse, onlar geçerlidir.

---

## Kurulum (Windows 11)

1. Python 3.10 veya üstünü kur.
2. Bu depoyu bir klasöre indir, örneğin `D:\redact-guard`.
3. **Yönetici PowerShell** aç ve çalıştır:
   ```powershell
   cd D:\redact-guard
   powershell -ExecutionPolicy Bypass -File scripts\windows\install.ps1 -ApplySettings
   ```
   Kurulum bekçiyi sistem servisi olarak başlatır, Claude Code ayarlarını yazar ve klasörleri kilitler.
4. Veritabanı portlarını Claude için kapat:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\windows\firewall-block-db.ps1 -BlockClaudeDirect -RegisterRefreshTask
   ```
5. **Normal (yönetici olmayan)** bir PowerShell'de, proje klasöründen kontrol et:
   ```powershell
   D:\redact-guard\.venv\Scripts\python.exe -m redact_guard doctor
   ```
   `FAIL` satırı olmamalı.
6. Claude Code'u yeniden başlat. Bu kadar.

**Önemli:** Claude Code'u asla "Yönetici olarak çalıştır" ile açma. Yönetici olarak çalışan bir program kasayı okuyabilir; normal terminal okuyamaz.

Linux, macOS ve ayrıntılı seçenekler için [İngilizce README](README.md)'ye bak.

---

## Bir şey ters giderse

- **`doctor` çalıştır.** Çoğu sorunu adıyla söyler ve ne yapacağını yazar.
- **"Waiting for API response · check your network"** uzun cevaplarda görünüyorsa: ağındaki bir cihaz cevabı bitene kadar tutuyordur. Cevap yine gelir; `doctor`'daki `reply streaming` satırı bunu gösterir.
- **Telefondan gönderdiğin mesaj işe yaramadıysa:** `%LOCALAPPDATA%\redact-guard\hook.log` dosyasına bak. Mesaj engellendiyse nedeni orada yazar. (Bu dosyalarda mesajın kendisi ya da şifre asla yer almaz.)

---

## Test

```bash
python -m pytest -q          # 360 test
bash tests/e2e/run_proxy.sh  # gerçek Claude Code CLI ile uçtan uca test
```
