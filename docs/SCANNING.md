# Kullanım ve kontrol ayrıntıları

[← README](../README.md)

Test etmeye yetkili olduğunuz sitelerde salt okunur, karşılaştırmalı testler çalıştıran Türkçe web uygulaması. Gerçek OWASP ZAP pasif motoru, iki test hesabı, maskelenmiş kanıt, durdurma, tarama geçmişi ve PDF raporu içerir.

## Başlatma

macOS'ta klasördeki iki dosyayı çift tıklayın:

- **safeZ Başlat.command**: uygulamayı ve tarama motorunu açar, hazır olunca tarayıcıyı açar. Tekrar tıklarsanız mevcut uygulama açılır.
- **safeZ Durdur.command**: Başlat kısayoluyla açılan uygulamayı, yerel laboratuvarları ve bağlı tarama motorunu tamamen kapatır. Kayıtlar silinmez. İlk kurulum sırasında da kullanılabilir.

İki kısayolu uygulama klasöründe tutun. Uygun arayüz portu otomatik seçilir; terminal penceresini kapatmak uygulamayı durdurmaz. Başlangıç sorunu olursa ayrıntılar `work/safez.log` dosyasındadır. Klasörü başka konuma taşımadan önce Durdur dosyasını çalıştırın. macOS kısayollarının kayıtları bulut klasörlerinden bağımsız olarak `~/Library/Application Support/safeZ/kanit.db` içinde tutulur. Eski terminal kurulumunun `work/data` kayıtları yerinde korunur; bu yeni kayıt alanına otomatik taşınmaz.

macOS veya Linux, Python 3.9+ ve ilk kurulum için internet gerekir. Terminalden alternatif başlangıç:

```sh
./start.sh
```

Arayüz: **http://127.0.0.1:8787**. Kapatmak için çalıştırdığınız terminalde **Ctrl+C**. Başlatıcı kendi ZAP sürecini de kapatır. 8787, 9121 ve 9122 portları boş olmalıdır. Farklı arayüz portu: `./start.sh --port 8788`. Portlar doluysa bağımsız başlatma: `./start.sh --port 8788 --lab-ports 0 0` (laboratuvar portları otomatik atanır).

İlk çalıştırma ReportLab, resmi OWASP ZAP 2.17.0 ve resmi Temurin Java 21 dağıtımını hazırlar. ZAP/Java indirmeleri SHA-256 ile denetlenir. Docker gerekmez. Codex'in hazır Python ortamı mevcutsa kullanılabilir; aksi halde proje içindeki `.venv` hazırlanır. Sistem Python paketleri değiştirilmez.

Java/ZAP büyük dosyaları bulut klasörlerinin otomatik boşaltmasından korumak için kullanıcıya özel geçici motor önbelleğinde tutulur. İşletim sistemi bu önbelleği temizlerse sonraki başlangıç yeniden indirir. Kalıcı bir konum isterseniz `KANIT_RUNTIME_DIR` ortam değişkenini ayarlayabilirsiniz. Kaynakları iCloud/OneDrive dışında yerel bir klasöre çıkarmak önerilir.

Motor bağlantısı olmadan çekirdek: `./start.sh --no-zap`. Bu modda keşif, SQL/NoSQL/şablon/HTML/açık yapılandırma ve ayarları sağlanan yetki/anonim erişim kontrolleri çalışır; rapor ZAP incelemesinin yapılmadığını açıkça gösterir. Motor hatası çekirdek bulguları sahte motor sonuçlarıyla değiştirmez.

## İlk deneme

1. **Açık hedefi tara** düğmesine basın. Yerel yapay hedef ve test bağlantıları hazırlanır; tarama hemen başlar.
2. Bulguları ve çözümünü inceleyin; **PDF indir** ile dışa aktarın.
3. **Düzeltilmiş hedefi tara** ile aynı testleri çalıştırın. Açık hedefte üç doğrulanmış yüksek bulgu, düzeltilmiş hedefte sıfır beklenir. Pasif uyarılar ayrıca gösterilir.

Laboratuvar SQLi için gerçek SQLite sorgu birleştirmesi, BOLA için eksik nesne sahipliği kontrolü, anonim erişim için eksik oturum kontrolü içerir. Düzeltilmiş sürüm parametreli sorgu, nesne sahipliği kontrolü ve zorunlu oturum kullanır. Veriler/sessions yapaydır; laboratuvarlar dış arayüzlere bağlanmaz.

## Kendi siteniz

Domaini veya tam site adresini girip Enter'a basın ya da **Taramayı başlat** düğmesine tıklayın. Şema yazılmamışsa HTTPS kullanılır. Site kaydedilir ve temel tarama doğrudan başlar; doğrulama dosyası veya DNS TXT istenmez. HTTPS/HTTP, alt alan adı ve port ayrı kapsamdır. DNS/IP sınırları her ağ isteğinde uygulanır.

İlk tarama hesap bilgisi gerektirmeyen keşif, SQL/NoSQL, şablon ifadesi, HTML yansıma ve açık yapılandırma/depo kontrollerini çalıştırır. Özel veri/iki hesap testleri için isteğe bağlı ayarları doldurup salt okunur test kayıtlarını kullandığınızı belirtin; **Test ayarlarıyla tekrar tara** düğmesine basın. Ayarları eksik kontroller raporda atlanmış olarak görünür. Yalnızca test etmeye yetkili olduğunuz hedefleri kullanın.

Özel veri testleri için kendi A/B test hesaplarınızın çerezini veya bearer belirtecini girin. A/B için ayrı, birbirini içermeyen test işaretleyicileri ve özel kayıt adresleri seçin. İşaretleyiciler URL veya oturum girdisinde bulunamaz. BOLA ayrıca aynı kimlik adresinden farklı ve kararlı hesap kimlikleri gerektirir: örneğin `/api/me` yanıtındaki `id` veya `user.id`. Kimlik adresi anonim isteği reddetmelidir. Bu bilgiler olmadan BOLA atlanır; farklı çerez metinleri farklı kullanıcı sayılmaz.

Anonim erişim için A'nın okuyabildiği özel bir GET kaydı ve benzersiz işaretleyici ekleyin. İşaretleyicinin gerçekten özel test verisinde olması sizin yapılandırma sorumluluğunuzdur. Hesap belirteçlerini yalnızca yerel uygulamaya girin; tarama sonunda sunucu yapılandırması ve arayüzdeki oturum alanları temizlenir.

Hassas etkiyi ancak test kayıtları kişisel/finansal/hassas veriyi temsil ediyorsa işaretleyin. SQL sorgu davranışı değişimi tek başına **orta** risktir. Normalde okunamayan hassas test kaydına iki turda erişilirse **yüksek** olur. Hiçbir tür adı otomatik olarak kritik risk üretmez.

## Gerçekte desteklenen testler

- **SQLi:** sayısal JSON kayıt parametreleri ve metin parametrelerinin tek JSON kayıt dizisi / HTML tablosu döndürdüğü uçlar karşılaştırılır. Normal sorgu, iki farklı sabit SELECT koşulu, yanlış koşul ve bulunmayan kayıt karşılaştırılır. Hata mesajı veya yansıtılan giriş kanıt sayılmaz. Hassas test kaydı için normal erişim ve sabit OR koşuluyla kapsam atlama ayrıca karşılaştırılır. UPDATE/DELETE, komut veya zaman geciktirme yükü yoktur.
- **NoSQL:** skaler GET alanı ile $eq/$ne ve bulunmayan kayıt sonuçları karşılaştırılır. Bazı API'ler operatörleri bilinçli destekler; özel veri erişimi kanıtlanmadığı için sonuç şüpheli kalır.
- **SSTI:** iki farklı zararsız aritmetik ifade, düz metin ve geçersiz ifade kontrolleriyle karşılaştırılır. Sunucuda ifade değerlendirmesi ayrı bulgudur; komut/kod yürütme veya dosya erişimi kanıtlandığı söylenmez.
- **HTML yansıma:** zararsız özel HTML öğesinin çıktıda gerçekten oluşup oluşmadığı iki tur ayrıştırılır. JavaScript yürütülmediğinden XSS adayı şüpheli kalır; kalıcılık/ayrıcalıklı etki doğrulanmaz.
- **Açık yapılandırma:** .env/config.json/config.yml/config.yaml ve rastgele bulunmayan dosya kontrol edilir. Maskelenmemiş kimlik bilgisine benzeyen atamalar iki okumada aynıysa dosya sızıntısı raporlanır; değerler saklanmaz/kullanılmaz. Git HEAD yalnız depo üst bilgisi adayıdır; depo nesneleri indirilmez.
- **BOLA:** iki ayrı ve kararlı oturum kimliği, her hesabın kendi özel kaydı, anonim negatif kontrol ve A → B okuması iki tur karşılaştırılır. Kimlikler/kayıtlar doğrulanamazsa sonuçsuz kalır.
- **Anonim erişim:** geçerli A oturumu, çerezsiz istek ve geçersiz çerez aynı özel test kaydında iki tur karşılaştırılır. Hesap ele geçirme veya parola değiştirme iddiası üretilmez.
- **OWASP ZAP:** yalnızca keşifte zaten alınmış anonim yanıtların HAR kaydı içe aktarılır. `sendRequests=false`; ZAP aktif tarama/spider başlatmaz. HAR dosyası geçicidir ve silinir. Motor uyarıları daima **şüpheli** kalır, doğrulanmış yüksek/kritik sayısına katılmaz.

HTML/GET formları, statik JavaScript API adresleri, robots.txt/sitemap ve üç yaygın salt okunur API adresi keşfedilir. Boş GET alanlarına deneme değeri atanır; gerçek JSON kayıt kimliklerinden parametre türetilir. Sunucuda olmayan API veya SQL parametresi oluşturulmaz; görmezden gelinen aday açık sayılmaz. POST formları gönderilmez, JavaScript yürütülmez. En fazla 32 keşif isteği, 6 sayısal SQL adayı, ek kontrollerde tür başına en fazla 3 parametre, 240 toplam tarama isteği ve varsayılan 2 istek/sn. Her ağ isteğinde DNS'in tüm IP cevapları kontrol edilir; bağlantı denetlenen IP'ye sabitlenir. Özel/rezerve ağlar, kapsam dışı yönlendirmeler, ağ çağrısı parametreleri ve işlem çağrıştıran uçlar engellenir. Yalnızca uygulamanın başlattığı iki yerel laboratuvar için kesin origin istisnası vardır. GET uçlarının gerçekten salt okunur olması gerekir; adres adı kontrolü bunun garantisi değildir.

DNS/HTTP için toplam 6 saniye sınırı, 256 KiB yanıt sınırı, 429 ile durdurma ve aktif okuma sırasında iptal uygulanır. İşletim sistemindeki devam eden DNS çözümleme işi iptal edilemez; sonucu tarama iptalinden sonra kullanılmaz. TCP bağlantı kurulumu en fazla kalan süreye kadar bekleyebilir.

## Sınırlar

**Bu sürüm kapsamlı bir pentest ürünü değildir.** İşletim sistemi komutu, keyfi dosya okuma/yazma/yükleme, SSRF callback doğrulaması, kalıcı/ayrıcalıklı XSS, sırların kullanılabilirliği, yönetici/işlev düzeyi yetki, iş mantığı, parola sıfırlama ve oturum yaşam döngüsü testleri uygulanmadı. Bunlar izole kayıt/hesap/rol/işlem akışı ve gerektiğinde kontrol edilen callback gerektirir. Hesapsız istek, iki ayrı kullanıcıya ait yetki karşılaştırmasının yerine geçmez. Her raporda bunlar **Uygulanmadı** olarak listelenir. Tüm uçlar/roller otomatik test edilmez. Yalnızca bir tekrar turunda görülen davranış şüpheli kalır. Açık bulunmaması güvenli site garantisi değildir.

Tek kullanıcılı yerel uygulamadır; internete açık çok kullanıcılı servis olarak dağıtılmamalıdır. Tarama sırasında sadece bir iş çalışır. Arayüz/API loopback, yerel Host/Origin denetimi, HttpOnly/SameSite çerezi ve mutasyon nonce'u ile korunur. Uzak servis/ekip rolleri bu sürümün kapsamı dışındadır.

## Veri ve raporlar

Hedef kayıtları ve maskeli raporlar `work/data/kanit.db` içinde tutulur; `--data-dir` ile değiştirebilirsiniz. Dizin 0700, veritabanı 0600. Oturum çerezleri/bearer belirteçleri ve özgün yanıt gövdeleri rapora veya veritabanına yazılmaz. Query değerleri maskelenir; HTTP durumları, boyutlar, SHA-256 ve işaretleyici var/yok kanıtı saklanır. URL yolları/parametre adları yapısal bilgi olarak raporda kalır; gizli değerleri URL yoluna koymayın. Pasif motorun oturum verileri geçici çalışma dizinindedir ve motor kapanınca temizlenir. Yerel ZAP günlüğü 0600'dür; destek için paylaşmadan önce inceleyin.

Yeni bulgular arayüz ve PDF’de Türkçe ve İngilizce sorun/etki/çözüm/tekrar adımları içerir. Konum GET adresi, parametre, keşif kaynağı ve varsa HTTP yanıt satırıdır; sunucu kaynak kodunun dosya/satırı HTTP taramasından belirlenemez. PDF, Noto Sans fontu ile özet, maskeli kanıt, test kapsamı ve motor durumunu içerir. Eski kayıtlar korunur; yeni motor ve açıklamalar için yeni tarama gerekir. Motor uyarılarının etkisi elle değerlendirilmelidir.

## Geliştirme ve doğrulama

```sh
python3 -m unittest discover -s tests -v
node --test tests/test_ui_races.js
```

ReportLab mevcut olmalıdır; başlatıcı oluşturduysa `.venv/bin/python` kullanılabilir. Otomatik testler gerçek yerel hedef ve HTTP API, doğrulamasız tarama, çıplak domain girişi, özel/mixed DNS engeli, yönlendirme, bütçe, iptal, yavaş yanıtlar, yanlış pozitifler, aynı hesapta iki oturum, motor HAR sözleşmesi ve PDF dışa aktarımını kapsar. Doğrulama çıktıları yerelde tutulur; kişisel çalışma notları herkese açık pakete dahil değildir.

## Dosyalar

`app.py`: yerel API/iş yönetimi; `kanit/engine.py`: karşılaştırmalı kanıt; `discovery.py`: kapsam içi keşif; `checks.py`: hesapsız kontrollü testler; `explanations.py`: Türkçe/İngilizce açıklamalar; `scope.py`: ağ kapsamı; `lab.py`: açık/düzeltilmiş hedef; `zap.py`: gerçek pasif motor; `store.py`: maskeli kayıt; `report.py`: PDF; `web/`: arayüz; `tests/`: testler. Resmi kaynaklar: [OWASP ZAP](https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0), [Temurin](https://adoptium.net/), [Noto Sans](https://github.com/notofonts/noto-fonts). Font lisansı [font lisansı](../assets/OFL.txt) içindedir.
