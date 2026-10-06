# GitHub'a yükleme rehberi

[← README](../README.md)

## Paylaşılacak içerik

Depo kökünde `README.md`, `.gitignore`, uygulama kaynakları, `kanit/`, `web/`, `tests/`, `docs/` ve `assets/` bulunmalıdır. Fontları ve `assets/OFL.txt` lisans metnini birlikte tutun. Kısayolları, `start.sh`, `requirements.txt` ve motor kurulum kodunu da ekleyin.

Hazırlanmış **safeZ-GitHub** klasörünün içeriğini kullanıyorsanız çalışma verileri bu klasöre alınmamıştır. ZIP'i önce açın; ZIP dosyasının kendisini proje kaynağı olarak yüklemeyin. `README.md` deponun kökünde kalmalıdır.

## Yerelde kalacak dosyalar

| Dosya / klasör | Neden dışarıda? |
| :--- | :--- |
| `work/` | Kayıtlar, denetim tokenı, HAR, motor oturumları ve günlükler. |
| `*.db`, `*.sqlite*` | Hedef geçmişi ve özel rapor kayıtları. |
| `*.har`, `*.session*` | İstek/yanıt içerikleri ve oturum verileri. |
| `.env*`, anahtarlar, çerez dosyaları | Yerel sırlar ve hesap bilgileri. |
| `.runtime/`, motor/JDK dizinleri | Yeniden indirilebilen büyük çalışma dosyaları. |
| `.venv/`, önbellekler, `node_modules/` | Yerel bağımlılıklar ve üretilmiş dosyalar. |
| PDF raporları, özel ekran görüntüleri | Gerçek hedef bilgisi içerebilen çıktılar. |
| `PROGRESS.md` | Kişisel geliştirme notları ve yerel ortam yolları. |
| ZIP, günlükler, yedekler, `.DS_Store` | Dağıtım/çalışma çıktıları ve sistem dosyaları. |

macOS kısayolunun `~/Library/Application Support/safeZ/` kayıtları proje dışındadır; onları da repoya kopyalamayın. Test kaynaklarındaki yapay örnekler pakette kalır. `docs/assets/safez-lab-report.png` yalnızca yerel, yapay laboratuvarın paylaşılabilir görünümüdür; gerçek hedef raporu değildir. `.env.example` ve `.env.sample` yalnızca bilerek hazırlanmış yapay örnekler için istisnadır.

## Git ile eklemeden önce

Gerçek Git deposunda, proje kökünden:

```sh
git status --short
git status --short --ignored
git check-ignore --no-index work/launcher.json .env reports/scan.pdf
```

`.gitignore`, yeni dosyaların takip edilmesini engeller; daha önce takip edilen dosyaları veya eski commitleri kaldırmaz. Daha önce eklenmiş bir dosyayı takipten çıkarmak için kendi dosya yolunuzla `git rm --cached` kullanılabilir. [GitHub'ın resmi açıklaması](https://docs.github.com/en/get-started/git-basics/ignoring-files).

Web üzerinden yüklerken temiz klasörün **içeriğini** seçin. `.gitignore` bir erişim kontrolü değildir; dışarıda tutulacak dosyaları ayrıca seçmeyin.

## Son kontrol

- `README.md` kökte ve kapak `docs/assets/safez-banner.svg` yolunda mı?
- `.gitignore` eklendi mi? Dosya adının başındaki nokta korunmalı.
- Özel hedefler, çerezler, anahtarlar ve gerçek raporlar dışarıda mı?
- Kaynaklar, testler ve font lisansı birlikte mi?
- Proje lisansı seçilecekse gerçek tercihe uygun `LICENSE` eklendi mi? Mevcut paket bir lisans seçmez.

Web yüklemesi yürütülebilir izinleri taşımadıysa, README'deki `chmod +x` adımıyla kısayollar/başlangıç hazırlanabilir. Git ile eklerken kaynak kısayollarının yürütülebilir izinlerini koruyun.
