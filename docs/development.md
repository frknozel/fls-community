# Geliştirme ve doğrulama

Varsayılan testler geçici dosya, sentetik envanter ve sahte servis/SQL adaptörleri kullanır; sunucuya kurulum yapmaz:

```sh
export PYTHONDONTWRITEBYTECODE=1
python3 -B tests/community_install_check.py
python3 -B tests/community_install_engine_check.py
python3 -B tests/community_storage_plan_check.py
python3 -B tests/community_release_check.py
python3 -B tests/community_release_build_check.py
python3 -B tests/community_edition_check.py
```

PHP 8.3 CLI, Python 3.12, Node ve OpenSSL gerekir. Node yalnız geliştirme içindir. Gerçek udev/sysfs verisi yerine geçici metadata kullanan `sudo python3 -B tests/community_inventory_check.py` ve disk adaptörlerinin root sahipliğini doğrulayan `sudo python3 -B tests/community_migration_check.py`, `tests/community_runtime_check.py` ve `tests/recovery_engine_check.py`, root ile çalıştırılan geçici dosya testleridir; gerçek aygıta yazmazlar. `tests/recovery_bootstrap_check.py` ağ denemelerini ayrıca izin verilmedikçe atlar.

`tests/community_schema_check.py --mariadb-prefix /tmp/extracted/usr`, Ubuntu paketlerinden **kurmadan açılmış** MariaDB 10.11 araçlarıyla yeni `/tmp` veritabanı ve socket oluşturur. TCP kapalıdır; dış veritabanı hedefi seçeneği yoktur. Root gerektirir; 80 tabloyu, şema tekrarlanmasını ve servis SQL yetkilerini sınar.

CI'nin geçmesi, temiz VM kurulumu, fiziksel disk taşıması, tam kurtarma veya zaman damgası sağlayıcısının kabul testi değildir. [VM test sırası](installation.md) ayrı yürütülür. Tüm `provision-*.py` dosyalarını sırayla çalıştırmayın; kurucu yalnız incelenmiş roller ve adımları çağırır.

## Sürüm bileşenlerinin derlenmesi

Ubuntu 24.04 amd64 derleme ortamında `third_party/rsyslog/source.json` içindeki derleme paketlerini ve Go 1.24 veya daha yenisini hazırlayın. İlk sürüm Go **1.27.4** ile üretildi. Kaynak JSON'undaki üç orijinal Ubuntu kaynak arşivini indirip bir önbellek dizinine koyun; betik boyut ve SHA-256 değerlerini tekrar denetler:

```sh
python3 tools/build-components.py --source "$PWD" \
  --cache /tmp/rsyslog-source-cache --output /tmp/fls-components \
  --go /path/to/go/bin/go
```

Betik yeni scratch dizininde `go test`, statik native derleme ve Ubuntu yamaları üzerine kontrollü yazım yamasını uygulayarak rsyslog derlemesi yapar. `make install` yalnız scratch `DESTDIR` içine yazar; sistem servislerini değiştirmez. Tam collector kaynak arşivi lisanslar, dağıtım yamaları ve derleme tarifiyle birlikte üretilir. Hiçbir mevcut `/opt` kurulumundan binary alınmaz. Çıktı karmaları `deploy/installer-components.json` ile uyuşmalıdır; farklı derleyici çıktıları için yeni sürüm ve incelenmiş pin güncellemesi gerekir.

Yayımlayıcı, temiz kaynak envanteriyle `tools/build-release.py` kullanır. Özel imza anahtarı depoların dışında 0600 olarak kalır. Sürüm arşivi, imzalı `release.json` ve karşılık gelen collector kaynak arşivi birlikte yayımlanır. Depoda bulunan açık anahtar paket doğrulaması içindir; müşteri yedek şifreleme anahtarlarıyla ilişkili değildir.

## RC9 disk kapasitesi tanısı

`tests/community_capacity_diagnostic.py`, yalnız hash doğrulanmış RC9 test VM’sinde tek disk kapasitesi senaryosunu geçici collector kopyasıyla inceler. Beklenen donanım parmak izini `--dmi-prefix` ile açıkça vermek gerekir. Kurulu uygulamayı veya servisleri değiştirmez; geçici dosyaları ve JSON raporunu tanı için korur. Onarım sonrasında gönderim/kayıt/kuyruk ilerlemesini beş saniyede bir, en çok 120 saniye gözler. Asıl 30 saniye sınırı aşılmışsa sonraki kurtarma başarılı olsa bile ilk testi başarılı saymaz ve çıkış kodu 1 kalır. Başarılı içerik doğrulamasında yalnız kendi geçici süreçlerinin kontrollü restart’ını sınar; başarısızlıkta çalışan geçici süreçleri ve yollarını inceleme için koruyup raporlar. Bu araç kurulum veya genel kapasite sertifikası değildir.

## Gerçek servislerle sentetik alım ve reboot kabulü

`tests/community_vm_intake_proof.py` yalnız kimliği açıkça doğrulanmış RC9 test VM’sinde, atanmış yerel IPv4 adresinden TCP5514’e iki ayrı 96 kayıt serisi gönderir. İlk `init` çağrısında `--target`, `--dmi-prefix`, `--release-manifest-sha256`, `--collector-sha256` ve `--installation-id` beklenen değerleri gerekir. Makbuzdaki `release_sha256`, kurulu `deploy/release-files.json` baytlarının hash’idir. Araç root sahipliğindeki özel `/var/tmp/fls-rc9-intake` durumunu reboot boyunca korur. `init` çıktısındaki benzersiz `RC9TEST_…` serisini panelde ayrı, devre dışı, varsayılan olmayan, API anahtarsız ve VDOM `root` cihaz olarak ekleyin. TLS hostname, bağlantı IP’si, kaynak/peer/alıcı/API trust IP alanlarında test VM’sini, HTTPS portunda443 değerini kullanın; yerel TCP kaynağına UI’den izin verin ve kendi görüntüleme erişiminizi atayın.

Sıra: `send-before`, `check-before`, normal reboot, `check-reboot`, `send-after`, `check-after`. Gönderim girişimi bir kez işaretlenir; belirsiz durumda aynı seri yeniden gönderilmez. Karşılaştırma tam UTF8 ham içerik, SHA256, ayrıştırılmış tüm alanlar, zamanlar, SQL indeks kimlikleri ve dosya konumu/checkpoint eşleşmesini ister. Reboot sonrası ilk96 indeks kimliği ve konumu değişmemelidir; son toplam192 ve eksik/tekrar0 olmalıdır. Araç doğrudan SQL yazmaz, servis/config değiştirmez ve reboot yapmaz; gönderim gerçek uygulamada sentetik ham kayıt ve indeks oluşturur. Doğrulama yerel raw dosyalarını okur ve MariaDB root Unix socket üzerinden salt okunur sorgular çalıştırır. Tek taramada256MiB sınırı vardır; yoğun/eski veri taşıyan makine için genel tarama aracı değildir. Yalnız kısa JSON kanıtını paylaşın.

Kaynaktaki `community_collector_check.py`, disk kapasitesi senaryosunda gerçek kuyruğun yapılandırılan sınıra ulaşmasını en çok10 saniye gözler. Onarım sonrası gönderici için30 saniye sınırı korunur ve gerçek bitiş zamanı kullanılır. Kapasiteye ulaşma veya gönderim süresi başarısızlığında gönderici, ham seri ve kuyruk gözlemi cleanup öncesi JSON raporuna eklenir. Bu kaynak testi iyileştirmesi RC9 paketindeki kurulu dosyaları değiştirmez.
