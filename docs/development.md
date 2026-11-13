# Geliştirme ve doğrulama

Varsayılan testler geçici dosya, sentetik envanter ve sahte servis/SQL adaptörleri kullanır; sunucuya kurulum yapmaz:

```sh
export PYTHONDONTWRITEBYTECODE=1
python3 -B tests/community_install_check.py
python3 -B tests/community_install_engine_check.py
python3 -B tests/community_migration_check.py
python3 -B tests/community_storage_plan_check.py
python3 -B tests/community_release_check.py
python3 -B tests/community_release_build_check.py
python3 -B tests/community_edition_check.py
```

PHP 8.3 CLI, Python 3.12, Node ve OpenSSL gerekir. Node yalnız geliştirme içindir. Kernel metadata sahipliğini doğrulayan `tests/community_runtime_check.py` ve `tests/recovery_engine_check.py`, root ile çalıştırılan geçici dosya testleridir; gerçek aygıta yazmazlar. `tests/recovery_bootstrap_check.py` ağ denemelerini ayrıca izin verilmedikçe atlar.

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
