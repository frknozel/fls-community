# FLS Community — FortiGate Log Sniffer

FortiGate loglarını toplamak, incelemek, bütünlüğünü doğrulamak ve arşivlemek için açık kaynak yazılım. FLS kaynakları **Apache-2.0** lisanslıdır; Community sürümünde süreli kullanım veya ücretli özellik kilidi yoktur.

**0.76.0-rc.3 bir test sürümüdür.** Kurulum motoru, imzalı dağıtım paketi ve ikinci diske taşıma işçisi uygulanmıştır. Ayrı, temiz Ubuntu VM üzerinde baştan sona kabul testi henüz tamamlanmamıştır. İlk denemeyi boş ve snapshot alınmış bir VM'de yapın. [Test adımları ve sınırlar](docs/installation.md).

## Kurulum

Ubuntu **24.04 LTS amd64**, **8 GiB RAM**, en az **40 GiB boş alan**, düz **ext4 sistem bölümü** gerekir. Ubuntu kurulurken LVM ve RAID seçmeyin. VM diskine benzersiz, kalıcı bir seri numarası/WWID atayın; kimliği doğrulanamayan disklerde kurulum durur. Bir disk yeterlidir; diğer diskler kurulum sırasında silinmez. VMware ESXi için VM kapalıyken `disk.EnableUUID=TRUE` ayarını etkinleştirin; [ayrıntılar](docs/installation.md).

Önce temel indirme araçlarını yükleyin, sonra sabit sürümün kurucusunu indirin:

```sh
sudo apt-get update
sudo apt-get install -y curl ca-certificates openssl python3
curl --fail --show-error --location --proto '=https' \
  https://raw.githubusercontent.com/frknozel/fls-community/v0.76.0-rc.3/install.sh \
  -o fls-install.sh
sudo bash fls-install.sh --check
```

Ön kontrol başarılıysa kurulumu açıkça başlatın:

```sh
sudo bash fls-install.sh --apply
```

`--check` paket veya servis kurmaz; engel varsa `blockers`, `probe_errors` ve açıklama verir. Ön kontrol engelinde `--apply` de `installation_started:false` ve `retry:fix_preflight_and_retry` döndürür; yalnız bu nedenle snapshot'a dönmek gerekmez.

Kurucu paket imzasını ve dosya karmalarını doğrular; Ubuntu'nun PHP 8.3/MariaDB 10.11 paketlerini, FLS'yi, servis hesaplarını, veritabanını ve yerel HTTPS sertifikasını hazırlar. Ağ/DNS ayarlarını değiştirmez. Gerekirse `--bind-ip`, `--hostname`, `--management-network` verilebilir. Mevcut FLS veya veritabanı bulunan makine reddedilir. Tamamlandığında ilk yönetici parolasını okuyun:

```sh
sudo cat /etc/fls/bootstrap-credentials.txt
```

Panelde ilk girişte parola değiştirilir. Log alımı başlangıçta kapalıdır; FortiGate bağlantısını tanımladıktan sonra bakım ekranından açıkça başlatılır. Harici aktarım ve ücretli zaman damgası işleri kendiliğinden açılmaz.

Kaynak checkout'u tek başına kurulum paketi değildir; derlenmiş bileşenleri içermez. Kaynak dizinindeki `bash install.sh --plan` salt okunur ön kontrol verir. `--apply` imzalı sürüm paketini kullanır.

## Özellikler

- Cihaz/VDOM kapsamında log gezgini, filtreler, kayıt incelemesi ve CSV dışa aktarma.
- Trafik, güvenlik, posta, VPN ve policy/profil değişiklik geçmişi.
- Ed25519 arşiv bütünlük zinciri, isteğe bağlı zaman damgası ve FTPS aktarımı.
- Yöneticiye özel logsuz sistem yedeği, günlük DB dump, kapasite takibi ve bakım.
- Tek diskten ikinci depo diskine panel üzerinden geçiş; isteğe bağlı üçüncü diske saatlik rsync. [Depolama](docs/storage-migration.md).

Sağlayıcı hesabı, kredileri ve dağıtım izni ayrıca gereken istemci SDK'sı bu depoda bulunmaz. Ücretsiz yazılım lisansı bu dış maliyetleri karşılamaz. FLS tek başına hukuki uygunluk belgesi değildir.

## Geliştirme ve lisans

[Katkı rehberi](CONTRIBUTING.md), [kontroller ve derleme](docs/development.md), [yayın durumu](docs/publication-status.json), [güvenlik](SECURITY.md).

Kaynak deposunda kurulum sırları, gerçek kayıtlar, SQL dump'ları, özel anahtarlar veya kurum içi Git geçmişi bulunmaz. İmzalı sürüm arşivi ve `release.json` GitHub Releases üzerinden dağıtılır. Collector'ın tam karşılık gelen kaynak arşivi aynı sürüme eklenir. FLS [Apache-2.0](LICENSE), üçüncü taraf bileşenler kendi lisansları kapsamındadır; [NOTICE](NOTICE) ve `third_party/` dosyalarına bakın. Proje resmî bir Fortinet ürünü değildir.
