# FLS Community — FortiGate Log Sniffer

FortiGate loglarını toplamak, incelemek, bütünlüğünü doğrulamak ve arşivlemek için açık kaynak yazılım. FLS kaynakları **Apache-2.0** lisanslıdır; Community sürümünde süreli kullanım veya ücretli özellik kilidi yoktur.

**0.76.0-rc.6 bir test sürümüdür.** Ayrı ESXi / Ubuntu 24.04 VM'de temiz RC6 kurulumu, gerçek FortiGate log alımı ve panelden 100 GiB ikinci diske taşıma kullanıcı tarafından doğrulandı. Taşıma sonrası panelden yeniden başlatmada FLS açıldı ve loglar otomatik gelmeye devam etti. Alıcının `syslog:adm` hesabıyla salt okunur depolama denetimi geçti; ayrı ext4 depo, altı log/yedek bağlantısı ve sistem diskinde kalan kuyruk doğrulandı. Beş temel servis çalışıyor ve başarısız systemd birimi yok.

RC6, RC5'te taşıma sırasında görülen üst dizin izin hatasını giderir. Disk sayfasında açık ayrıntıların ve kaydırma konumunun otomatik yenilemelerde korunduğu da kullanıcı tarafından doğrulandı. İki diskli düzende logsuz sistem yedeği oluşturulup indirildi; dosya/kaynak bütünlüğü, SQL kapsamı ve anahtar eşleşmeleri salt okunur incelendi. Yedeğin özgün hibrit düzeni birebir yeniden kurma sınırı ve desteklenen tek diskli prova akışı [kurtarma kılavuzunda](docs/system-backup-restore.md) açıklanır. Kuyruk/yazım hataları, veri bütünlüğü ve ayrı cihazda tam kurtarma kabulü henüz tamamlanmadı. [Test adımları ve sınırlar](docs/installation.md).

## Kurulum

Ubuntu **24.04 LTS amd64**, **8 GiB RAM**, en az **40 GiB boş alan**, düz **ext4 sistem bölümü** gerekir. Ubuntu kurulurken LVM ve RAID seçmeyin. VM diskine benzersiz, kalıcı bir seri numarası/WWID atayın; kimliği doğrulanamayan disklerde kurulum durur. Bir disk yeterlidir; diğer diskler kurulum sırasında silinmez. VMware ESXi için VM kapalıyken `disk.EnableUUID=TRUE` ayarını etkinleştirin; [ayrıntılar](docs/installation.md).

Önce temel indirme araçlarını yükleyin, sonra sabit sürümün kurucusunu indirin:

```sh
sudo apt-get update
sudo apt-get install -y curl ca-certificates openssl python3
curl --fail --show-error --location --proto '=https' \
  https://raw.githubusercontent.com/frknozel/fls-community/v0.76.0-rc.6/install.sh \
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

Panelde ilk girişte parola değiştirilir. Log alımı başlangıçta kapalıdır. Önce yeniden başlatma ve kapalı durumun korunduğunu sınayın; ardından **ilk kaynak iznini uygulamadan önce** Log sunucusu → Log alımı bölümünden başlatıp **Çalışıyor** durumunu bekleyin. FortiGate cihazı Hazırlık / devre dışı durumunda eklenebilir; ilk syslog denemesi için API anahtarı gerekmez. Gönderici izni ile kullanıcının cihazı görüntüleme erişimi ayrı tanımlanır. Cihazın **Etkin** seçeneği API sorgulamasını açar ve etkin API anahtarı ister; **Hazırlık** durumunda syslog kayıtları incelenebilir. FortiGate hedefini tanımlamak ve kullanıcıya görüntüleme izni vermek, FLS alıcısına gönderici izni vermez: **Kaynağı kaydet ve sunucuya uygula** adımını da tamamlayın. Harici aktarım ve ücretli zaman damgası işleri kendiliğinden açılmaz.

Kurulumdan sonra [FortiGate bağlantı rehberini](docs/fortigate-setup.md) izleyin: boş syslog hedefini bulma, mevcut hedefleri koruyan TCP 5514 komutları, FLS kaynak/kullanıcı izinleri, ilk kaydı doğrulama ve isteğe bağlı salt okunur API hesabı adım adım anlatılır. Çoklu VDOM kapsamını kontrol edin; `root` adı tek başına VDOM modunu göstermez. Mevcut üretim API hesabını test kurulumu için yeniden kullanmayın. [VM kabul sırası](docs/installation.md#ilk-açılış-ve-kabul-sırası).

Veri kökü `/srv/fls-server`, ayrı depo diskinin bağlama noktası `/srv/fls-storage` olarak kullanılır. Önceki bir RC denemesinden RC6'ya geçerken temiz Ubuntu snapshot'ına dönüp yeniden kurun; kurucu mevcut kurulumu yerinde güncellemez.

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
