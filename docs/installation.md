# Temiz Ubuntu VM ile kurulum denemesi

İlk sürüm `v0.76.0-rc.2`, ayrı VM kabul testi bekleyen bir test sürümüdür. Mevcut çalışan FLS sunucusuna kurulmaz. Kurucu mevcut FLS, veri dizini veya MariaDB veritabanı izleri varsa yazmaya başlamadan durur.

## VM hazırlığı

- Ubuntu Server 24.04 LTS, amd64, 8 GiB RAM; kullanım miktarına göre büyütülebilen disk, en az 40 GiB boş alan.
- Ubuntu kurucusunda düz ext4 sistem bölümü seçin; LVM, RAID ve şifreli blok aygıtı bu ilk profilde desteklenmez. EFI/boot bölümleri bulunabilir; FLS bunları değiştirmez.
- Sanallaştırıcıda diske benzersiz ve sabit bir seri numarası veya WWID atayın. Kopyalanmış VM'lere aynı disk kimliğini vermeyin. Udev/sysfs üzerinden doğrulanamayan fiziksel kimlik kurulumu durdurur.
- Sabit/rezervasyonlu IPv4, yönetim bilgisayarından HTTPS erişimi ve Ubuntu/GitHub indirmeleri için internet erişimi sağlayın. Kurucu ağ, DNS veya hipervizör ayarlarını değiştirmez.
- **Kurulumdan önce temiz VM snapshot'ı alın.** İlk denemeyi tek diskle yapın; ikinci diski sonraki aşamada ekleyin.

VMware ESXi'de disk WWN/seri bilgisi boşsa test VM'yi kapatın. **Edit Settings → VM Options → Advanced → Configuration Parameters** bölümünde `disk.EnableUUID` değerini `TRUE` yapıp VM'yi açın. `lsblk -o NAME,TYPE,WWN,SERIAL` ile kimliğin göründüğünü doğrulayın. Bu, dosya sistemini yeniden oluşturmayı gerektirmez. [Broadcom'un resmî yönergesi](https://knowledge.broadcom.com/external/article/418101/mapping-a-linux-guest-os-disk-to-its-cor.html). Uzun ESXi NAA kimliği tam WWID olarak korunur; 16 haneye kısaltılmaz.

README'deki sabit sürüm komutunu çalıştırın. Kurucu ayrı paket deposu/PPA eklemez. Ubuntu'nun PHP 8.3, MariaDB 10.11 ve diğer paketleri kullanılır. Sistem rsyslog'u ayrı kalır; FLS'nin kontrollü yazım düzeltmesi içeren collector'ı sürüm paketinden özel `/opt/fortigate/` yoluna kurulur. Native araçlar kaynak deposu yerine doğrulanmış sürüm arşivinde bulunur.

Birden fazla uygun ağ adresi olduğunda otomatik seçim yapılmaz:

```sh
sudo bash fls-install.sh --apply \
  --bind-ip 192.0.2.10 --hostname fls.example.invalid \
  --management-network 192.0.2.0/24
```

Bu örnek adresleri kendi ağınıza göre değiştirin. Seçilen bind adresi makinede atanmış olmalıdır; yönetim CIDR'si panelin erişim sınırıdır. Kurucu DNS kaydı oluşturmaz. HTTPS için kurulum başına yeni CA ve SAN sertifikası üretir. İlk tarayıcı erişiminde CA henüz güvenilir değildir; `/etc/nginx/fls-tls/ca.crt` dosyasını yönetim cihazında doğrulayıp güvenilir hale getirin veya kendi sertifika yönetiminizi uygulayın.

## Ön kontrol ve yeniden deneme

Tek başına indirilmiş başlangıç betiği de imzalı paketi indirip kurulum yapmadan denetleyebilir:

```sh
sudo bash fls-install.sh --check
```

Başarılı kontrolde çıkış kodu 0, engelde 2'dir. `blockers` koşulları, `probe_errors` okunamayan sistem bilgilerini gösterir. İndirme/geçici açma dışında hedef yapılandırma yazılmaz; paket, servis veya veritabanı kurulmaz. Kontrol, mevcut kurulum izlerini de raporlayabilir.

`--apply` ön kontrolde durursa `installation_started:false`, `target_modified:false` ve `retry:fix_preflight_and_retry` döner; parola dosyası oluşmaması beklenir. Koşulu düzeltip tekrar kontrol edin. **Sadece ön kontrol engeli için temiz snapshot'a dönüş gerekmez.** Paket/servis aşaması başladıktan sonraki hatalarda ise önce kanıtları kaydedip temiz snapshot'a dönün. Başlamış kurulumun üzerine tekrar uygulama yapılmaz.

## İlk açılış ve kabul sırası

1. `sudo cat /etc/fls/bootstrap-credentials.txt` ile ilk `admin` parolasını alın; panelde değiştirin. Parola çıktı günlüklerine basılmaz.
2. Panelde tek sistem diski, boş olaylar ve **durdurulmuş log alımı** göründüğünü doğrulayın. Normal kullanıcıların disk/yedek/güç yönetimini göremediğini kontrol edin.
3. Test FortiGate bağlantısı ve izinli gönderici ekleyin. Yönetimden alımı açıkça başlatın. TCP 5514'e gelen test kayıtlarının ham dosyada ve arayüzde göründüğünü doğrulayın. Cihazın hedef ayarını yalnız test ortamına yönlendirin.
4. Yeniden başlatıp HTTPS, servisler ve aynı kayıtların tekrar eklenmeden okunmasını kontrol edin.
5. Logsuz FLS System Backup ve günlük DB dump üretin; indirmeyi ve varsa test FTPS aktarımını sınayın. Şifreleme açılacaksa kurtarma özel anahtarını sunucu dışında saklayın.
6. Yeni boş ikinci sanal disk ekleyip [taşıma denemesini](storage-migration.md) yapın. Sonra yeniden başlatma ve depo diski eksik olduğunda yazımın durması senaryolarını sınayın.
7. Sorunda hata kodunu, kurulum aşamasını ve ilgili servis günlüklerini kaydedin; sırları paylaşmayın. Temiz snapshot'a dönün, düzeltilmiş sürümden tekrar başlayın. Başlamış/yarım kurulum otomatik tekrar edilmez.

Root'a özel kurulum durumu `/var/lib/fls-community-install/journal.json` içindedir. Bir aşamaya geçmeden önce niyet kalıcı yazılır. Hata halinde önceki aşamalar otomatik geri alınmaz; bu VM kabul akışında temiz snapshot'a dönüş kullanılır. Başarılı kurulumun üzerine `--apply` güncelleme yöntemi değildir.

## Yedek ve kurtarma sınırı

Logsuz yedek; yazılım, sistem veritabanı/ayarları ve gerekli anahtarları içerir; günlük log arşivinin yerine geçmez. Sağlayıcı SDK'sı ve ücretli lisans çekirdeği Community yedeğinde zorunlu değildir. Git geçmişi gerekmez; kurulu sürümün dosya manifesti doğrulanır.

Panel kurtarma kitinin çevrimdışı bağımlılık paketi ayrıca `bin/prepare-recovery-runtime.py` ile hazırlanır. Hazır olmayan kit hazırmış gibi sunulmaz. Kurtarma motorunun dosya/kimlik testleri ayrı bir Ubuntu cihazında tam geri yükleme provasının yerine geçmez. İlk kurulum ve ikinci disk VM kabulü tamamlanana kadar üretim kullanımı doğrulanmış sayılmaz.

## Güven zinciri

Kurucu sabit sürümden `release.json` ve Ed25519 imzasını indirir; gömülü yayımlayıcı açık anahtarı ile doğruladıktan sonra arşivin uzunluğunu ve SHA-256'sını denetler. Arşivde yol geçişi, link, aygıt dosyası ve beklenmeyen dosya kipleri reddedilir; kurulum motoru tam dosya envanterini yeniden doğrular. Başlangıç betiğini aldığınız GitHub hesabı/tag'ı ilk güven kaynağıdır; imza bu ilk kaynağa olan güvenin yerine geçmez.
