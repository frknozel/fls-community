# Temiz Ubuntu VM ile kurulum denemesi

`v0.76.0-rc.4`, uçtan uca kabul testi henüz tamamlanmamış bir test sürümüdür. Ayrı bir VMware ESXi / Ubuntu 24.04 VM'de temiz kurulum, yönetici girişi, tek disk rolleri, `/srv/fls-server` yolları, yeniden başlatma sonrası panelin açılması ve durdurulmuş log alımının korunması kullanıcı tarafından doğrulandı. Log alımı panelden başlatıldı; gönderici izni uygulandıktan sonra gerçek FortiGate kayıtlarının API anahtarı olmadan arayüzde görünmesi de kullanıcı tarafından doğrulandı. Alım açıkken yeniden başlatma/süreklilik, kuyruk-yazım denetimi, yedekler, ikinci diske taşıma ve tam kurtarma kabulü henüz bekliyor. Mevcut çalışan FLS sunucusuna kurulmaz. Kurucu mevcut FLS, veri dizini veya MariaDB veritabanı izleri varsa yazmaya başlamadan durur.

Bu sürümün mantıksal veri kökü `/srv/fls-server` dizinidir. MariaDB/indeksler ve geçici teslim kuyruğu sistem diskinde bu kökte tutulur. Ayrı depo diski `/srv/fls-storage` altında bağlanır; log ve yedek dizinleri bu depodan mantıksal köke bağlanır. RC3 veya daha eski bir denemeden geçerken temiz Ubuntu snapshot'ına dönüp yeniden kurun; `--apply` yerinde güncelleme veya eski yedeği dönüştürme aracı değildir.

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

Kurucunun son sağlık kontrolü HTTPS/sürüm bilgisinin yanında disk işçisini bir kez çalıştırır ve panelin PHP okuma modeli üzerinden güncel, bağlı sistem diski envanterini doğrular. Bu kontrol başarısızsa kurulum tamamlandı olarak bildirilmez. Kontrol yalnız yeni, disk işi bulunmayan kurulum veritabanında çalışır.

## İlk açılış ve kabul sırası

1. `sudo cat /etc/fls/bootstrap-credentials.txt` ile ilk `admin` parolasını alın; panelde değiştirin. Parola çıktı günlüklerine basılmaz.
2. Panelde tek sistem diski, boş olaylar ve **durdurulmuş log alımı** göründüğünü doğrulayın. Normal kullanıcıların disk/yedek/güç yönetimini göremediğini kontrol edin.
3. Yalnız test VM'sini yeniden başlatın. HTTPS, panel ve disk rollerini; log alımının hâlâ durdurulmuş olduğunu doğrulayın. Bu kurulu durumun ayrı bir snapshot'ını saklayın.
4. **İlk kaynak iznini uygulamadan önce** Log sunucusu → Log alımı bölümünden alımı başlatın ve **Çalışıyor** durumunu bekleyin. Bu sürümde ilk kaynak izni uygulanırken alıcının çalışması gerekir.
5. Test FortiGate'i doğru seri numarası ve VDOM adıyla ekleyin; cihaz **Hazırlık / devre dışı** durumunda kalabilir. İlk syslog denemesi için API anahtarı zorunlu değildir. Kaynak/gönderici iznini tanımlayın ve yönetici hesabına cihazı görüntüleme erişimini ayrıca verin; bunlar farklı izinlerdir.
6. Aşağıdaki FortiGate ön kontrolünden sonra gerçekten boş bir ek syslog hedefi seçin. Mevcut çalışan FLS hedefini ve global/VDOM yönlendirmesini koruyarak test VM'sinin TCP 5514 portuna ek kopya gönderin. Gelen kayıtların ham dosyada ve arayüzde göründüğünü, indeksin ilerlediğini ve yazım/kuyruk hatası olmadığını doğrulayın. Alıcının **Çalışıyor** görünmesi tek başına gerçek log kabulü sayılmaz.
7. Log alımı açıkken test VM'sini yeniden başlatın; HTTPS, servisler ve aynı kayıtların tekrar eklenmeden okunmasını kontrol edin.
8. Logsuz FLS System Backup ve günlük DB dump üretin; indirmeyi ve varsa test FTPS aktarımını sınayın. Şifreleme açılacaksa kurtarma özel anahtarını sunucu dışında saklayın.
9. Yeni boş ikinci sanal disk ekleyip [taşıma denemesini](storage-migration.md) yapın. Sonra yeniden başlatma ve depo diski eksik olduğunda yazımın durması senaryolarını sınayın.
10. Sorunda hata kodunu, kurulum aşamasını ve ilgili servis günlüklerini kaydedin; sırları paylaşmayın. Temiz snapshot'a dönün, düzeltilmiş sürümden tekrar başlayın. Başlamış/yarım kurulum otomatik tekrar edilmez.

### API anahtarı olmadan logları görüntüleme

Cihazdaki **Etkin** seçeneği FortiGate API sorgulamasını açar ve bu nedenle en az bir etkin API anahtarı ister. İlk syslog kabulünde cihaz **Hazırlık / devre dışı** durumunda kalabilir. Bu durum kullanıcıya atanmış cihazın loglarını raporlardan çıkarmaz; API/canlı durum kontrolleri ayrı olarak bekleyebilir.

Üç adımı ayrı tamamlayın: FortiGate'te ek hedefi tanımlamak, FLS'de **Kaynağı kaydet ve sunucuya uygula** ile TCP göndericisini kabul etmek ve kullanıcı hesabına cihazı görüntüleme erişimi vermek. Kaynak izni onaylandıktan sonra yeni log eşleşmesini ve kayıtları kontrol edin.

**Engeller ve kayıtlar** ekranının varsayılan filtresi yalnız güvenlik engellerini gösterebilir. İlk denemede **Hangi kayıtlar? → Tüm kayıtlar**, uygun zaman aralığı ve doğru FortiGate seçimini kullanın. Boş bir filtre sonucu, tek başına alımın durmuş olduğunu göstermez.

### FortiGate'e ek test hedefi hazırlığı

Komutları uygulamak için [FortiGate bağlantı rehberini](fortigate-setup.md) kullanın. Rehber, boş hedef seçimi ve TCP syslog komutlarının yanında FLS izinlerini, doğrulamayı, yalnız eklenen hedefi durdurmayı ve ayrı salt okunur API hesabını kapsar. Aşağıdaki bölüm uygulama öncesi envanterin kısa özetidir.

Önce FortiOS sürümünü ve VDOM çalışma biçimini salt okunur komutla öğrenin:

```text
get system status
```

Ardından mevcut dört syslog hedefini okuyun. VDOM kapalıysa cihazın normal CLI bağlamını, çoklu VDOM açıksa global bağlamı kullanın:

```text
show full-configuration log syslogd setting
show full-configuration log syslogd2 setting
show full-configuration log syslogd3 setting
show full-configuration log syslogd4 setting
```

FLS'deki `root` VDOM adı, FortiGate'te çoklu VDOM'un kapalı olduğu anlamına gelmez. Çoklu VDOM açıksa ilgili VDOM'un `syslog-override` durumunu ve mevcut `override-setting` / `override-filter` ayarlarını da okuyun. Mevcut akışı anlamadan override açmayın veya global hedefi değiştirmeyin. Komut desteklenmiyorsa çıktısını ve CLI bağlamını kaydedin; başka bir yapılandırma uygulayarak aşmaya çalışmayın.

Hedef adını önceden `syslogd2` olarak varsaymayın. Kapalı olsa bile sunucu adresi kayıtlı bir hedefin amacı önce netleştirilmelidir. Sürüm, VDOM bağlamı ve mevcut hedefler görüldükten sonra boş ek hedefe özgü komutları hazırlayın. [Fortinet: VDOM başına birden fazla syslog hedefi](https://docs.fortinet.com/document/fortigate/latest/administration-guide/610676/configuring-multiple-fortianalyzers-or-syslog-servers-per-vdom), [VDOM override davranışı](https://docs.fortinet.com/document/fortigate/7.2.7/administration-guide/557920/override-fortianalyzer-and-syslog-server-settings).

Bu aşamada panelin API hesabı oluşturan tüm kurulum komutlarını çalıştırmak gerekmez. API bağlantısı sonradan eklenecekse örneğin `FLS_API_1` adlı hesap mevcut üretim FLS'si için kullanılıyorsa test kurulumu adına yeniden kullanılmamalıdır; test için ayrı hesap adı seçin.

Root'a özel kurulum durumu `/var/lib/fls-community-install/journal.json` içindedir. Bir aşamaya geçmeden önce niyet kalıcı yazılır. Hata halinde önceki aşamalar otomatik geri alınmaz; bu VM kabul akışında temiz snapshot'a dönüş kullanılır. Başarılı kurulumun üzerine `--apply` güncelleme yöntemi değildir.

## Yedek ve kurtarma sınırı

Logsuz yedek; yazılım, sistem veritabanı/ayarları ve gerekli anahtarları içerir; günlük log arşivinin yerine geçmez. Sağlayıcı SDK'sı ve ücretli lisans çekirdeği Community yedeğinde zorunlu değildir. Git geçmişi gerekmez; kurulu sürümün dosya manifesti doğrulanır.

Panel kurtarma kitinin çevrimdışı bağımlılık paketi ayrıca `bin/prepare-recovery-runtime.py` ile hazırlanır. Hazır olmayan kit hazırmış gibi sunulmaz. Kurtarma motorunun dosya/kimlik testleri ayrı bir Ubuntu cihazında tam geri yükleme provasının yerine geçmez. İlk kurulum ve ikinci disk VM kabulü tamamlanana kadar üretim kullanımı doğrulanmış sayılmaz.

## Güven zinciri

Kurucu sabit sürümden `release.json` ve Ed25519 imzasını indirir; gömülü yayımlayıcı açık anahtarı ile doğruladıktan sonra arşivin uzunluğunu ve SHA-256'sını denetler. Arşivde yol geçişi, link, aygıt dosyası ve beklenmeyen dosya kipleri reddedilir; kurulum motoru tam dosya envanterini yeniden doğrular. Başlangıç betiğini aldığınız GitHub hesabı/tag'ı ilk güven kaynağıdır; imza bu ilk kaynağa olan güvenin yerine geçmez.
