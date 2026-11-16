# FLS Community logsuz sistem yedeği ve kurtarma provası

FLS System Backup; uygulamayı, veritabanı tablo yapılarını, kullanıcı ve yetkileri,
cihaz/aktarım ayarlarını, FLS veritabanı hesaplarını ve gerekli kasa, imza ve TLS
anahtarlarını korur. Veritabanından yalnız yapılandırma tablolarının satırları
alınır. Ham loglar, olaylar, geçmiş raporlar, arşivler, zaman damgası kanıtları,
alıcı kuyruğu, oturumlar, önbellekler ve eski yedek dosyaları bu pakette yoktur.
Bu paket Ubuntu disk imajı değildir; açılış düzenini veya geçmiş logları kurtarmaz.

RC6'nın iki diskli kullanıcı VM'sinde yedek oluşturma ve indirme doğrulandı.
Paylaşılan paketin dosya/kaynak hash'leri, logsuz SQL kapsamı ve imza/TLS anahtar
eşleşmeleri salt okunur incelendi; ayrı hedefte tam kurtarma henüz yapılmadı.
Bu RC6 yedeğinde fiziksel ana depo birimi `srv-fls\x2dstorage.mount` eksiktir;
altı bind mount ve servis bağımlılıkları ise bulunur. Özgün hibrit düzeni bu
paketten birebir yeniden kurma tamamlanmış bir kurtarma yöntemi değildir.
Aşağıdaki tek diskli prova motoru eski mount'ları ve HDD bağımlılıklarını
yüklemez; hedef kimliğiyle yeni `system-root` düzeni oluşturur. Dolayısıyla bu
eksik, desteklenen tek diskli prova akışını engellemez. Geliştirme kaynağındaki
kapsam düzeltmesi ana depo birimini sonraki yedekler için de seçer; mevcut
imzalı RC6 kurulum paketi ve alınmış yedek bu kaynak güncellemesiyle değişmez.

## Yedeği oluşturma ve dışarıda saklama

1. Yönetici olarak **Ayarlar → Arşiv ve Yedekleme → FLS System Backup** düğmesine
   basın. İş arka planda ilerler. Yalnız **Doğrulandı** durumundaki paketi kullanın.
2. Yedek dosyasını, SHA-256 dosyasını ve doğrulama raporunu sistem dışında saklayın.
   Paneldeki FTPS aktarımı, yapılandırılmış ve doğrulanmış hedefi kullanır.
3. Şifreleme etkinse `.age` kopyasını ve onun doğrulama dosyalarını da saklayın.
   `age` kurtarma özel anahtarını yedekten ayrı, güvenli bir yerde tutun. Bu anahtar
   sunucudan kaldırıldıktan sonra yedek dosyası kayıp anahtarın yerine geçmez.

**Yedek bir sır kasasıdır.** İçinde FLS'nin imza/kasa özel anahtarları, TLS özel
anahtarları, parola hash'leri ve veritabanı hesap bilgileri bulunur. `.tar.gz`
sıkıştırmadır, şifreleme değildir. Şifreli bağlantı bilgileri de paketteki kasa
anahtarıyla açılabilir. Dosyaları Git'e, herkese açık web dizinine veya bir hata
bildirimine eklemeyin. FLS'nin paket içindeki anahtarları ile ayrı saklanan `age`
kurtarma özel anahtarı farklıdır; dışarıya teslim edilen `age` özel anahtarı bu
pakete eklenmez.

Doğrulama raporu; dosya hash'lerini, geçici ve ağ bağlantısı kapalı MariaDB'ye
bağımsız geri yüklemeyi, yapılandırma satırlarının birebir korunmasını, diğer
veri tablolarının boş kalmasını, SQL hesaplarını ve anahtar eşleşmelerini sınar.
Bu kontrol, ayrı Ubuntu cihazında baştan sona kurtarma provasının yerine geçmez.

## Kurtarma kitini önceden hazırlama

**Yedekten geri dön**, seçilen yedeğe bağlı ayrı bir başlangıç kiti indirir;
kaynak sunucuda geri yükleme çalıştırmaz. Kit, yedek dosyasını veya `age` özel
anahtarını içermez. Panelin bu kiti verebilmesi için çevrimdışı bağımlılık paketi
önceden hazırlanmış olmalıdır. Normal kurulum bu büyük paketi kendiliğinden
hazırlamaz; kit hazır değilse panel işlemi reddeder. Bu durum logsuz yedek
oluşturmayı veya dosyasını indirmeyi engellemez.

Kaynakla uyumlu Ubuntu 24.04 amd64 paketlerini, bütün gerekli `.deb`
bağımlılıklarıyla birlikte güvenilir bir root dizininde toplayın. Paket listesini
önce kurulu aracın salt okunur planından öğrenin:

```sh
sudo python3 /var/www/fls/bin/prepare-recovery-runtime.py
```

Eksiksiz ve doğrulanmış paket dizini hazır olduğunda, örnekteki dizin yerine kendi
güvenilir dizininizi kullanarak yayımlayın:

```sh
sudo python3 /var/www/fls/bin/prepare-recovery-runtime.py \
  --publish --packages /root/fls-recovery-packages
```

Araç hedefe işletim sistemi paketi kurmaz; verilen `.deb` dosyalarını ve `age`
aracını denetleyip kurtarma kitine gereken paketi üretir. Yalnız üst düzey
paketleri içeren bir dizin yeterli değildir: temiz hedefte gereken bağımlılıkların
da bulunması gerekir. Şüpheli dosyaları kabul ettirmek için izin, hash veya
kaynak denetimlerini kaldırmayın.

## Ayrı ve boş Ubuntu üzerinde tek diskli prova

İlk desteklenen akış, **yalnız prova amacıyla ayrı bir Ubuntu 24.04 amd64
cihazına** geri yüklemedir. [Kurulum kılavuzundaki](installation.md) disk kimliği
koşulları geçerlidir: düz ext4 kök bölümü ve udev/sysfs üzerinden doğrulanabilen
sabit disk kimliği gerekir. LVM/RAID kökü bu akışta desteklenmez. Hedefte FLS,
uygulama veritabanı veya önceki yarım kurtarma durumu bulunmamalıdır. Hedefin
boş alanı hem açılacak paket hem geri yükleme çalışması için yeterli olmalıdır;
sihirbaz ayrıca alan denetimi yapar.

1. Yeni Ubuntu'yu kurun ve temiz snapshot alın. Hedefi kaynakla çakışmayan bir IP
   adresinde ve yalıtılmış test ağında tutun. FortiGate'ten bu hedefe log yönlendirmeyin.
   Boş hedefe önce normal FLS kurucusunu çalıştırmayın; kurtarma başlangıcı FLS'nin
   kurulu olmadığı bir hedef ister.
2. Kaynak panelde doğrulanmış yedeği seçip **Yedekten geri dön** ile kitini indirin.
   Yedek ve gerekiyorsa `.age` anahtar dosyası elinizde, sistem dışında bulunmalıdır.
   Kaynak sunucuya erişim kaybedilmeden önce kiti de dışarıda saklamak yararlıdır.
3. Güvenilen kiti yeni hedefe kopyalayın. Aşağıdaki `KURTARMA-KITI.tar` yerine
   indirdiğiniz kitin gerçek yolunu yazın. Komutlar yalnız **yeni hedefte** çalışır:

   ```sh
   sudo -i
   install -d -m 0700 /root/fls-recovery
   tar -xf KURTARMA-KITI.tar -C /root/fls-recovery
   cd /root/fls-recovery/fls-recovery
   python3 start.py
   ```

4. Konsol HTTPS adresini, sertifika SHA-256 parmak izini ve tek kullanımlık giriş
   kodunu gösterir. Konsolu açık tutun. Yönetim cihazından hedefin `8444` portundaki
   adrese bağlanın; sertifika parmak izini konsolla karşılaştırıp kodla giriş yapın.
   Başlangıç oturumu en fazla sekiz saat geçerlidir. Kod veya özel anahtarı URL'ye,
   komut satırına veya sohbet mesajına yazmayın.
5. Seçilen `.tar.gz` veya kitin tanıdığı `.age` yedeğini yükleyin. Şifreli kopya
   için dışarıda tuttuğunuz `age` anahtar dosyasını sihirbazda seçin. Anahtar hedef
   sunucunun belleğinde kullanılır; kurtarma akışı onu dosyaya kaydetmez.
6. **Yedeği doğrula ve önizle** adımında hedef kimliğini, sürümü ve kapsamı inceleyin.
   Başlatmak için `TAMAM` yazıp **Prova geri yüklemesini başlat** düğmesine basın.
   Aynı kaynağa geri yükleme reddedilir. Eski ağ, açılış, `fstab` ve HDD bağlantıları
   yeni donanıma körlemesine uygulanmaz; tek disk kimliği hedefe göre hazırlanır.
7. Başarılı sonuçtaki prova arayüzü bağlantısını açın. Bu ayrı HTTPS arayüzü
   `8443` portundadır ve hedefe ait yeni sertifika kullanır. Yedekteki yönetici
   hesabıyla kullanıcıları, cihazları, ayarları ve sürümü denetleyin. Log geçmişinin
   boş olması beklenir.

## Geri yükleme sonrasında kapalı kalan işler

Prova arayüzü **bakım/duraklatılmış** durumda kalır. Log alıcısı ve normal veri
üreten işçiler başlatılmaz; ücretli zaman damgalama, otomatik paketleme ve harici
aktarım otomatik etkinleştirilmez. Eski güç komutları, çalışma kuyrukları ve tekrar
önleme günlükleri yeniden yürütülmez; kurtarma için taze çalışma durumu kurulur.
Kaynak sistem çalışırken kurtarılan kopyayı ikinci bir etkin FLS gibi kullanmayın.
Üretime geçiş bu prova sihirbazının kapsamı dışındadır ve ayrıca planlanmalıdır.

Hata halinde ekrandaki sabit hata kodunu ve aşamayı saklayın. Root'a özel çalışma
kanıtları hedefte `/var/lib/fls-recovery` altındadır; içeriklerini gelişigüzel
paylaşmayın. Başlamış veya yarım geri yüklemeyi zorlayarak yeniden oynatmayın.
Sorun incelendikten sonra temiz snapshot'a dönüp düzeltilmiş kit ile yeniden
başlayın. Eski diskleri formatlamak veya çalışan kaynağı değiştirmek gerekmez.

## Paket ve kurulu kaynak sözleşmesi

Arşivin `backup/` dizininde şu temel kaynaklar bulunur:

| Kaynak | Amaç |
| --- | --- |
| `system.tar` | Uygulama, gerekli servis/config dosyaları ve anahtarlar |
| `database.sql.gz` | Tablo yapıları ve özgün yapılandırma satırları |
| `database-accounts.sql` | FLS SQL hesapları ve dar yetkileri |
| `restore-safe.sql` | Yalnız yeni hedefe uygulanacak güvenli başlangıç durumu |
| `MANIFEST.json` ve `inventory/` | Kapsam, hash'ler, hesap/dizin/paket envanterleri |
| `RESTORE.md` | Bu kılavuzun yedekle birlikte saklanan kopyası |

Geri yükleme motoru arşivin ve içeriğin hash'lerini bağımsız doğrular; arşivdeki
rastgele betikleri doğrudan çalıştırmaz. `restore-safe.sql` çalışan kaynağa veya
mevcut logları olan bir veritabanına uygulanmaz.

Community kurulumu Git geçmişi gerektirmez. Kurulu ağacın
`deploy/release-files.json` dosyası, sürümün bütün kaynak dosyalarını SHA-256 ve
izinleriyle listeler. Sistem yedeği bu manifesti ve dosyaları doğrular. Eksik veya
elle değiştirilmiş kaynak, yanlış izinler ya da beklenmeyen dosyalar doğrulamayı
durdurabilir; manifest denetimini atlamak bir onarım yöntemi değildir. Kurtarma
kitinin başlangıç betiği ve motoru da root sahipliği ve dosya bütünlüğü kontrollerine
tabidir.

Günlük logsuz **DB dump**, tablo/ayar kurtarmasına yardımcı olur; yazılımı,
SQL hesaplarının parolalarını ve dosya anahtarlarını tek başına içermez. Tam FLS
kurtarma kopyasının yerine geçmez. Geçmiş log ve arşivlerin ayrı saklanması ile
[ikinci disk taşıma akışı](storage-migration.md) ayrıca yönetilir.
