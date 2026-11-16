# FLS Community logsuz sistem yedeği ve kurtarma provası

FLS System Backup; uygulamayı, veritabanı tablo yapılarını, kullanıcı ve yetkileri,
cihaz/aktarım ayarlarını, FLS veritabanı hesaplarını ve gerekli kasa, imza ve TLS
anahtarlarını korur. Veritabanından yalnız yapılandırma tablolarının satırları
alınır. Ham loglar, olaylar, geçmiş raporlar, arşivler, zaman damgası kanıtları,
alıcı kuyruğu, oturumlar, önbellekler ve eski yedek dosyaları bu pakette yoktur.
Bu paket Ubuntu disk imajı değildir; açılış düzenini veya geçmiş logları kurtarmaz.

RC6'nın iki diskli kullanıcı VM'sinde yedek oluşturma ve indirme doğrulandı.
Paylaşılan paketin dosya/kaynak hash'leri, logsuz SQL kapsamı ve imza/TLS anahtar
eşleşmeleri salt okunur incelendi. Aynı yedekle ayrı ve temiz Ubuntu 24.04 amd64
VirtualBox hedefinde tek diskli kurtarma provası kullanıcı tarafından tamamlandı:
sihirbaz `succeeded · complete` sonucunu verdi, yedekteki yönetici hesabıyla giriş
yapıldı, üç prova servisi etkin ve başarısız birim sayısı sıfırdı. Log alıcısı ve
indeksleyici maskeli kaldı; depolama yeni hedef kimliğiyle `system-root` olarak
doğrulandı. Yeniden başlatma sonrasında da `8443` prova paneline giriş yapıldı;
aynı üç servis etkin, başarısız birim sayısı sıfır, log alıcısı ve indeksleyici
maskeliydi. Depolama aynı hedef kimliğiyle `system-root` kaldı. Kullanıcı ve cihaz
ayarları korundu, geçmiş loglar boş ve log alımı duraklatılmış durumdaydı.
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

İnternete erişebilen Community kaynak VM'de [paket hazırlama aracını](../tools/prepare-recovery-packages.py)
ayrı bir dosya olarak çalıştırabilirsiniz. Bu araç kurulu FLS dosyalarını
değiştirmez; gerekli paketleri özel bir çalışma dizinine indirir, yalnız yerel
depo kullanan ve boş paket durumuyla çalışan APT simülasyonunda bağımlılıkların
tamamlandığını doğrular, ardından kurulu runtime yayımlayıcısını çağırır.
Kaynak sunucuya paket kurmaz veya servis başlatıp durdurmaz. Bu bağımsız araç
geliştirme kaynağında yayımlanır; imzalı RC6 kurulum paketine eklenmiş değildir.

RC6 kabul denemesinde bu araçla 173 paket ve yaklaşık 85 MiB çevrimdışı runtime
hazırlanması kullanıcı tarafından doğrulandı. Kaynakta kurulu paketler, uygulama
dosyaları ve servisler değiştirilmedi. Bu paketle ayrı VirtualBox hedefindeki
tek diskli kurtarma provası ve yeniden başlatma kontrolü tamamlandı. Bu kabul,
prova arayüzündeki aşağıda açıklanan RC6 durum gösterimi sorununu kapsamaz.

Araç yalnız **kurulu Community v0.76.0-rc.6** kaynağını kabul eder; sürüm makbuzunu,
kaynak envanterini ve kullandığı yardımcıların hash'lerini doğrular. Aracı
**çalışan Community kaynak VM'de** çalıştırın. Yeni kurtarma hedefinde
çalıştırılmaz; hedefte FLS kurulu bulunmamalıdır.
`prepare-recovery-packages.py` dosyasını kaynak VM'ye indirdikten sonra:

```sh
sudo python3 prepare-recovery-packages.py --plan &&
sudo python3 prepare-recovery-packages.py --prepare
```

Ön kontrol indirme veya runtime yayımlaması yapmaz. İndirme veya bağımlılık
doğrulaması başarısızsa runtime yayımlanmaz; sabit hata kodunu ve özel günlük
yolunu saklayın. Başarılı hazırlıktan sonra kaynak panelde doğrulanmış yedeğin
**Yedekten geri dön**
işlemiyle başlangıç kitini indirin. Yedek, kit ve varsa ayrı `age` anahtarı
kurtarma hedefinde birlikte kullanılacaktır.

Hazırlama aracı her denemede yeni, özel bir çalışma dizini kullanır. İndirme
başlamadan oluşan bir araç hatasını düzeltmek için kaynak VM'yi yeniden kurmak
gerekmez; güncellenmiş bağımsız araçla ön kontrol ve hazırlık tekrarlanabilir.

Elle veya çevrimdışı hazırlık tercih ederseniz kaynakla uyumlu Ubuntu 24.04 amd64
paketlerini, bütün gerekli `.deb` bağımlılıklarıyla birlikte güvenilir bir root
dizininde toplayın. Paket listesini
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

Kurtarma akışı ESXi gerektirmez; VirtualBox hedefi de aynı işletim sistemi,
ext4 ve disk kimliği kontrollerinden geçmelidir. WWN bulunmadığında güvenilir
seri numarası kullanılabilir. İlk alan kontrolü en az 8 GiB boşluk ister;
başlangıç ayrıca yedeğin üç katı, runtime paketinin dört katı ve 1 GiB pay
hesabını denetler. Açılmış yedek için ek alan kontrolü de vardır. Normal
kurucunun 40 GiB boş alan koşulu bu kurtarma sınırının yerine geçmez. Küçük,
logsuz bir yedek için 16 GiB boş alan uygun olabilir; gerçek kit boyutu ve
hedef ön kontrolü sonucu belirler. VirtualBox'ta temiz Ubuntu kurulumu sonrası
snapshot alın; kaynak FLS'ye ait IP adresini hedefe vermeyin veya FortiGate'ten
hedefe log yönlendirmeyin.

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
   `running · packages` aşaması paketler kurulurken birkaç dakika sürebilir.
   Bu sırada yükleme ve başlatma düğmelerinin kapalı kalması normaldir;
   **Durumu yeniden oku** ile ilerlemeyi kontrol edin.
7. Başarılı sonuçtaki prova arayüzü bağlantısını açın. Bu ayrı HTTPS arayüzü
   `8443` portundadır ve hedefe ait yeni sertifika kullanır. Yedekteki yönetici
   hesabı ve kaynakta yedek alınırken geçerli olan parolayla giriş yapın;
   kullanıcıları, cihazları, ayarları ve sürümü denetleyin. Log geçmişinin boş
   olması beklenir. `8444` kurtarma sihirbazıdır; `8443` geri yüklenen FLS prova
   arayüzüdür. Yeniden başlatma sonrası sihirbazın kapanması beklenir;
   etkinleştirilen `fls-rehearsal-web` servisi prova arayüzünü sunmaya devam eder.

## Geri yükleme sonrasında kapalı kalan işler

Prova arayüzü **bakım/duraklatılmış** durumda kalır. Log alıcısı ve normal veri
üreten işçiler başlatılmaz; ücretli zaman damgalama, otomatik paketleme ve harici
aktarım otomatik etkinleştirilmez. Eski güç komutları, çalışma kuyrukları ve tekrar
önleme günlükleri yeniden yürütülmez; kurtarma için taze çalışma durumu kurulur.
Kaynak sistem çalışırken kurtarılan kopyayı ikinci bir etkin FLS gibi kullanmayın.
Üretime geçiş bu prova sihirbazının kapsamı dışındadır ve ayrıca planlanmalıdır.

RC6 yedeğiyle yapılan gerçek provada, disk envanterini güncelleyen işçi de
maskeli kaldığı için **Disk ve depolama** ekranı boş başlangıç kaydını
`state_invalid` olarak gösterdi. Aynı hedefte depolama doğrulaması ve servis
kontrolleri başarılıydı; bu arayüz hatası tek başına disk arızası anlamına gelmez.
Eski arayüzdeki **Log alımını başlat** isteği de kuyruğa yazılabilse bile maskeli
işçi tarafından uygulanmaz. Provanın log alımını kapalı tutması beklenir; bu
düğmenin kullanılabilir görünmesi ve disk durumunun hata gibi sunulması RC6
arayüzünün eksikliğidir.

Geliştirme kaynağındaki düzeltme, ayrı prova web sunucusunun verdiği güvenilir
`FLS_RECOVERY_REHEARSAL` FastCGI işaretiyle prova bağlamını tanır. Disk ve log
alımı durumları, güncel envanter doğrulanmış gibi gösterilmeden, işçilerin kapalı
olduğunu açıklar. Log alımı, disk yönetimi ve güç işlemlerinin düğmeleri
kapatılır; korunan işlem istekleri kuyruğa yazılmadan
`recovery_rehearsal_read_only` koduyla reddedilir. Kurtarma denetimi, bu desteği
içeren uygulamalarda yalnız HTTP başarısını değil bu prova durumunu da doğrular.

Bu düzeltme henüz yeni imzalı sürümde yayımlanmamıştır; mevcut RC6 kurulum
paketi, alınmış yedek ve çalışan prova VM'si değiştirilmez. Eski yedek kendi
uygulama dosyalarını geri yüklediğinden yeni kit kullanılması tek başına eski
arayüzü güncellemez. Eski yedekle desteklenen kurtarma çalışabilir; geliştirme
motorunun kontrol raporundaki `rehearsal_ui_supported: false`, yeni prova
arayüzü sözleşmesinin o yedekte bulunmadığını belirtir. Düzeltilmiş arayüzün
ayrı kabulü, bu desteği içeren yayımlanmış uygulama ve ondan alınan yedekle
henüz yapılmamıştır.

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
