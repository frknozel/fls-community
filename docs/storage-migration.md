# Disk rolleri ve ikinci diske geçiş

| Düzen | Sistem diskinde | Ayrı depo diskinde |
| --- | --- | --- |
| Tek disk (`system-root`) | Ubuntu, FLS, MariaDB/indeksler, geçici dayanıklı kuyruk ve tüm log/yedekler | Henüz yok |
| İki disk (`hybrid`) | Ubuntu, FLS, MariaDB/indeksler ve 10 GB sınırlı dayanıklı kuyruk | Ham kayıt, arşiv, metrik, logsuz yedek ve günlük DB dump |
| Üç disk | Aynı sistem ve ana depo | Üçüncü disk yalnız ana deponun saatlik rsync kopyası |

RC6'nın ayrı ESXi / Ubuntu test VM'sinde 200 GiB sistem diskinden 100 GiB ikinci diske panel üzerinden geçişi 16 Kasım 2026'da tamamlandı. Taşıma sonrası panelden yeniden başlatmada FLS açıldı ve loglar kendiliğinden gelmeye devam etti. Alıcının `syslog:adm` hesabıyla salt okunur depolama denetimi geçti; ayrı ext4 depo, altı log/yedek bağlantısı ve sistem diskinde kalan kuyruk doğrulandı. Beş temel servis çalışıyor ve başarısız birim yok. Sayfa yenilemelerinde açık ayrıntı ve kaydırma konumunun korunduğu da kullanıcı tarafından doğrulandı. Tüm logların eksiksizliği ve disk eksikken koruma kabulü henüz tamamlanmadı. İlk denemeyi snapshot'lı VM'de yapın.

Uygulamanın veri kökü `/srv/fls-server`, ayrı depo diskinin bağlama noktası `/srv/fls-storage` olarak sabittir. MariaDB `/srv/fls-server/database/mysql`, geçici kuyruk `/srv/fls-server/queue` altında sistem diskinde kalır. `/opt/fortigate` collector çalışma zamanı ve `/etc/fortigate` collector yapılandırması için korunur.

## Panelde ikinci disk

**Yönetici → Ayarlar → Disk ve depolama** ekranı disk kimliklerini, rolleri ve dizinleri gösterir. Tek diskli kurulumda uygun ek disk için **hazırla ve kayıtları taşı** işlemi sunulur. Herhangi bir ek disk kendiliğinden seçilmez veya silinmez.

Önizlemede model, seri/WWID, tam kapasite ve **diskin bütün içeriğinin kalıcı silineceği** gösterilir. İşlemi başlatmak için büyük harfle tam `TAMAM` yazılır. Sunucu ayrıca rol, CSRF, zaman aşımı ve disk envanterine bağlı imzalı token'ı kontrol eder. Kimliği değişmiş, sistem diski olan, kullanılan, salt okunur, çıkarılabilir veya yeterli kapasitesi bulunmayan hedefler reddedilir. Hedefin sistem diski kadar büyük olması gerekmez; mevcut taşınacak veri ve boşluk payı sığmalıdır.

RC6, deponun `FLS-Logs` ve `FLS-Backups` üst dizinlerini root sahipliğinde `0711` ile oluşturur; servisler gerekli alt dizinlerin kimliğini kontrol edebilir. Özel yedek/DB dump alt dizinlerinin izinleri ve kopyalanan dosyaların ACL'leri genişletilmez. Bağlantılar hazırlandıktan sonra depolama kontrolü alıcının `syslog` hesabıyla da geçmeden servisler açılmaz.

İşçi yeni hedefi GPT üzerinde tek ext4 bölüm olarak hazırlar. Kayıt alımını ve ilgili yazıcı servis/zamanlayıcılarını durdurur; panel, MariaDB ve iş takibi çalışır kalır. Durdurma engeli yeniden başlatmada da korunur. ACL, xattr, hardlink, sahiplik ve dosya içeriği karşılaştırıldıktan sonra geçiş yapılır. Kaynak log inode/checkpoint eşlemesi aynı olayların yeniden indekslenmesini önlemek için uyarlanır; olay kimlikleri ve byte offset'leri korunur.

| Mantıksal yol | Depoda karşılığı |
| --- | --- |
| `/srv/fls-server/raw` | `/srv/fls-storage/FLS-Logs/raw` |
| `/srv/fls-server/archive` | `/srv/fls-storage/FLS-Logs/archive` |
| `/srv/fls-server/metrics` | `/srv/fls-storage/FLS-Logs/metrics` |
| `/srv/fls-server/backups` | `/srv/fls-storage/FLS-Backups/staging` |
| `/var/lib/fls-recovery-download` | `/srv/fls-storage/FLS-Backups/published` |
| `/srv/fls-server/db-dumps` | `/srv/fls-storage/DB-Dump` |

Kalıcı bind mount'lar uygulamanın kullandığı yolları korur. UUID ile fiziksel kimlik birlikte doğrulanır; depo yoksa SSD'deki boş dizine sessiz yazım yapılmaz. Eski SSD verileri bind mount altında korunur, **otomatik silinmez**. Bu sürümde eski kopyanın alanını boşaltmak ayrı doğrulama ve bakım gerektirir.

Ayarlar sayfasındaki otomatik yenileme açık ayrıntı bölümlerini ve kaydırma konumunu korur; disk işi bağımsız olarak izlenir.

Hata veya güç kesintisinde root günlüğü `/var/lib/fls-disks/primary-migration.json` hangi adımların başladığını/tamamlandığını, son komutun sabit işlem/birim adını ve çıkış durumunu tutar; komut çıktısı veya gizli argümanlar rapora eklenmez; log alımı durdurulmuş kalır. İşlem otomatik biçimlendirme, inode güncelleme veya geri alma tekrarı yapmaz. Hedefte yeni yazım başladıysa eski veriye körlemesine geri dönülmez. Prova sırasında hata kanıtlarını saklayıp snapshot'a dönün; üretimde elle uzlaştırma gerekir.

## Üçüncü disk

Ana depodan küçük olmayan uygun üçüncü disk aynı açık silme onayıyla tek ext4 bölüm hazırlanır. Başka role atanamaz. Saatlik rsync değişmeyen dosyaları yeniden yazmaz; günlük kapsam ve önceki günün kapanış eşitlemesi kullanılır. Kaynak silmeleri eşlemeye yansıyabilir; rsync geçmişe dönüş sağlayan yedek değildir. FTPS kopyası ve logsuz sistem yedeği ayrı işlevlerdir. Fiziksel disk kabulü, bağlantı kesilmesi ve saatlik eşleme kullanıcı VM testinde ayrıca sınanmalıdır.

`bin/storage_migration_plan.py` eski schema 1 JSON sözleşmesini çevrimdışı değerlendiren ayrı geliştirme aracıdır; gerçek disk yönetiminin yerine kullanılmaz. Yeni kurulum ve panel işçisi schema 2'nin doğrulanmış WWN/WWID/seri kimliklerini kullanır. Düz ext4 dışındaki LVM/RAID hedefler desteklenmez.

RC5 kullanıcı denemesinde kopyalama ve bağlantılar tamamlanmış, servisleri açma aşamasında üst dizin izinleri nedeniyle durulmuştur. `new_writes_possible=true` olan bu durumda hedefte yeni veri oluşmuş olabilir. Eski sistem diski kopyasına dönmeyin, aynı taşıma isteğini yeniden yürütmeyin veya koruma işaretlerini elle kaldırmayın. Kabul denemesini RC6 ile tekrarlamak için iki diskin birlikte temiz olduğu snapshot düzenini kullanın ve temiz Ubuntu üzerine kurun. Yalnız kurulu RC5 snapshot’ına dönmek, RC6 kurucusunu çalıştırmak için yeterli değildir.
