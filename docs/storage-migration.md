# Disk rolleri ve ikinci diske geçiş

| Düzen | Sistem diskinde | Ayrı depo diskinde |
| --- | --- | --- |
| Tek disk (`system-root`) | Ubuntu, FLS, MariaDB/indeksler, geçici dayanıklı kuyruk ve tüm log/yedekler | Henüz yok |
| İki disk (`hybrid`) | Ubuntu, FLS, MariaDB/indeksler ve 10 GB sınırlı dayanıklı kuyruk | Ham kayıt, arşiv, metrik, logsuz yedek ve günlük DB dump |
| Üç disk | Aynı sistem ve ana depo | Üçüncü disk yalnız ana deponun saatlik rsync kopyası |

Bu geçiş işçisi uygulanmıştır; ayrı boş VM'de uçtan uca disk/yeniden başlatma kabulü henüz tamamlanmamıştır. İlk denemeyi snapshot'lı VM'de yapın.

## Panelde ikinci disk

**Yönetici → Ayarlar → Disk ve depolama** ekranı disk kimliklerini, rolleri ve dizinleri gösterir. Tek diskli kurulumda uygun ek disk için **hazırla ve kayıtları taşı** işlemi sunulur. Herhangi bir ek disk kendiliğinden seçilmez veya silinmez.

Önizlemede model, seri/WWID, tam kapasite ve **diskin bütün içeriğinin kalıcı silineceği** gösterilir. İşlemi başlatmak için büyük harfle tam `TAMAM` yazılır. Sunucu ayrıca rol, CSRF, zaman aşımı ve disk envanterine bağlı imzalı token'ı kontrol eder. Kimliği değişmiş, sistem diski olan, kullanılan, salt okunur, çıkarılabilir veya yeterli kapasitesi bulunmayan hedefler reddedilir. Hedefin sistem diski kadar büyük olması gerekmez; mevcut taşınacak veri ve boşluk payı sığmalıdır.

İşçi yeni hedefi GPT üzerinde tek ext4 bölüm olarak hazırlar. Kayıt alımını ve ilgili yazıcı servis/zamanlayıcılarını durdurur; panel, MariaDB ve iş takibi çalışır kalır. Durdurma engeli yeniden başlatmada da korunur. ACL, xattr, hardlink, sahiplik ve dosya içeriği karşılaştırıldıktan sonra geçiş yapılır. Kaynak log inode/checkpoint eşlemesi aynı olayların yeniden indekslenmesini önlemek için uyarlanır; olay kimlikleri ve byte offset'leri korunur.

| Mantıksal yol | Depoda karşılığı |
| --- | --- |
| `/srv/fortigate/raw` | `/srv/fls-storage/FLS-Logs/raw` |
| `/srv/fortigate/archive` | `/srv/fls-storage/FLS-Logs/archive` |
| `/srv/fortigate/metrics` | `/srv/fls-storage/FLS-Logs/metrics` |
| `/srv/fortigate/backups` | `/srv/fls-storage/FLS-Backups/staging` |
| `/var/lib/fls-recovery-download` | `/srv/fls-storage/FLS-Backups/published` |
| `/srv/fortigate/db-dumps` | `/srv/fls-storage/DB-Dump` |

Kalıcı bind mount'lar uygulamanın kullandığı yolları korur. UUID ile fiziksel kimlik birlikte doğrulanır; depo yoksa SSD'deki boş dizine sessiz yazım yapılmaz. Eski SSD verileri bind mount altında korunur, **otomatik silinmez**. Bu sürümde eski kopyanın alanını boşaltmak ayrı doğrulama ve bakım gerektirir.

Hata veya güç kesintisinde root günlüğü `/var/lib/fls-disks/primary-migration.json` hangi adımların başladığını/tamamlandığını tutar; log alımı durdurulmuş kalır. İşlem otomatik biçimlendirme, inode güncelleme veya geri alma tekrarı yapmaz. Hedefte yeni yazım başladıysa eski veriye körlemesine geri dönülmez. Prova sırasında hata kanıtlarını saklayıp snapshot'a dönün; üretimde elle uzlaştırma gerekir.

## Üçüncü disk

Ana depodan küçük olmayan uygun üçüncü disk aynı açık silme onayıyla tek ext4 bölüm hazırlanır. Başka role atanamaz. Saatlik rsync değişmeyen dosyaları yeniden yazmaz; günlük kapsam ve önceki günün kapanış eşitlemesi kullanılır. Kaynak silmeleri eşlemeye yansıyabilir; rsync geçmişe dönüş sağlayan yedek değildir. FTPS kopyası ve logsuz sistem yedeği ayrı işlevlerdir. Fiziksel disk kabulü, bağlantı kesilmesi ve saatlik eşleme kullanıcı VM testinde ayrıca sınanmalıdır.

`bin/storage_migration_plan.py` eski schema 1 JSON sözleşmesini çevrimdışı değerlendiren ayrı geliştirme aracıdır; gerçek disk yönetiminin yerine kullanılmaz. Yeni kurulum ve panel işçisi schema 2'nin doğrulanmış WWN/WWID/seri kimliklerini kullanır. Düz ext4 dışındaki LVM/RAID hedefler desteklenmez.
