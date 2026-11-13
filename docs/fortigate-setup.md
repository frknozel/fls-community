# FortiGate'i FLS'ye bağlama

Bu rehber, mevcut log hedefini koruyarak FLS'ye ikinci bir syslog kopyası göndermeyi ve ardından isteğe bağlı salt okunur API bağlantısını kurmayı anlatır. CLI örnekleri FortiOS 7.6.x içindir; model, sürüm ve VDOM kapsamına göre alanlar değişebilir. Komutları uygulamadan önce rehberi bütünüyle okuyun ve örnek değerleri kendi ortamınıza uyarlayın.

Community test kurulumunda gerçek FortiGate kayıtlarının API anahtarı olmadan panelde görünmesi kullanıcı tarafından doğrulanmıştır. Bu, aşağıdaki bütün API yetkilerinin her FortiOS/model üzerinde doğrulandığı veya uzun süreli alım, yedek ve disk taşıma kabulünün tamamlandığı anlamına gelmez.

## 1. Adresleri ve rolleri ayırın

Buradaki adresler dokümantasyon içindir; doğrudan kullanılmaz.

| Bilgi | Örnek | Anlamı |
|---|---|---|
| FLS alıcı IP'si | `192.0.2.10` | FortiGate'in TCP 5514 ile ulaşacağı sunucu |
| FortiGate syslog kaynak IP'si | `192.0.2.254` | FortiGate'in bir arayüzüne atanmış, bu yoldan kullanılabilen IP |
| FLS'nin göreceği TCP kaynak IP'si | `192.0.2.254` | NAT varsa çevrilmiş gönderici adresi olabilir |
| API için FLS çıkış IP'si | `192.0.2.10` | FortiGate'in HTTPS bağlantısında göreceği kaynak; NAT varsa ayrıca belirlenir |
| FortiGate TLS alan adı | `fg.example.invalid` | HTTPS sertifikasındaki adla eşleşen gerçek alan adıyla değiştirilir |
| API bağlantı IP'si / HTTPS portu | `192.0.2.254` / `443` | Mevcut HTTPS yönetim adresi ve portu |
| API için gelişmiş FLS çıkış bağlama IP'si | `192.0.2.10` | Kullanılırsa Linux sunucuya atanmış yerel adres; FortiGate'in kaynak IP'si değildir |
| Cihaz kimliği / VDOM | `FGT_EXAMPLE_001` / `root` | Gerçek seri numarası ve logdaki VDOM adıyla değiştirilir |

Syslog yönü **FortiGate → FLS**, API yönü **FLS → FortiGate** şeklindedir. Syslog kaynağı, TCP göndereni ve API çıkış adresi farklı amaçlara hizmet eder. FLS'de birine izin vermek diğerini otomatik yetkilendirmez. Cihaz bağlantısını düzenlerken gelişmiş çıkış IP'si alanını kullanıyorsanız buraya Linux sunucunun yerel adresini girin; kurulum formundaki FortiGate syslog kaynak IP'sini kopyalamayın. Ayrıca `root` adı, çoklu VDOM'un kapalı olduğunu tek başına göstermez.

## 2. FLS alıcısını ve cihaz erişimini hazırlayın

İlk denemede ayrı test VM'sini kullanın. Temiz işletim sistemi snapshot'ını ve başarılı FLS kurulumu snapshot'ını saklayın. Snapshot'a dönüş aradaki kayıtları da geri alır; bunu devam eden üretim arşivinin yerine kullanmayın.

1. FLS yönetici panelinde **Log sunucusu → Log alımı → Başlat** seçin ve **Çalışıyor** durumunu bekleyin. İlk kaynak izni uygulanırken alıcının çalışması gerekir.
2. **Ayarlar → FortiGate'ler ve API anahtarları** bölümünde gerçek seri numarası ve VDOM ile cihazı ekleyin. İlk syslog denemesinde **Hazırlık / devre dışı** durumu uygundur.
3. Cihazın **Kurulum ve doğrulama → Log gönderimi ve sunucu izni** bölümünde kaynak IP, sunucunun göreceği TCP kaynak IP'si ve FLS alıcı IP'sini girin. API trusted-host alanına API bağlantısının çıkış IP'sini yazın. Syslog hedefini aşağıdaki envantere göre seçin.
4. **Bu TCP kaynağına izin ver** seçeneğini işaretleyip **Kaynağı kaydet ve sunucuya uygula** işlemini tamamlayın. Yalnız formu doldurmak izin uygulamak değildir; onay sonucunu kontrol edin.
5. **Kullanıcı hesapları** bölümünde kendi hesabınıza ilgili FortiGate'i görüntüleme erişimi verin. Yönetici rolü, cihaz erişiminin ayrıca atanması gereğini kaldırmaz.

**Etkin** cihaz durumu FortiGate API sorgulamasını açar ve en az bir etkin API anahtarı ister. Syslog alma ve yetkili kullanıcının logları incelemesi için cihazı Etkin yapmak gerekmez. API kuruluncaya kadar API/canlı durum kontrolleri beklemede kalabilir.

## 3. Mevcut FortiGate hedeflerini okuyun

FortiGate web panelindeki CLI konsolunda önce salt okunur bilgileri alın:

```text
get system status
show full-configuration log syslogd setting
show full-configuration log syslogd2 setting
show full-configuration log syslogd3 setting
show full-configuration log syslogd4 setting
```

FortiOS sürümünü, **Virtual domain configuration** durumunu ve mevcut hedefleri kaydedin. Etkin üretim hedefini değiştirmeyin. `status disable` görünen fakat sunucu veya başka ayarlar içeren bir hedefi de otomatik olarak boş kabul etmeyin; kullanım amacını netleştirin. Uygun boş hedef yoksa burada durun.

**Aşağıdaki uygulama örneği yalnız çoklu VDOM kapalı ve `syslogd2` gerçekten boşsa kullanılır.** Başka boş hedef seçtiyseniz uygulama, filtre, doğrulama ve geri alma bloklarındaki bütün `syslogd2` adlarını aynı hedefle değiştirin. FLS formundaki hedef seçimini de eşleştirin. Seçtiğiniz hedefin filtresini uygulama öncesinde okuyun:

```text
show full-configuration log syslogd2 filter
```

Çoklu VDOM açıksa global hedeflerle ilgili VDOM'un override hedefleri ayrı değerlendirilir. Salt okunur olarak ilgili VDOM'da mevcut durumu inceleyin:

```text
config vdom
    edit "root"
        show full-configuration log setting
        show full-configuration log syslogd2 override-setting
        show full-configuration log syslogd2 override-filter
    next
end
```

VDOM adını gerçek kapsamla değiştirin; mevcut olmayan bir adı `edit` ile oluşturmayın. Bu komutlar mevcut VDOM'u seçmek içindir. Override'ı açmak o VDOM'un mevcut log yönlendirmesini değiştirebilir. Mevcut `syslog-override` ve global/VDOM akışı anlaşılmadan override açmayın veya bu rehberin tek cihaz uygulama bloğunu kullanmayın. FLS'de doğru kapsamı seçerek VDOM'a özgü komutları ayrıca hazırlayın. Desteklenmeyen komutta hata metnini ve CLI bağlamını saklayın; rastgele alternatif ayar uygulamayın. [Fortinet: VDOM başına syslog hedefleri](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/610676/configuring-multiple-fortianalyzers-or-syslog-servers-per-vdom).

## 4. Boş ek hedefe TCP syslog gönderin

Tek cihaz / çoklu VDOM kapalı örneği:

```text
config log syslogd2 setting
    set status enable
    set server "192.0.2.10"
    set mode reliable
    set port 5514
    set facility local7
    set source-ip "192.0.2.254"
    set format default
    set priority default
    set max-log-rate 0
    set enc-algorithm disable
    set interface-select-method auto
    set vrf-select 0
end

config log syslogd2 filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
end

show full-configuration log syslogd2 setting
show full-configuration log syslogd2 filter
```

`source-ip`, FortiGate'in gerçekten kullanabileceği atanmış adres olmalıdır. Örnekte VRF 0 ve otomatik arayüz seçimi kullanılır; farklı yönlendirme/VRF gerektiren ağlarda bunları uygulamadan önce kendi rotanıza uyarlayın. `max-log-rate 0` hız sınırı uygulamaz; test sunucusunun kapasitesini ve oluşan hacmi izleyin. Mevcut özel filtreler varsa eklediğiniz ayarların onları nasıl etkilediğini ayrıca kontrol edin. Gönderim filtresi, firewall policy üzerinde üretilmeyen bir trafik kaydını kendiliğinden üretmez; ilk test için mevcut loglanan trafiği kullanın.

`reliable`, TCP taşımasıdır. Bu örnek **TCP 5514 üzerinde şifrelenmemiş syslog** kullanır; TLS syslog kurulumu değildir. Bunu güvenilir yönetim ağında veya korunan ağ yolunda kullanın. API'nin HTTPS sertifikası bu syslog akışını şifrelemez. [Fortinet: syslog hedefi CLI alanları](https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/141516630/config-log-syslogd-setting).

FortiGate, 514 yerine 5514 kullanıldığını belirtip `Do you want to continue? (y/n)` sorarsa, doğru hedefte portun **5514** olduğunu kontrol edip `y` ile onaylayın. Son `show` çıktılarında hedef adresini, portu ve modu yeniden kontrol edin.

## 5. İlk gerçek kaydı doğrulayın

FLS'de kaynak izni uygulandıktan sonra **Bağlantıyı ve yeni logu sına** işlemini kullanın. Kaynak izni ve yeni log eşleşmesini ayrı kontrol edin; API anahtarı yokken bütün kurulum kontrollerinin yeşil olması beklenmez.

**Engeller ve kayıtlar** ekranında doğru FortiGate'i seçin. **Hangi kayıtlar? → Tüm kayıtlar**, zaman aralığı **Bugün** seçip filtreleri uygulayın. Varsayılan güvenlik engelleri filtresi, yalnız normal trafik gelen bir denemede boş kalabilir. Yeni kayıtların zamanını ve seri/VDOM eşleşmesini kontrol edin. **Log sunucusu** ekranında ham veri ve indeks ilerlemesini, kuyruk ve yazım hatalarını inceleyin. **Çalışıyor** göstergesi tek başına uçtan uca log kabulünün kanıtı değildir.

## 6. İsteğe bağlı salt okunur API hesabı ekleyin

API; canlı cihaz bilgileri, policy ve profil okuması içindir. FLS, FortiGate'in mevcut HTTPS yönetim servisine bağlanır. Bu işlem için WAN yönetim erişimi açmak veya mevcut üretim API hesabının anahtarını değiştirmek gerekmez. Hesabı oluşturan yönetici `super_admin` yetkisine sahip olmalıdır; oluşturulacak FLS API hesabına aşağıdaki salt okuma profili atanır, `super_admin` verilmez.

Önce aşağıdaki adların boş olduğunu doğrulayın:

```text
show system accprofile "FLS_COMMUNITY_RO"
show system api-user "fls_community"
```

Bu adlardan biri mevcutsa onu yeniden düzenlemeyin veya anahtarını yenilemeyin. Yeni, ayırt edilebilir profil ve hesap adları seçip aşağıdaki bütün kullanımları birlikte değiştirin. Aynı FortiGate'e bağlı başka FLS kurulumunun hesabını paylaşmayın. Çoklu VDOM açık cihazda profil/hesap oluşturma bağlamı ayrıca doğrulanmalıdır; aşağıdaki blok tek cihaz / çoklu VDOM kapalı örneğidir.

```text
config system accprofile
    edit "FLS_COMMUNITY_RO"
        set comments "FLS Community read-only monitoring"
        set fwgrp read
        set utmgrp read
        set vpngrp read
        set netgrp read
        set sysgrp read
        set authgrp none
        set loggrp none
        set ftviewgrp none
        set secfabgrp none
        set wanoptgrp none
        set wifi none
        set cli-config disable
        set cli-exec disable
        set cli-diagnose disable
        set cli-get disable
        set cli-show disable
    next
end

config system api-user
    edit "fls_community"
        set accprofile "FLS_COMMUNITY_RO"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost 192.0.2.10 255.255.255.255
            next
        end
    next
end

show system accprofile "FLS_COMMUNITY_RO"
show system api-user "fls_community"
```

Trusted host, **FortiGate'in API bağlantısında göreceği FLS çıkış adresi** olmalıdır. `/32` örneğini geniş ağ iznine çevirmeyin. Yalnız gereken beş yetki grubu `read`, diğer yetki grupları `none` kalmalıdır; yazma veya CLI yetkisi vermeyin. Bu grupların FLS'nin kullandığı bütün uç noktalar için yeterliliği model/sürüm üzerinde ayrıca sınanır. Bir alan desteklenmiyorsa işlemi durdurup sürümün CLI belgesini kontrol edin. [Fortinet: erişim profili](https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/309990135/config-system-accprofile), [REST API yöneticisi](https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/399023/rest-api-administrator).

Doğru yeni hesap için anahtarı **bir kez** üretin:

```text
execute api-user generate-key fls_community
```

Anahtarı yalnız FLS panelinde ilgili cihazın **+ API anahtarı** alanına girin; sohbet, ekran görüntüsü, issue veya genel günlüklerle paylaşmayın. Anahtarı URL'ye, kaynak koda ya da açık metin notlarına eklemeyin. Aynı komutu yeniden çalıştırmak mevcut anahtarı değiştirebilir; bağlantı hatasını bu komutu tekrarlayarak çözmeye çalışmayın. [Fortinet: API anahtarı üretme](https://docs.fortinet.com/document/fortigate/7.6.6/cli-reference/302621566/execute-api-user).

FLS'deki TLS alan adı, FortiGate HTTPS sertifikasının SAN/adıyla eşleşmelidir. Bağlantı IP'sini ve gerçek HTTPS yönetim portunu ayrı girin. Özel CA kullanılıyorsa CA yöneticisinden aldığınız, kimliğini ayrıca doğruladığınız açık CA sertifikasını FLS sunucusunun güven deposuna ekleyin. Örneğin Ubuntu üzerinde, dosya yolunu kendi CA sertifikanızla değiştirerek:

```sh
sudo install -m 0644 /path/to/verified-organization-ca.crt \
  /usr/local/share/ca-certificates/fls-fortigate-ca.crt
sudo update-ca-certificates
```

CA sertifikası PEM biçiminde ve `.crt` uzantılı olmalıdır; her dosyada tek sertifika kullanın. Bu dosya CA'nın **açık sertifikasıdır**; özel anahtarını sunucuya kopyalamayın. CA'ya güvenmek, yanlış TLS alan adını veya süresi dolmuş sertifikayı düzeltmez. [Ubuntu: güven deposuna CA ekleme](https://ubuntu.com/server/docs/how-to/security/install-a-root-ca-certificate-in-the-trust-store/).

FortiGate HTTPS sertifikasının kendisi de doğru ad ve zincirle yapılandırılmış olmalıdır; sertifika doğrulamasını kapatmayın. Anahtarı etkin kaydedip **Sına** işlemini çalıştırın. Ardından cihazı **Etkin** yapın ve canlı durum/policy okumalarını doğrulayın. TLS hatası, 401 ve 403 farklı nedenlerdir; syslog'un çalışıyor olması API bağlantısını doğrulamaz.

## 7. Sorunları ayırın ve test gönderimini durdurun

| Belirti | İlk kontrol |
|---|---|
| Cihazı Etkin yaparken API anahtarı isteniyor | Syslog denemesinde Hazırlık durumunu koruyun; API gerekiyorsa ayrı anahtarı ekleyin. |
| Menüler kapalı / cihaz seçilemiyor | Kullanıcı hesabına cihaz görüntüleme erişimini atayın ve paneli yenileyin. |
| Alıcı çalışıyor, yeni kayıt yok | Kaynağı kaydedip sunucuya uyguladığınızı, gerçek TCP peer IP'sini, TCP 5514 rotasını ve ek hedefi kontrol edin. |
| Ham veri var, rapor boş | Doğru seri/VDOM, cihaz seçimi, zaman aralığı, Tüm kayıtlar filtresi ve indeks ilerlemesini kontrol edin. |
| Kaynak kabul edildi, yeni log eşleşmedi | İşlemden sonra üretilmiş kaydı bekleyin; FortiGate filtrelerini ve loglanan trafiği kontrol edin. |
| API sertifika hatası | TLS alan adı, SAN, geçerlilik zamanı ve CA zincirini kontrol edin. |
| API 401 / 403 | Sırasıyla anahtar/geçerlilik ve gerekli salt okuma yetkilerini inceleyin; trusted-host adresini de doğrulayın. |

Testi sonlandırırken yalnız eklediğiniz hedefin gönderimini kapatın; ilk hedefi veya başka cihazın hesabını değiştirmeyin. Aşağıdaki blok yine **tek cihaz / `syslogd2`** örneğidir:

```text
config log syslogd2 setting
    set status disable
end
show full-configuration log syslogd2 setting
```

Bu, ek hedefi silmez; yalnız gönderimini durdurur. Farklı slot veya VDOM override kullandıysanız geri alma da aynı slot ve kapsamda yapılmalıdır. FLS tarafındaki kaynak izni ve kullanıcı erişimini kaldırmak ayrı işlemlerdir; ortak kullanılan kaynağı kaldırmadan önce diğer cihazları kontrol edin.

İlk kayıt görüldükten sonraki kabul adımları: alım açıkken test VM'sini yeniden başlatma, kuyruk/yazım denetimi, logsuz sistem yedeği ve indirme, ikinci diske taşıma ve ayrı Ubuntu cihazında tam kurtarma provasıdır. Bunları yalnız ilk logun görünmesine dayanarak tamamlandı saymayın.
