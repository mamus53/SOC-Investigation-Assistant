# SOC Investigation Assistant

Chrome yan panelinde dosya, süreç, DLL, script ve ağ göstergeleri için hızlı SOC araştırması yapmaya yardımcı olan Manifest V3 uzantısı.

Amaç, bir analistin karşılaştığı dosya veya süreç adını tek başına zararlı/meşru olarak etiketlemek yerine; olası işlevi, beklenen konumu, meşru kullanım alanlarını, bilinen kötüye kullanım örneklerini ve sonraki inceleme adımlarını aynı yerde değerlendirmesini kolaylaştırmaktır.

## Öne çıkan özellikler

- **Çevrimdışı dosya ve süreç kataloğu:** Yerel katalogda 206.055 benzersiz ad bulunur. İsim eşleşmeleri araştırma başlangıcıdır; dosyanın kimliğini, imzasını veya güvenliğini tek başına doğrulamaz.
- **Seçili metni inceleme:** Web sayfasında bir dosya adı, hash, IP, domain veya URL seçilerek uzantı panelinde araştırma başlatılabilir.
- **Bağlam ve SOC yönlendirmesi:** Dosya/süreç profilleri; işlev, konum, kullanım bağlamı ve analistin kontrol edebileceği noktalar için kısa bilgiler sunar.
- **VirusTotal sorguları:** Hash, IP, domain ve URL göstergeleri kullanıcı tarafından başlatılan sorguyla VirusTotal üzerinden incelenebilir.
- **AbuseIPDB sorguları:** IP adresleri, kullanıcının kendi API anahtarı ve verdiği izinle AbuseIPDB üzerinden kontrol edilebilir.
- **Dosyayı yüklemeden hash:** Desteklenen dosya akışında dosya içeriği uzantı içinde yerel olarak hash'lenir; dosyanın kendisi VirusTotal'a yüklenmez.

## Kurulum

1. Bu depoyu indirin veya klonlayın.
2. Chrome'da `chrome://extensions` sayfasını açın.
3. **Geliştirici modu** seçeneğini etkinleştirin.
4. **Paketlenmemiş öğe yükle** düğmesine tıklayın ve bu deponun kök klasörünü seçin.
5. Uzantıyı araç çubuğuna sabitleyin; simgeye tıklayarak yan paneli açın.
6. Bir web sayfasında araştırmak istediğiniz metni seçin ve uzantının **Analiz Et** eylemini kullanın.

Ayrıntılı kurulum ve güncelleme notları için [`KURULUM.txt`](KURULUM.txt) dosyasına bakın.

## Tehdit istihbaratı API ayarları

Çevrimdışı katalog API anahtarı gerektirmez. Çevrimiçi sorgular için ilgili servis hesabınızdan kendi anahtarınızı uzantı panelindeki ayarlara girin:

- [VirusTotal](https://www.virustotal.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)

İlk sorguda ilgili servise erişim izni istenir. API anahtarları Chrome uzantısının yerel depolama alanında tutulur. Bu nedenle kaynak koduna, ekran görüntülerine, issue kayıtlarına veya herkese açık commit'lere API anahtarı eklemeyin. Servislerin kota, gizlilik ve kullanım koşulları kullanıcı hesabına bağlıdır.

**Veri aktarımı:** Sorgu başlatıldığında yalnızca sorgulanan gösterge (ör. hash, IP, domain veya URL) ilgili servise gönderilir. Gizli/kurum içi IOC'leri, müşteri verilerini veya paylaşma yetkiniz olmayan göstergeleri harici servislere göndermeyin. Dosya adı kataloğu çevrimdışı çalışır.

## Chrome izinleri

Manifest'te kullanılan temel izinler:

- `sidePanel`: Chrome yan panelini açmak için.
- `storage`: Kullanıcı tercihleri ve API anahtarlarını uzantı depolamasında saklamak için.
- `contextMenus`: Bağlam menüsü üzerinden araştırma akışını desteklemek için.
- `https://www.virustotal.com/*` ve `https://api.abuseipdb.com/*`: İlgili çevrimiçi sorgu başlatıldığında isteğe bağlı olarak talep edilen sunucu izinleri.

İçerik betiği HTTP/HTTPS sayfalarında seçili metinle etkileşimi sağlar. Uzantı, seçilen göstergeyi kullanıcı açıkça araştırma başlatmadan tehdit istihbaratı servislerine göndermemelidir.

## Sınırlamalar ve analist notu

- Dosya adı, uzantı, yol veya tekil bir itibar sonucu kesin hüküm değildir. Aynı isim meşru yazılımlarda ve kötüye kullanım senaryolarında görülebilir.
- `rundll32.exe`, `regsvr32.exe`, PowerShell ve benzeri sistem araçları meşru amaçlarla kullanılabilir; değerlendirme tam yol, imza, komut satırı, parent process, kullanıcı ve olay zaman çizelgesiyle birlikte yapılmalıdır.
- VirusTotal'da rapor bulunmaması veya sıfır tespit, dosyanın güvenli olduğunu kanıtlamaz.
- Bu araç bir EDR/antivirüs ürünü, sandbox veya otomatik olay müdahale sistemi değildir. Nihai karar analistin bağlamsal incelemesine dayanmalıdır.

## Kaynaklar ve lisans

Katalog ve profil notlarında açık kaynak ve kamuya açık referanslardan yararlanılmıştır. Kaynakların kapsamı, sürüm notları ve atıf bilgileri şu dosyalarda tutulur:

- [`KAYNAKLAR-23.3.txt`](KAYNAKLAR-23.3.txt)
- [`SOURCE-LICENSE-ATTRIBUTION-v810.md`](SOURCE-LICENSE-ATTRIBUTION-v810.md)
- [`SOURCE-MANIFEST-225.json`](SOURCE-MANIFEST-225.json)
- [`THIRD-PARTY-NOTICES-v580.md`](THIRD-PARTY-NOTICES-v580.md) ve önceki sürüm bildirimleri
- [`MITRE-ATTACK-LICENSE.txt`](MITRE-ATTACK-LICENSE.txt)

**Önemli lisans notu:** Bu depoya genel proje lisansı eklenmemiştir. Üçüncü taraf kaynakların kendi lisansları ve koşulları geçerlidir. Özellikle GPL-3.0 ve CC BY-NC-SA 3.0 kapsamındaki kaynaklardan türetilen içerikleri yeniden dağıtmadan veya ticari amaçla kullanmadan önce ilgili koşulları inceleyin. Üçüncü taraf bildirimleri, projenin tamamı için otomatik bir açık kaynak lisansı verildiği anlamına gelmez.

## Geliştirme ve test

Uzantı, Chrome Manifest V3 ile hazırlanmıştır; manifest'te belirtilen minimum Chrome sürümü **138**'dir. Kaynak dosyalar doğrudan uzantı paketinde bulunur. Katalog JSON parçaları uygulamanın çevrimdışı arama verisidir; yayın paketinden çıkarılmamalıdır.

Değişikliklerden sonra `chrome://extensions` sayfasında uzantıyı yenileyin ve ilgili sayfaları da yeniden yükleyin. Özellikle API izinleri, depolama, seçili metin akışı ve çevrimdışı arama davranışını test edin.

## Sorumluluk reddi

Bu proje güvenlik araştırması ve savunma amaçlı triage desteği için sunulur. Sağlanan içerik “olduğu gibi” verilir; eksiksizlik, güncellik veya belirli bir ortamda doğru sonuç garantisi yoktur. Üretim ortamında kullanmadan önce kurumunuzun güvenlik, gizlilik ve lisans politikalarına göre doğrulama yapın.

## GitHub'a yükleme

İlk yayın için [GITHUB-YAYIN.md](GITHUB-YAYIN.md) dosyasındaki Git komutlarını kullanabilirsiniz.
