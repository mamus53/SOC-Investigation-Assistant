# Güvenlik Bildirimi

Bir güvenlik açığı veya hassas veri ifşası fark ederseniz, ayrıntıları herkese açık bir issue içinde paylaşmayın. Depo sahibine GitHub üzerinden özel bir iletişim kanalıyla ulaşın.

## API anahtarları ve hassas göstergeler

- VirusTotal ve AbuseIPDB anahtarlarını kaynak koda, commit geçmişine, ekran görüntülerine veya issue/PR içeriklerine eklemeyin.
- Gerçek müşteri IOC'lerini, dahili IP/domain bilgilerini veya gizli olay verilerini örnek/test verisi olarak yayımlamayın.
- Yanlışlıkla anahtar yayımlandıysa ilgili sağlayıcı panelinden anahtarı iptal edip yenileyin; yalnızca commit'i silmek yeterli değildir.
- Harici sorgular kullanıcı tarafından başlatılır. Gönderilen göstergelerin üçüncü taraf sağlayıcıların saklama ve paylaşım politikalarına tabi olduğunu unutmayın.

## Güvenlik değerlendirmesi

Bu uzantı bir triage yardımcısıdır. İsim eşleşmesi, imza bilgisi veya tehdit istihbaratı sonucu tek başına güvenlik kararı olarak kullanılmamalıdır. Bulguları tam dosya yolu, parent process, komut satırı, imza ve olay bağlamıyla doğrulayın.
