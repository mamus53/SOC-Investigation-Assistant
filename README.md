# SOC Investigation Assistant

Chrome yan panelinde dosya, süreç ve ağ göstergeleri için hızlı SOC araştırması yapmaya yardımcı olan Manifest V3 uzantısı.

Amaç, analistin karşılaştığı dosya veya süreç adını tek başına zararlı/meşru olarak etiketlemek yerine olası işlevi, beklenen konumu, meşru kullanım alanlarını, bilinen kötüye kullanım örneklerini ve sonraki inceleme adımlarını aynı yerde değerlendirmesini kolaylaştırmaktır.

## Özellikler

- Çevrimdışı dosya ve süreç kataloğu
- Seçili metin üzerinden araştırma başlatma
- SOC kontrol önerileri ve bağlamsal inceleme notları
- Kullanıcının kendi API anahtarlarıyla VirusTotal ve AbuseIPDB sorguları
- Dosyayı servise yüklemeden yerel hash hesaplama

## Kurulum

1. Depoyu indirin veya klonlayın.
2. Chrome'da `chrome://extensions` sayfasını açın.
3. Geliştirici modunu etkinleştirin.
4. **Paketlenmemiş öğe yükle** seçeneğiyle proje kök klasörünü seçin.

## Güvenlik ve gizlilik

API anahtarlarını kaynak koda, commit geçmişine veya issue içeriklerine eklemeyin. Gerçek müşteri verilerini ve kurum içi IOC'leri herkese açık olarak yayımlamayın. Harici tehdit istihbaratı sorguları yalnızca kullanıcı tarafından başlatılmalıdır.

Dosya adı eşleşmesi veya tek bir tehdit istihbaratı sonucu kesin zararlı/meşru kararı vermez. Tam dosya yolu, imza, komut satırı, parent process ve olay bağlamı birlikte değerlendirilmelidir.

## Kaynaklar ve lisans

Üçüncü taraf kaynakların lisans ve atıf notları proje paketindeki `SOURCE-LICENSE-ATTRIBUTION-v810.md`, `SOURCE-MANIFEST-225.json`, `THIRD-PARTY-NOTICES-*.md` ve ilgili kaynak bildirim dosyalarında tutulur. Depoya genel bir proje lisansı eklenmemiştir; üçüncü taraf materyallerin kendi koşulları geçerlidir.

## Sorumluluk reddi

Bu proje SOC araştırması ve savunma amaçlı triage desteği için sunulur. Çıktılar doğrulama gerektirir ve profesyonel güvenlik incelemesinin yerine geçmez.
