# Üçüncü taraf açık kaynak bildirimi — v5.6.0

Bu sürümün offline ZIP'i **upstream veri setlerinin tam kopyalarını içermez**. Aşağıdaki kaynakların önemli bir kısmına bağlantı verilir; indirilebilir derleme aracı gerçek meta verilerini yerel olarak dönüştürmek üzere sağlanır. Proje ücretsiz dağıtılsa bile yazarlık, lisans, telif ve marka yükümlülüklerine uyulmalıdır.

| Kaynak | Kaynak URL | Lisans / koşul | Bu ZIP içindeki durum |
|---|---|---|---|
| MITRE ATT&CK STIX Enterprise v20.1 | https://github.com/mitre-attack/attack-stix-data | MITRE ATT&CK Terms of Use, MITRE telif/atfı | Önceden yazılmış 94 Türkçe not; v20.1 STIX **indirilmedi** |
| SigmaHQ | https://github.com/SigmaHQ/sigma | Detection Rule License DRL-1.1; yazar ve kaynak atfı | Referans derleyici, gerçek binlerce Sigma kuralı **indirilmedi** |
| LOLBAS | https://github.com/LOLBAS-Project/LOLBAS | GPL-3.0, upstream notice | Ad/kural metadata derleyicisi; upstream YAML **indirilmedi** |
| Splunk Security Content | https://github.com/splunk/security_content | Apache-2.0 | Açık kaynak referans derleyicisi; upstream YAML **indirilmedi** |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | MIT | Komutları ayıklayan test metadata derleyicisi; upstream **indirilmedi** |
| GTFOBins | https://github.com/GTFOBins/GTFOBins.github.io | GPL-3.0 | İşlev/ad metadata derleyicisi; upstream **indirilmedi** |
| LOLDrivers | https://github.com/magicsword-io/LOLDrivers | Apache-2.0 | Sadece sürücü adı araştırma derleyicisi; upstream **indirilmedi** |

**Referans lisans URL'leri:**
- Sigma DRL-1.1 tam metin: https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md
- LOLBAS lisans ve notice: https://github.com/LOLBAS-Project/LOLBAS
- GTFOBins lisans: https://github.com/GTFOBins/GTFOBins.github.io/blob/master/LICENSE
- MITRE ATT&CK lisans/telif: https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt
- Atomic Red Team lisans: https://github.com/redcanaryco/atomic-red-team/blob/master/LICENSE.txt
- LOLDrivers lisans: https://github.com/magicsword-io/LOLDrivers/blob/main/LICENSE

### Tam kaynak derlemesinde kurallar

`tools/build_offline_sources.py --download` kaynak arşivlerinin SHA-256 değerini kaydeder ve yayımlanacak pakette gerekli notice/license metinlerinin bulunmasını zorunlu kılar. Kurallarda `author` ve upstream `url` alanları saklanır. İndirilmiş ham ZIP, pentest payload'u ve `.sys` binary'si son kullanıcı ZIP'ine eklenmez. Sigma tam kural koşullarının çalıştırıldığı iddia edilmez; DRL yazarları yalnız referans bölümünde görünür.

### Projenin kendi lisansı

**Bu geliştirmenin proje çapındaki lisansı kullanıcı/proje sahibi tarafından henüz seçilmemiştir.** Açık kaynak ilanı ve kamuya repo yükleme öncesinde kaynak kod lisansı, varsa katkıcı bildirimleri ve üçüncü taraf varlıkların lisansları ayrıca değerlendirilmelidir. Buradaki kaynak referanslarını kullanmak ürünün otomatik GPL veya MIT lisansına geçtiği anlamına gelmez.
