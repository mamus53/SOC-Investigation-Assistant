# GitHub'da yayımlama

Bu klasör, uzantının kök dizinidir. Depoyu GitHub'da oluştururken README veya `.gitignore` dosyasını GitHub'ın yeniden üretmesine izin vermeyin; ikisi de bu pakette hazırdır.

1. GitHub'da **New repository** ile `SOC-Investigation-Assistant` adında bir depo oluşturun. Görünürlüğü yayımlama tercihinize göre seçin.
2. Bilgisayarınızda bu klasörü açıp terminalde aşağıdaki komutları çalıştırın. `KULLANICI` bölümünü kendi GitHub kullanıcı adınızla değiştirin.

```powershell
git init -b main
git add .
git status
git commit -m "Initial release: SOC Investigation Assistant 23.16"
git remote add origin https://github.com/KULLANICI/SOC-Investigation-Assistant.git
git push -u origin main
```

`git status` çıktısında `.env`, API anahtarı, özel anahtar veya kurum içi IOC bulunmadığını kontrol etmeden commit/push yapmayın. Git kimliği tanımlı değilse önce `git config --global user.name` ve `git config --global user.email` ayarlarını kendi bilgilerinizle yapılandırın.

Depo daha önce oluşturulduysa `git init` ve `git remote add origin` adımlarını tekrarlamayın; mevcut remote adresini `git remote -v` ile kontrol edin.
