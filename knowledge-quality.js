'use strict';
(()=>{
 const inventory=new Set(['debian-observed-file-225','observed-package-filename','extended-source-name-reference','archive-derived-name-only-reference']);
 const hypothetical=new Set(['potential-executable-name','curated-name-only-not-an-ioc','previous-unverified-name-cue','illustrative-not-confirmed','original-name-reference']);
 const categoryOnly=new Set(['name-reference','model-curated-name-reference']);
 function fileType(name){
  if(/\.so(?:\.[\d.]+)?$/i.test(name))return 'Paylaşılan kütüphane adı';
  const ext=name.split('.').pop().toLowerCase();
  return ({sh:'Shell betiği adı',bat:'Windows komut betiği adı',cmd:'Windows komut betiği adı',ps1:'PowerShell betiği adı',psm1:'PowerShell modülü adı',vbs:'VBScript betiği adı',py:'Python modülü/betiği adı',pm:'Perl modülü adı',pl:'Perl betiği adı',js:'JavaScript dosyası adı',mjs:'JavaScript modülü adı',dll:'Dinamik kütüphane adı',exe:'Çalıştırılabilir dosya adı',sys:'Sürücü dosyası adı'})[ext]||'Dosya / araç adı';
 }
 function normalize(name,input){
  if(!input)return null;
  const e={...input};if(e.knowledgeScope)return e;
  if(inventory.has(e.catalogClass)){
   e.knowledgeScope='inventory-only';
   e.sourceContext=typeof e.purpose==='string'?e.purpose:'';
   e.filePurpose=fileType(name)+'. Bu kayıtta dosyanın özel işlevi kaynak kodu veya dosyaya özgü teknik belge üzerinden doğrulanmamıştır. Paket veya ürün açıklaması bu dosyanın yaptığı işlem olarak kabul edilmemelidir.';
  }else if(hypothetical.has(e.catalogClass)){
   e.knowledgeScope='name-hypothesis';e.researchRole='name-hypothesis';
   e.filePurpose=fileType(name)+'. Kayıt, adlandırmaya dayalı bir araştırma ipucudur; bu adla bir ürünün veya derlemenin varlığı ve özel işlevi doğrulanmamıştır.';
  }else if(categoryOnly.has(e.catalogClass)&&!e.sourceURL&&!e.sourceURLs?.length){
   e.knowledgeScope='category-only';e.filePurpose=fileType(name)+'. Mevcut kayıt yalnız genel bir ürün/kullanım kategorisi öneriyor; dosyaya özgü işlev bu kayıtla doğrulanmış değildir.';
  }else if(e.researchRole==='name-hypothesis'){
   e.knowledgeScope='name-hypothesis';e.filePurpose=e.purpose;
  }else if(e.kind==='ioc'){
   e.knowledgeScope='incident-reference';e.filePurpose=e.purpose||'Kaynak olay raporunda geçen dosya adı; mevcut dosyanın kimliği doğrulanmadı.';
  }else if(e.kind==='family'||e.kind==='malware'||e.nameRelation){
   e.knowledgeScope='family-reference';e.filePurpose=e.purpose||e.shortPurpose||'Bu aileyle ilişkili dosyanın özel işlevi içerikten doğrulanmalıdır.';
  }else{
   e.knowledgeScope='product-reference';e.filePurpose=e.purpose||e.shortPurpose||fileType(name)+'. Dosyaya özgü işlev bu kayıtta açıklanmamıştır.';
  }
  if(!e.purpose)e.purpose=e.filePurpose;
  if(e.knowledgeScope==='inventory-only'&&!e.packageName){
   e.expected=(e.expected||'Bu ad için doğrulanmış bir konum yoktur.')+'\n\nKaynak bağlamı (dosya işlevi değildir): '+(e.sourceContext||e.sourceGroup||'Yalnız isim envanteri.');
  }
  if(['category-only','inventory-only'].includes(e.knowledgeScope)&&!e.benign)e.benign='Normal kullanım, kaynak paket/uygulama ve gerçek dosya eşleşmesi doğrulanmadan belirlenemez.';
  if(!e.expected)e.expected='Bu kayıt dosyaya özgü bir kurulum konumu belgelemiyor. Gerçek yolu, kaynak uygulamayı/paketi ve sürümü birlikte doğrulayın; örnek veya varsayılan dizini güvenilirlik garantisi saymayın.';
  if(!e.benign)e.benign=e.knowledgeScope==='family-reference'?'Bu ad araştırma veya kontrollü örnek arşivinde bulunabilir. Gerçek dosyanın normal kullanım bağlamı bu aile kaydından belirlenemez.':'Bu kayıt için meşru kullanım ayrıca belgelenmemiştir. İşlem amacını, kaynak uygulamayı ve kullanıcı/iş kaydı bağlamını doğrulayın.';
  if(!e.review)e.review='Dosya başlığını veya kaynak kodunu, gerçek yolu, sürümü, hash değerini ve çağıran/yükleyen uygulamayı birlikte inceleyin. Kaynağın anlatmadığı işlevleri gerçekleşmiş kabul etmeyin.';
  return e;
 }
 function purposeText(e,fallback){
  if(!e)return fallback;
  if(e.knowledgeScope==='reviewed-source-example')return 'İncelenen kaynak örneğinin işlevi: '+e.filePurpose+'\n\nBu açıklama yalnız belirtilen kaynak ve sürüm örneğine aittir; aynı adlı yerel dosyanın içeriği doğrulanmamıştır.';
  if(e.ambiguousName)return e.filePurpose+'\n\nİsim çakışması: '+(e.ambiguityContext||'Paket ve tehdit adı bağlamları ayrıştırılmalıdır.');
  if(e.knowledgeScope==='family-reference')return 'Ürün / aile hakkında bilinen işlev: '+e.filePurpose+'\n\nAile yetenekleri, bu adlı dosyada her işlevin bulunduğu veya çalıştırıldığı anlamına gelmez.';
  return e.filePurpose||fallback;
 }
 globalThis.SOC_KNOWLEDGE={normalize,purposeText,fileType};
})();
