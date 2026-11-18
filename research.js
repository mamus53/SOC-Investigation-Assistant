'use strict';
(function(g){
 const types={exe:['Windows çalıştırılabilir dosyası','Yayıncı imzası, ürün/sürüm bilgisi, importlar ve giriş noktasını incele.'],dll:['Windows dinamik kütüphanesi','Export/import tablolarını ve kütüphaneyi yükleyen uygulamayı incele.'],sys:['Windows sürücüsü','Sürücü imzasını, sürümünü ve bilinen güvenlik açıklarını araştır.'],bat:['Windows komut dosyası','Komut içeriğini ve çağırdığı dosyaları incele.'],cmd:['Windows komut dosyası','Komut içeriğini ve çağırdığı dosyaları incele.'],ps1:['PowerShell betiği','Fonksiyonları, dış bağlantıları ve kodlanmış içerikleri incele.'],vbs:['VBScript dosyası','Nesne oluşturma, pencere seçenekleri ve çağrılan işlemleri incele.'],js:['JavaScript dosyası','Tarayıcı, Node.js veya Windows Script Host bağlamını ve bağımlılıkları belirle.'],jse:['Kodlanmış JScript dosyası','İçeriği çalıştırmadan çözümle; kullanılan script motorunu belirle.'],vbe:['Kodlanmış VBScript dosyası','İçeriği çalıştırmadan çözümle.'],wsf:['Windows Script dosyası','XML içindeki script motorlarını ve çağrıları incele.'],hta:['HTML uygulaması','Script içeriğini, dış kaynakları ve mshta kullanımını incele.'],sh:['Shell betiği','Yorumlayıcıyı, komutları ve dosya izinlerini incele.'],py:['Python dosyası','Importları, giriş noktasını ve dış kaynak erişimini incele.'],rb:['Ruby betiği','Bağımlılıkları ve işletim sistemi çağrılarını incele.'],pl:['Perl betiği','Yorumlayıcıyı, modülleri ve komut çağrılarını incele.'],so:['Paylaşılan kütüphane','ELF başlığını, sembolleri ve yükleyici ilişkisini incele.'],dylib:['macOS dinamik kütüphanesi','Mach-O yapısını, imzayı ve yükleme komutlarını incele.'],elf:['ELF ikili dosyası','Mimariyi, segmentleri, sembolleri ve bağımlılıkları incele.'],jar:['Java arşivi','Manifesti, sınıfları ve bağımlılıkları incele.'],apk:['Android uygulama paketi','Manifest izinlerini, imzayı ve kodu incele.'],msi:['Windows kurulum paketi','CustomAction tablosunu, imzayı ve kurulacak dosyaları incele.'],scr:['Windows ekran koruyucu yürütülebiliri','PE yapısını ve gerçek işlevini incele.'],lnk:['Windows kısayolu','Hedef yolu, argümanları ve çalışma dizinini incele.'],psm1:['PowerShell modülü','Dışa aktarılan fonksiyonları ve modül yükleme davranışını incele.'],reg:['Kayıt defteri dosyası','Değiştirilecek anahtarları çalıştırmadan incele.'],zip:['ZIP arşivi','Üye dosyaları, şifreleme ve iç içe arşivleri incele.'],iso:['Disk görüntüsü','İç dosya ağacını ve çalıştırılabilir içerikleri incele.'],docm:['Makro içerebilen Word belgesi','VBA makrolarını ve dış ilişkileri incele.'],xlsm:['Makro içerebilen Excel belgesi','Makroları, otomatik açılma işlevlerini ve dış ilişkileri incele.'],pdf:['PDF belgesi','JavaScript, ek dosya ve dış bağlantı nesnelerini incele.'],wasm:['WebAssembly modülü','Import/exportları ve modül çağıran kodu incele.'],asar:['Electron uygulama arşivi','Ana süreç, preload ve renderer ilişkilerini arşiv içeriğinden incele.']};
 function assess(name,entry,variant){
  const ext=name.includes('.')?name.split('.').pop():'';
  const type=types[ext];
  let label='Bağlamı doğrula',reason='Ad eşleşmesi dosyanın kimliğini veya güvenliğini doğrulamaz.',level='info';
  const evidence=String(entry?.evidenceGrade||'')+' '+String(entry?.catalogClass||'');
  if(!entry){label='İncelenmesi önerilir';reason=type?type[1]:'Dosya başlığından türü belirle; kaynağını, paket ilişkisini ve içeriğini incele.';level='review';}
  if(entry && ['dual','admin','security','sigma-observed-name'].includes(entry.kind)){label='İncelenmesi önerilir';reason=String(entry.review||entry.verify||entry.benign||aResearchFallback(entry)).slice(0,320);level='review';}
  if(/^(bat|cmd|vbs|vbe|ps1|psm1|sh|jse|wsf|hta)$/.test(ext)){label='İncelenmesi önerilir';reason=type[1]+' İçerik görülmeden gerçekleştirilen işlemler belirlenemez.';level='review';}
  if(name==='certutil.exe'){label='İncelenmesi önerilir';reason='Meşru sertifika aracının indirme ve kod çözme işlevleri kötüye kullanılabilir. Kaynak URL’yi, çıktı dosyasını ve kullanım amacını incele.';level='review';}
  if(entry && (['malware','family','ioc'].includes(entry.kind)||/historic|threat-name/.test(evidence))){label='Yüksek güvenlik ilgisi';reason='Adın tehdit araştırmasıyla ilişkili bir referansı var. Bu ilişki dosyanın aynı zararlı olduğunu kanıtlamaz; kaynak, hash ve içerikle karşılaştır.';level='high';}
  const role=entry?.researchRole;
  const pentest=role==='pentest'||(!role&&entry?.kind==='security'&&/red.team|pentest|sızma|c2-pentest/i.test([entry?.product,entry?.name,entry?.group].join(' ')));
  if(pentest){label='Yüksek araştırma önceliği';level='high';reason='Planlı sızma testi / kırmızı takım çalışmalarında veya yetkisiz sızma aktivitelerinde kullanılabilir. '+String(entry?.review||'Kullanım amacını, hedefleri ve onaylı test kapsamını öncelikle doğrula.');}
  if(role==='sensitive-dual'){label='Yüksek araştırma önceliği';level='high';reason='Meşru yönetim veya planlı sızma testinde kullanılabilir; yetkisiz kullanımı yüksek güvenlik ilgisi taşır. '+String(entry?.abuse||'Kullanım amacını araştır.');}
  if(role==='name-hypothesis'){label='İsim ipucu · doğrulama gerekli';level='review';reason='İsim araştırma ipucudur; dosyanın işlevi veya tehdit kimliği bu adla doğrulanmaz.';}
  const hypotheses=[];
  if(/hidden|silent|stealth/i.test(name))hypotheses.push('Ad, sessiz veya gizli pencereyle çalışma amacını düşündürebilir; bu işlev içerikten doğrulanmış değildir.');
  if(/dump|cred|token|inject/i.test(name))hypotheses.push('Adın içerdiği terimler bellek, kimlik bilgisi veya süreç araştırmasına değer katabilir; gerçek işlevi içerikten doğrula.');
  if(/\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|bat|cmd|js|vbs|lnk)$/i.test(name)||/[\u202a-\u202e\u2066-\u2069]/.test(name)){label='Yüksek güvenlik ilgisi';reason='Dosya adında türü gizleyebilen çift uzantı veya yönlendirme karakteri var. Gerçek türü dosya başlığından kontrol et.';level='high';}
  if(/^csrsss\.exe$/i.test(name)){label='Yüksek araştırma önceliği';level='high';reason='csrss.exe adına benzerlik nedeniyle taklit olasılığı araştırılmalı. Dosya adı tek başına arka kapı veya zararlı kimliği kanıtlamaz.';hypotheses.push('Gerçek dosya yolunu, yayıncı imzasını ve hashini doğrula; csrss.exe ile aynı dosya olduğunu varsayma.');}
  if(!entry && /adware/i.test(name))hypotheses.push('Addaki adware sözcüğü reklam yazılımını çağrıştırır; gerçek işlev veya zararlılık doğrulanmamıştır.');
  if(variant)hypotheses.push('İsim ilişkisi: '+variant+'. İlişki araştırma ipucudur; aynı dosya veya ürün olduğu doğrulanmadı.');
  return {name,ext,type:type?.[0]||'Türü içerikten doğrulanacak dosya / araç',label,reason,level,hypotheses,next:type?.[1]||'Dosyanın kaynağını, gerçek türünü, imzasını ve içeriğini incele.'};
 }
 function aResearchFallback(entry){return (entry.product||entry.name||'Bu araç')+' için meşru kullanım ile yetkisiz kullanımı ayır; hedefini ve içeriğini doğrula.';}
 function node(tag,text,cls){const n=document.createElement(tag);if(text!=null)n.textContent=text;if(cls)n.className=cls;return n;}
 function detail(root,title,text){if(!text)return;const d=node('details');d.append(node('summary',title));d.append(node('p',text));root.append(d);return d;}
 function link(root,url,label){try{const u=new URL(url);if(u.protocol!=='https:')return;const a=node('a',label);a.href=u.href;a.target='_blank';a.rel='noopener noreferrer';root.append(a);}catch{}}
 function describeResearch(entry,a){
  if(entry?.nameRelation)return entry.product+' adıyla ilişkili araştırma bilgisi: '+entry.shortPurpose;
  if(/^csrsss\.exe$/i.test(a.name))return 'Windows’un csrss.exe süreç adına fazladan bir s harfiyle benzeyen dosya adıdır. Gerçek işlevi içerik incelenmeden bilinemez.';
  if(entry?.shortPurpose)return entry.shortPurpose;
  const purpose=String(entry?.purpose||'').trim();
  if(purpose&&!/^(SigmaHQ:|Kaynaklarda belgelenen inceleme alanları:|Bu gerçek dosya adı)/i.test(purpose))return purpose.length>380?purpose.slice(0,377)+'…':purpose;
  return a.type+'. Bu ada özgü işlev doğrulanmamıştır; içeriği ve kaynağı incelenmelidir.';
 }
 function block(root,title,text){const box=node('div',null,'block');box.append(node('h3',title),node('p',text));root.append(box);}
 function renderResearch(root,name,entry,variant,context={}){
  entry=SOC_KNOWLEDGE.normalize(name,entry);
  const a=assess(name,entry,variant),soc=SOC_GUIDANCE.guidance(name,entry,a,context);g.SOC_RESEARCH_CURRENT={...a,entry,category:soc.category,location:soc.location};
  root.replaceChildren();
  root.append(node('div',a.ext==='exe'?'PROCESS İNCELEMESİ':a.ext?'DOSYA / YÜRÜTME İNCELEMESİ':'PROCESS / ARAÇ İNCELEMESİ','sectionTitle'),node('h2',name.replace(/[\u202a-\u202e\u2066-\u2069]/g,c=>'[U+'+c.codePointAt(0).toString(16)+']'),'exename'));
  const product=entry?.product||entry?.name||a.type;
  root.append(node('p',product+(entry?.nameRelation?' · isim ilişkisi; dosya kimliği doğrulanmadı':''),'productname'));
  const badges={configuration:['Yapılandırma · kötüye kullanılabilir','yellow'],incident:['Olay raporunda geçen ad','yellow'],ambiguous:['İsim çakışması · bağlamı doğrula','yellow'],hypothesis:['İsim ipucu · işlev doğrulanmadı','yellow'],system:['Windows bileşeni adı','green'],admin:['Meşru / çift kullanımlı araç adı','yellow'],pentest:['Sızma testi / red team aracı','yellow'],malware:['Zararlı / tehdit ailesi adı','red'],legitimate:['Meşru kullanım referansı','green'],reference:['Yerel isim referansı','gray'],unknown:['İşlevi içerikten doğrulanmalı','yellow']};
  const badge=soc.location?.status==='mismatch'?['Konum uyumsuzluğu · araştırılmalı','yellow']:badges[soc.category];root.append(node('span',badge[0],'pill '+badge[1]));
  block(root,'Ne işe yarar?',SOC_KNOWLEDGE.purposeText(entry,describeResearch(entry,a)));
  block(root,'Beklenen konum / ürün notu',soc.location&&soc.location.status!=='missing'?(entry.expected+'\n\n'+soc.location.text):entry?.expected||(entry?.nameRelation?'Bu ad '+product+' ile ilişki düşündürür; dosyanın gerçek türü, kaynağı ve aile kimliği içerik ve hash ile doğrulanmalıdır.':'Bu ad için tek bir güvenilir kurulum yolu doğrulanmamıştır. Ürün/paket kaynağını, gerçek dosya yolunu ve yayıncı imzasını kontrol edin.'));
  block(root,'Meşru kullanım / normal bağlam',entry?.benign||(soc.category==='malware'?'Güvenlik araştırması, arşiv veya kontrollü laboratuvar örneği olabilir; bu, zararlı işlevleri meşru hâle getirmez.':soc.category==='pentest'?'Yetkilendirilmiş sızma testi ve güvenlik değerlendirmesinde kullanılabilir; kapsam ve onay doğrulanmalıdır.':'Dosyanın normal kullanım bağlamı yalnız isminden belirlenemez; uygulama kaynağı ve işlem amacı doğrulanmalıdır.'));
  const checks=node('div',null,'block soc-controls');checks.append(node('h3','SOC kontrol önerileri'));const list=node('ul');for(const item of soc.items){const li=node('li');const prefix='Kötüye kullanım örneği: ';if(item.startsWith(prefix))li.append(node('strong',prefix),node('span',item.slice(prefix.length)));else li.textContent=item;list.append(li);}checks.append(list);root.append(checks);
  const links=node('details');links.append(node('summary','Dış kaynaklarda araştır'));
  links.append(node('p','Seçtiğin bağlantı dosya adını ilgili arama hizmetine gönderir.','hint'));
  for(const url of new Set([...(entry?.sourceURLs||[]),entry?.sourceURL].filter(Boolean)))link(links,url,'Ürün / aile kaynağı');
  if(soc.category==='malware')link(links,'https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts','EDR tarama ve cihaz izolasyonu rehberi');
  for(const [label,url] of [['Web araması','https://www.google.com/search?hl=tr&lr=lang_tr&q='+encodeURIComponent('"'+name+'" nedir ne işe yarar güvenlik meşru kullanım kötüye kullanım Türkçe')],['LOLBAS','https://lolbas-project.github.io/'],['GTFOBins','https://gtfobins.github.io/'],['MITRE ATT&CK','https://attack.mitre.org/software/'],['Malpedia','https://malpedia.caad.fkie.fraunhofer.de/']])link(links,url,label);
  root.append(links);
  root.append(node('div','Bu açıklama dosya/süreç adı ve verilen bağlama dayanır; gerçek dosyanın güvenliğini veya False Positive durumunu doğrulamaz. Gerçek dosyanın kimliği ve çalıştırıldığı ayrıca doğrulanmalıdır.','note')); 
 }
 g.renderResearch=renderResearch;g.assessResearch=assess;
 if(typeof module!=='undefined')module.exports={assess,types};
})(globalThis);
