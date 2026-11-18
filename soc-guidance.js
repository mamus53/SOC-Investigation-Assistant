'use strict';
(()=>{
 const systemNames=new Set(['csrss.exe','lsass.exe','smss.exe','services.exe','svchost.exe','winlogon.exe','wininit.exe','system','registry','ntoskrnl.exe']);
 function classify(name,entry){
  if(!entry)return 'unknown';
  entry=SOC_KNOWLEDGE.normalize(name,entry);
  const role=entry.researchRole;
  if(entry.ambiguousName)return 'ambiguous';
  if(entry.kind==='configuration')return 'configuration';
  if(entry.kind==='ioc'&&role!=='malware')return 'incident';
  if(['inventory-only','category-only','reviewed-source-example'].includes(entry.knowledgeScope))return 'reference';
  if(role==='name-hypothesis')return 'hypothesis';
  if(['extended-source-name-reference','observed-package-filename','publisher-bulk-filename-reference','archive-derived-name-only-reference','debian-observed-file-225'].includes(entry.catalogClass))return 'reference';
  if(role==='pentest'||/^(redteam|pentest)(?:$|[-_])/.test(entry.group||'')||['bloodhound','bloodhound.exe','metasploit','metasploit.exe'].includes(name))return 'pentest';
  if(role==='sensitive-dual'||['dual','admin'].includes(entry.kind))return 'admin';
  if(role==='defensive')return systemNames.has(name)?'system':'legitimate';
  if(role==='malware')return 'malware';
  if(entry.kind==='security'&&/pentest|red.team|sızma|c2-pentest/i.test([entry.product,entry.name,entry.group].join(' ')))return 'pentest';
  if(['malware','family','ioc'].includes(entry.kind))return 'malware';
  if(['windows','critical','driver','dllref'].includes(entry.kind)||systemNames.has(name))return 'system';
  return 'reference';
 }
 function guidance(name,entry,assessment,context={}){
  entry=SOC_KNOWLEDGE.normalize(name,entry);
  const category=classify(name,entry),items=[],location=SOC_WINDOWS_LOCATION.assess(name,entry,context);
  const add=s=>{if(typeof s==='string'&&s.trim())items.push(s.trim());};
  // Location detail already appears in the location block; repeat only actionable exceptions.
  if(location?.status==='mismatch')add('Konum uyarısı: beklenen etkin bileşen yolu dışında. Taklit/yeniden adlandırma ihtimalini araştırın; yedek kopyasını çalışan süreçle karıştırmayın. Yalnız yol farkıyla izolasyon veya FP kararı vermeyin.');
  if(category==='incident')add('Olay raporunda geçen ad, mevcut dosyanın aynı örnek olduğunu kanıtlamaz. Raporun hash/içerik ve davranış göstergeleriyle karşılaştırın; yalnız adla zararlı veya FP kararı vermeyin.');
  if(category==='ambiguous')add('Bu ad farklı paket ve tehdit bağlamlarında kullanılır. Gerçek kaynak ve içerik belirlenmeden FP veya izolasyon kararı vermeyin.');
  const packageInventory=entry?.knowledgeScope==='inventory-only'&&!!entry.sourcePackage;
  const specific=entry?.socFocus||entry?.review||entry?.verify;
  const generic=new Set(['Komut içeriğini ve çağırdığı dosyaları incele.','Export/import tablolarını ve kütüphaneyi yükleyen uygulamayı incele.','Dosya başlığını veya kaynak kodunu, gerçek yolu, sürümü, hash değerini ve çağıran/yükleyen uygulamayı birlikte inceleyin. Kaynağın anlatmadığı işlevleri gerçekleşmiş kabul etmeyin.']);
  if(!generic.has(specific)&&!packageInventory)add(specific);
  if(Array.isArray(entry?.socExamples)){
   for(const example of entry.socExamples)add('Kötüye kullanım örneği: '+example);
  }else{
   const misuse=entry?.abuse||entry?.misuse||entry?.risk;
   if(typeof misuse==='string'&&misuse.trim()&&misuse!==specific)add('Bilinen kötüye kullanım / araştırma noktası: '+misuse);
  }
  if(category==='malware'){
   add(name+' adı tehdit ailesiyle ilişkilidir; isim tek başına bulaşma kanıtı değildir. Dosyanın çalıştırıldığı tespit edildiyse, EDR kullanılıyorsa tarama görevi gönderin; aile ilişkisini içerik/hash ve davranışla doğrulayın.');
   add('Şüpheli çalıştırma kurumun bilgisi veya onayı dahilinde değilse olay müdahale prosedürüne göre ağ izolasyonu önerilir. Aktif şifreleme/yayılma varsa tarama sonucunu beklemeyin; bulguları koruyun.');
  }else if(category==='pentest')add(name+' sızma testi / kırmızı takım aracı olarak kullanılabilir. Hedefleri ve zaman aralığını test kaydıyla karşılaştırın; test sorumlusundan onay alınmasını öneririz. Onaysız faaliyeti yüksek öncelikle araştırın.');
  else if(category==='hypothesis')add('İsim ipucudur; işlevi içerikten doğrulayın. Güvenlik testi iddiası varsa kapsam ve yetkili kullanım onayını kontrol edin.');
  const script=/\.(sh|bat|cmd|ps1|psm1|vbs|vbe|wsf|hta|py|pl|pm|rb|js|jse|mjs|cjs)$/i.test(name);
  const driver=/\.sys$/i.test(name);
  const library=/\.(dll|ocx|so(?:\.[\d.]+)?|dylib)$/i.test(name);
  let common=packageInventory?'Paket yöneticisinden dosya sahipliğini ve bütünlüğünü; gerçek yolu, paket sürümünü ve hash değerini doğrulayın. Çalıştırma/yükleme bulgusu varsa çağıran uygulamayla karşılaştırın. Ad eşleşmesi tek başına FP kararı için yeterli değildir.':category==='configuration'?'Yapılandırma içeriğini ve referans verilen dosyaların kaynağını, hashini ve varsa imzasını doğrulayın; hedefin gerçekten çalıştırılıp çalıştırılmadığını ayrıca kontrol edin.':script?'Betiği çalıştırmadan, çağırdığı komutlar ve yardımcılarıyla inceleyin; kaynak paketini/deposunu, yolu ve hash değerini doğrulayın. İmza varsa kontrol edin; imzasız betik tek başına zararlı değildir.':driver?'Sürücünün gerçek yükleme yolunu, yayıncı imzasını, sürümünü ve hash değerini doğrulayın; hizmet/cihaz kaydıyla karşılaştırın. İmzalı olması tek başına güvenli olduğunu kanıtlamaz.':library?'Kütüphaneyi yükleyen uygulamayı, gerçek yükleme yolunu, yayıncı/imza ve hash değerini doğrulayın.':'Gerçek dosya yolunu, yayıncı/imza ve hash değerini; çalıştırılmışsa kullanıcı, başlatan süreç ve komut satırını birlikte doğrulayın.';
  const systemPath=/(?:^|[\\/])(?:system32|syswow64)(?:[\\/]|$)/i.test(context.fullPath||'');
  if(['admin','system','legitimate'].includes(category)||systemPath)common+=' İşlemin yetkili kullanıcı veya beklenen hizmet hesabı ile uyumunu; yönetim/değişiklik işlemleri için onay alınmasını kontrol edin.';
  if(systemPath&&category==='unknown')common+=' Sistem dizininde olması meşru olduğunu kanıtlamaz.';
  add(common);
  // Retain genuinely new name cues, but do not repeat curated hypotheses or alias disclaimers.
  if(category!=='hypothesis')for(const h of assessment.hypotheses||[])if(!h.startsWith('İsim ilişkisi:'))add(h);
  if(assessment.level==='high'&&category==='unknown')items.unshift(assessment.reason);
  const key=t=>t.toLocaleLowerCase('tr').replace(/[\s.,;:]+/g,' ').trim();
  const seen=new Set();return {category,location,items:items.filter(t=>{const k=key(t);if(seen.has(k))return false;seen.add(k);return true;})};
 }
 globalThis.SOC_GUIDANCE={classify,guidance};
 if(typeof module!=='undefined')module.exports={classify,guidance};
})();
