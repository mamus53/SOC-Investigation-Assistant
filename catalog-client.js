(()=>{
 const cache=new Map(),pending=new Map(),suggestCache=new Map(),inventoryCache=new Map();
 function bucket(n){let h=0;for(const c of n)h=(h*31+c.charCodeAt(0))>>>0;return h%256;}
 async function json(url){const r=await fetch(url,{signal:AbortSignal.timeout(4000)});if(!r.ok)throw Error('Kütüphane okunamadı');return r.json();}
 function related(name){
  const stem=name.replace(/\.(exe|dll|sys|bat|cmd|ps1|psm1|vbs|js|sh|py|so|elf|bin|dat|scr)$/i,'').replace(/[-_](x64|x86|amd64|arm64)$/i,'').replace(/[ _-]/g,'').toLowerCase();
  const alias=Object.hasOwn(SOC_FAMILIES.aliases,stem)?SOC_FAMILIES.aliases[stem]:null;if(!alias)return null;
  const entry=Object.hasOwn(SOC_FAMILIES.records,alias)?SOC_FAMILIES.records[alias]:null;if(!entry)return null;
  return {entry:{...entry,nameRelation:true},from:entry.product};
 }
 function inventoryEntry(name,row,packages){
  const [path,pkg,count]=row;const info=packages[pkg]||[];
  const type=/\.so(?:\.|$)/.test(name)?'paylaşılan kütüphane':/\.pyw?$/.test(name)?'Python modülü/betiği':/\.pm$/.test(name)?'Perl modülü':/\.(?:js|mjs|cjs)$/.test(name)?'JavaScript dosyası':/\.(?:sh|pl|rb|bat|cmd|ps1|vbs)$/.test(name)?'betik dosyası':'program veya yazılım bileşeni';
  return {entry:{name:pkg+' · kaynak paketinde gözlenen ad',product:pkg,kind:'runtime',catalogClass:'debian-observed-file-225',knowledgeScope:'inventory-only',packageName:pkg,packageDescription:info[0]||'',filePurpose:type+' adlandırmasıyla uyumlu. Bu dosyanın hangi girdileri okuduğu, hangi işlemleri yaptığı ve hangi çıktıları ürettiği henüz dosya içeriği veya dosyaya özgü belgeyle doğrulanmamıştır.',purpose:'Dosyaya özgü işlev incelenmemiştir; paket açıklaması dosya işlevi değildir.',expected:'Kaynakta gözlenen örnek Linux yolu: /'+path+(count>1?' · Birden fazla yol/paket kaydı görülür; gösterilen yol yalnız bir örnektir.':'')+' Windows üzerinde aynı ad, aynı dosyayı veya aynı ürünü doğrulamaz.\n\nPaket bağlamı (dosyanın özel işlevi değildir): '+pkg+'\nPaketin özgün kısa açıklaması: '+(info[0]||'belirtilmemiş'),benign:'Bu ad açık kaynak paket dağıtımında gözlenmiştir. Elinizdeki dosyanın o dağıtıma ait veya güvenli olduğu henüz doğrulanmamıştır.',review:'Paket yöneticisinin dosya sahipliği ve bütünlük bilgisiyle karşılaştırın; gerçek dosya yolunu, paket sürümünü, hashini ve çağıran uygulamayı doğrulayın. Ad eşleşmesini FP kapatma gerekçesi olarak tek başına kullanmayın.',sourceURL:'https://packages.debian.org/stable/'+encodeURIComponent(pkg),sourceURLs:['https://packages.debian.org/stable/'+encodeURIComponent(pkg),'https://deb.debian.org/debian/dists/stable/main/'],evidenceGrade:'observed-package-file-not-identity',observedPath:path,sourcePackage:pkg},from:null};
 }
 async function inventoryLookup(name){
  const id=bucket(name);if(!inventoryCache.has(id))inventoryCache.set(id,json('inventory/'+id+'.json').catch(e=>{inventoryCache.delete(id);throw e;}));
  const d=await inventoryCache.get(id);if(inventoryCache.size>8)inventoryCache.delete(inventoryCache.keys().next().value);
  if(!Object.hasOwn(d.files,name))return {entry:null,from:null};
  const r=inventoryEntry(name,d.files[name],d.packages),example=SOC_SOURCE_EXAMPLES[name];
  if(example&&r.entry.sourcePackage===example.packageName&&r.entry.observedPath===example.observedPath){Object.assign(r.entry,example);r.entry.sourceURLs=[example.sourceURL,...r.entry.sourceURLs];r.entry.expected+='\n\nİncelenen örnek: '+example.packageName+' '+example.packageVersion+'; SHA-256: '+example.sourceSHA256;}
  return r;
 }
 async function lookup(name,resolveAlias=true){
  name=String(name).toLowerCase();
  if(Object.hasOwn(SOC_REVIEWED_CONTEXT,name))return SOC_REVIEWED_CONTEXT[name];
  if(Object.hasOwn(SOC_AMBIGUOUS_NAMES,name)){
   const r=await inventoryLookup(name);if(r.entry){r.entry.ambiguousName=true;r.entry.ambiguityContext=SOC_AMBIGUOUS_NAMES[name]+' tehdit adı ve paket kaydı aynı adı kullanıyor; içerik ve kaynak doğrulanmalı.';r.entry.purpose+=' Ayrıca bu ad '+SOC_AMBIGUOUS_NAMES[name]+' tehdit adıyla ilişkilidir. Bu iki bağlam dosyanın kimliğini tek başına belirlemez.';r.entry.review='Ad hem paket envanterinde hem tehdit adı referansında geçer. Hangi bağlamın geçerli olduğunu dosya kaynağı, hash, içerik ve gerçek davranışla belirleyin; yalnız isimden karantina veya FP kararı vermeyin. '+r.entry.review;return r;}
  }
  if(Object.hasOwn(SOC_CORE,name))return SOC_CORE[name];
  const relation=related(name);if(relation&&!SOC_FAMILIES.exact.includes(name))return relation;
  const id=bucket(name);
  if(!cache.has(id)){
   if(!pending.has(id))pending.set(id,json('data/'+id+'.json').then(data=>{cache.set(id,data);if(cache.size>12)cache.delete(cache.keys().next().value);return data;}).finally(()=>pending.delete(id)));
   const data=await pending.get(id);if(Object.hasOwn(data,name))return data[name];
  }else{
   const data=cache.get(id);cache.delete(id);cache.set(id,data);if(Object.hasOwn(data,name))return data[name];
  }
  const normalized=name.replace(/\.(exe|dll|sys|bat|cmd|ps1|psm1|vbs|js|sh|py|so|elf|bin|dat|scr)$/i,'').replace(/[-_](x64|x86|amd64|arm64)$/i,'').replace(/[ _-]/g,'');
  const alias=Object.hasOwn(SOC_THREAT_ALIASES,normalized)?SOC_THREAT_ALIASES[normalized]:null;
  if(resolveAlias&&alias&&alias!==name){const r=await lookup(alias,false);if(r.entry)return {entry:{...r.entry,nameRelation:true},from:r.entry.product||alias};}
  return related(name)||inventoryLookup(name);
 }
 globalThis.SOC_CATALOG={lookup,related,async suggest(text){
  const prefix=text.slice(0,2),id=(prefix.charCodeAt(0)*31+(prefix.charCodeAt(1)||0))%64;
  if(!suggestCache.has(id))suggestCache.set(id,json('suggestions/'+id+'.json').catch(e=>{suggestCache.delete(id);throw e;}));
  const groups=await suggestCache.get(id),names=groups[prefix]||[],found=[];
  if(names.includes(text))found.push(text);
  for(const n of names){if(found.length===8)break;if(n!==text&&n.startsWith(text))found.push(n);}
  return found;
 }};
})();

