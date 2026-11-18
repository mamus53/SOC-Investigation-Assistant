(()=>{
 'use strict';
 const $=id=>document.getElementById(id);
 const str=v=>typeof v==='string'?v.slice(0,1000):typeof v==='number'&&Number.isFinite(v)?String(v):'';
 function parse(raw){
  const input=String(raw||'').trim();
  if(/^https?:\/\//i.test(input)){
   if(input.length>4096||/[\r\n\t]/.test(input))return null;
   try{const u=new URL(input);if(!u.hostname||u.username||u.password)return null;const value=u.href;const id=btoa(String.fromCharCode(...new TextEncoder().encode(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');return {value,type:'urls',path:'urls/'+id,id};}catch{return null;}
  }
  let value=String(raw||'').trim().toLowerCase();if(!value||value.length>253||/[\s/@?#%\\]/.test(value))return null;
  let type;
  if(/^\d+(\.\d+){3}$/.test(value)){
   if(!value.split('.').every(s=>/^(0|[1-9]\d{0,2})$/.test(s)&&+s<=255))return null;type='ip_addresses';
  }else if(value.includes(':')){
   if(value.startsWith('[')&&!/^\[[0-9a-f:.]+\]$/.test(value))return null;
   try{value=new URL('http://'+(value.startsWith('[')?value:'['+value+']')).hostname.replace(/^\[|\]$/g,'');if(!value.includes(':'))return null;type='ip_addresses';}catch{return null;}
  }else{
   if(value.endsWith('.'))value=value.slice(0,-1);
   try{value=new URL('https://'+value).hostname;}catch{return null;}
   if(!value.includes('.')||!value.split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))||/^\d+$/.test(value.split('.').pop()))return null;
   type='domains';
  }
  return {value,type,path:type+'/'+encodeURIComponent(value)};
 }
 function add(parent,tag,value,cls){const node=document.createElement(tag);node.textContent=value;if(cls)node.className=cls;parent.append(node);return node;}
 function fields(parent,title,rows){const section=document.createElement('section');section.className='net-box';parent.append(section);add(section,'h3',title);const dl=document.createElement('dl');dl.className='vt-version';section.append(dl);for(const [label,value]of rows){add(dl,'dt',label);add(dl,'dd',str(value)||'Bilgi bulunamadı');}}
 function link(parent,url,label){const a=add(parent,'a',label,'sourceLink');a.href=url;a.target='_blank';a.rel='noopener noreferrer';}
 function date(value){if(!value)return '';const d=new Date(typeof value==='number'?value*1000:value);return Number.isNaN(d.getTime())?'':d.toLocaleString('tr-TR');}
 function scoreHead(target,score,total,title,subtitle,state){
  const head=document.createElement('div');head.className='net-head '+state;target.append(head);
  const ring=document.createElement('div');ring.className='net-ring';head.append(ring);add(ring,'strong',String(score));add(ring,'small','/ '+total);
  const context=document.createElement('div');head.append(context);add(context,'h2',title);add(context,'p',subtitle,'hint');
 }
 function renderVT(target,indicator,a){
  target.replaceChildren();
  const stats=a.last_analysis_stats;
  if(stats&&typeof stats==='object'){
   const n=k=>Number.isInteger(stats[k])&&stats[k]>=0?stats[k]:0;
   const total=n('malicious')+n('suspicious')+n('undetected')+n('harmless');
   scoreHead(target,n('malicious'),total,indicator.value,a.as_owner?`AS${a.asn||'?'} · ${a.as_owner}`:'VirusTotal gösterge raporu',n('malicious')?'bad':n('suspicious')?'warn':'good');
   add(target,'p',n('malicious')?`${n('malicious')} / ${total} kaynak zararlı işaretledi`:n('suspicious')?`${n('suspicious')} kaynak şüpheli işaretledi`:'✓ Zararlı veya şüpheli tespit bildirilmedi.','net-banner '+(n('malicious')?'bad':n('suspicious')?'warn':'good'));
   const rows=Object.entries(a.last_analysis_results||{}).filter(([,v])=>v&&['malicious','suspicious'].includes(v.category)).sort((x,y)=>x[0].localeCompare(y[0]));
   const grid=document.createElement('div');grid.className='vt-engine-grid';target.append(grid);
   for(const [name,v]of rows.slice(0,10)){const card=document.createElement('div');card.className='vt-engine-card';card.dataset.category=v.category;add(card,'span',str(v.engine_name)||name,'vt-engine-name');add(card,'span',v.category==='malicious'?'⊗ Zararlı':'⚠ Şüpheli','vt-engine-state');grid.append(card);}
   if(!rows.length&&n('malicious')+n('suspicious')>0)add(target,'p','Motor ayrıntıları raporda bulunamadı.','hint');
   if(n('malicious')+n('suspicious')===0)add(target,'div','✓ Zararlı/şüpheli tespit yok; güvenli olduğunun garantisi değildir.','net-clear');
  }else{add(target,'h2',indicator.value);add(target,'p','Tespit bilgisi bulunamadı.');}
  if(indicator.type==='ip_addresses'){
   const pair=document.createElement('div');pair.className='net-pair';target.append(pair);fields(pair,'Konum',[['Ülke',a.country],['Kıta',a.continent]]);
   fields(pair,'Ağ',[['Ağ bloğu',a.network],['ASN',a.asn!==undefined?'AS'+a.asn:''],['Sahip',a.as_owner],['RIR',a.regional_internet_registry]]);
  }else if(indicator.type==='domains'){
   fields(target,'Domain bilgileri',[['Kayıt kuruluşu',a.registrar],['Kayıt tarihi',date(a.creation_date)],['Son değişiklik',date(a.last_update_date)],['Topluluk itibarı',a.reputation]]);
   const records=Array.isArray(a.last_dns_records)?a.last_dns_records.filter(x=>x&&typeof x==='object'):[];
   if(records.length)fields(target,'Son gözlenen DNS kayıtları',records.slice(0,8).map(x=>[str(x.type)||'DNS',str(x.value)]));
  }
  add(target,'p','IP/domain itibarı zamanla değişebilir. Sıfır tespit güvenli olduğu anlamına gelmez. Konum yaklaşık ağ konumudur; kişi veya cihazın kesin konumu değildir.','hint');
  if(a.last_analysis_date)add(target,'p','Son analiz: '+date(a.last_analysis_date),'hint');
  link(target,'https://www.virustotal.com/gui/'+(indicator.type==='urls'?'url/'+(a._reportId||indicator.id):(indicator.type==='domains'?'domain/':'ip-address/')+encodeURIComponent(indicator.value)),'VirusTotal raporunu aç ↗');
 }
 globalThis.SOC_NETWORK={parse,renderVT};
 let sequence=0,controller;
 const cancel=()=>{sequence++;controller?.abort();$('abReport').hidden=true;$('abQuery').disabled=false;$('abStatus').textContent='';};
 $('abOpen').addEventListener('click',()=>{const open=true;$('abArea').hidden=!open;$('abOpen').setAttribute('aria-expanded',String(open));$('vtArea').hidden=true;$('vtSettings').hidden=true;$('vtOpen').setAttribute('aria-expanded','false');});
 const ready=chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}).then(()=>chrome.storage.local.get('abApiKey')).then(v=>{if(!$('abKey').value&&v.abApiKey)$('abKey').value=v.abApiKey;});
 ready.catch(()=>{});
 $('abForget').addEventListener('click',async()=>{await ready;cancel();$('abKey').value='';await chrome.storage.local.remove('abApiKey');$('abStatus').textContent='AbuseIPDB anahtarı silindi.';});
 chrome.storage.onChanged.addListener((c,area)=>{if(area==='local'&&c.abApiKey&&$('abKey').value!==(c.abApiKey.newValue||'')){cancel();$('abKey').value=c.abApiKey.newValue||'';}});
 for(const id of ['abInput','abKey'])$(id).addEventListener('input',cancel);
 $('abInput').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();$('abQuery').click();}});
 $('abQuery').addEventListener('click',async()=>{
  const item=parse($('abInput').value),key=$('abKey').value.trim();
  if(item?.type!=='ip_addresses'){$('abStatus').textContent='Geçerli bir IPv4 veya IPv6 girin; domain veya URL yazmayın.';return;}
  if(!key||/\s/.test(key)){$('abSettings').open=true;$('abKey').focus();$('abStatus').textContent='AbuseIPDB API anahtarınızı girin.';return;}
  cancel();const token=sequence;controller=new AbortController();const signal=controller.signal;$('abQuery').disabled=true;
  try{
   const permission={origins:['https://api.abuseipdb.com/*']};
   const allowed=await chrome.permissions.contains(permission)||await chrome.permissions.request(permission);
   if(token!==sequence)return;if(!allowed)throw Error('AbuseIPDB erişim izni verilmedi.');
   await chrome.storage.local.set({abApiKey:key});
   const result=await navigator.locks.request('soc-abuse-api',{signal},async()=>{
    const next=(await chrome.storage.session.get('abNextRequest')).abNextRequest||0;
    if(next>Date.now())throw Error('İstek sınırı beklemesi var. Biraz sonra yeniden deneyin.');
    await chrome.storage.session.set({abNextRequest:Date.now()+1500});
    if(signal.aborted)throw new DOMException('Aborted','AbortError');
    $('abStatus').textContent='AbuseIPDB raporu alınıyor…';
    const response=await fetch('https://api.abuseipdb.com/api/v2/check?ipAddress='+encodeURIComponent(item.value)+'&maxAgeInDays=90&verbose',{
     headers:{Key:key,Accept:'application/json'},signal:AbortSignal.any([signal,AbortSignal.timeout(30000)]),credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer'
    });
    if(response.status===429)await chrome.storage.session.set({abNextRequest:Date.now()+60000});
    if(!response.ok)throw Error(({401:'API anahtarı geçersiz.',403:'Hesabınızın bu sorguya erişimi yok.',422:'IP sorgusu kabul edilmedi.',429:'API kotası veya istek sınırı doldu.'})[response.status]||'AbuseIPDB raporu alınamadı.');
    return response.json();
   });
   if(token!==sequence)return;
   const d=result?.data;if(!d||parse(d.ipAddress)?.value!==item.value)throw Error('Rapordaki IP sorguyla eşleşmedi.');
   const target=$('abReport');target.replaceChildren();
   const score=d.abuseConfidenceScore,valid=Number.isFinite(score)&&score>=0&&score<=100;
   const level=!valid?'unknown':score===0?'good':score>=75?'bad':'warn';
   if(valid)scoreHead(target,score,100,'İstismar Güven Skoru',`${d.totalReports??'?'} Rapor · ${d.numDistinctUsers??'?'} Bildiren`,level);
   add(target,'h2',item.value,'ab-ip');add(target,'p','IPv'+(d.ipVersion|| (item.value.includes(':')?6:4)),'hint ab-ip-version');
   add(target,'span',!valid?'Veri yok':score===0?'✓ Bildirim puanı yok':score>=75?'⊗ Yüksek risk':'⚠ İncelenmeli','ab-badge '+level);
   add(target,'p',!valid?'İtibar puanı bulunamadı.':score===0?'✓ Düşük istismar güven skoru (0%).':`⚠ İstismar güven skoru: ${score}%`,'net-banner '+level);
   add(target,'p','Puan topluluk bildirimlerine dayanır; zararlılık olasılığı veya kesin saldırgan kimliği değildir.','hint');
   fields(target,'İstismar metrikleri (son 90 gün)',[['Güven skoru',valid?score+'%':''],['Toplam rapor',d.totalReports],['Farklı bildirenler',d.numDistinctUsers],['Son bildirim',date(d.lastReportedAt)]]);
   const categoryNames={3:'Dolandırıcılık',4:'DDoS',5:'FTP kaba kuvvet',6:'Ping of death',7:'Kimlik avı',9:'Açık proxy',10:'Web spam',11:'E-posta spam',14:'Port tarama',15:'Sızma girişimi',16:'SQL enjeksiyonu',18:'Kaba kuvvet',19:'Kötü bot',20:'Ele geçirilmiş sunucu',21:'Web uygulaması saldırısı',22:'SSH',23:'IoT hedefleme'};
   const categories=[...new Set((Array.isArray(d.reports)?d.reports:[]).flatMap(x=>Array.isArray(x?.categories)?x.categories:[]).filter(x=>Number.isInteger(x)))];
   if(categories.length){const box=document.createElement('section');box.className='net-box';target.append(box);add(box,'h3','Dönen bildirimlerdeki kategoriler');const tags=document.createElement('div');tags.className='net-tags';box.append(tags);for(const id of categories)add(tags,'span',categoryNames[id]||'Kategori '+id);}
   
   fields(target,'Konum ve ağ',[['Ülke',d.countryName||d.countryCode],['ISP',d.isp],['Kullanım türü',d.usageType],['İlişkili domain',d.domain],['Host adları',Array.isArray(d.hostnames)?d.hostnames.filter(x=>typeof x==='string').slice(0,8).join(', '):''],['Tor çıkışı',d.isTor===true?'Evet':d.isTor===false?'Hayır':''],['Genel IP',d.isPublic===true?'Evet':d.isPublic===false?'Hayır':'']]);
   add(target,'p','Bu bilgiler cihazınızın gerçek bağlantı geçmişi değildir. Konum yaklaşık olabilir; ASN ve CIDR bu API yanıtında yoksa gösterilmez.','hint');
   link(target,'https://www.abuseipdb.com/check/'+encodeURIComponent(item.value),'AbuseIPDB raporunu aç ↗');
   target.hidden=false;$('abStatus').textContent='Mevcut rapor alındı; bildirim gönderilmedi.';
  }catch(e){if(token===sequence)$('abStatus').textContent=e instanceof TypeError?'Bağlantı kurulamadı. İnterneti ve erişim iznini kontrol edin.':['AbortError','TimeoutError'].includes(e.name)?'İstek iptal edildi veya zaman aşımına uğradı.':e.message;}
  finally{if(token===sequence)$('abQuery').disabled=false;}
 });
 globalThis.SOC_NETWORK_SELECT=async value=>{
  const item=parse(value);if(item?.type!=='ip_addresses')return;
  globalThis.SOC_VT_SELECT?.(item.value);
  $('abArea').hidden=true;$('abOpen').setAttribute('aria-expanded','false');$('abInput').value=item.value;cancel();const token=sequence;
  await ready;if(token!==sequence)return;
  if(!$('abKey').value.trim()){$('abStatus').textContent='AbuseIPDB sorgusu için API anahtarınızı ekleyin.';return;}
  const allowed=await chrome.permissions.contains({origins:['https://api.abuseipdb.com/*']});if(token!==sequence)return;
  if(!allowed){$('abStatus').textContent='İlk kullanımda izin için AbuseIPDB Sorgula düğmesine basın.';return;}
  $('abQuery').click();
 };
})();
