/* Optional hash-only VirusTotal lookup. Never uploads or executes a file. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const origin = 'https://www.virustotal.com/*';
  let selected = null, generation = 0, controller = null, current = null, hashing = false;
  const validHash = s => /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(s);
  const clean = v => typeof v === 'string' ? v.slice(0, 700) : '';
  const number = v => Number.isInteger(v) && v >= 0 ? v : 0;
  function text(parent, value, tag = 'p', className = '') {
    const el = document.createElement(tag); el.textContent = value;
    if (className) el.className = className;
    parent.append(el); return el;
  }
  function reset() {
    generation++; controller?.abort(); current = null; hashing = false;
    $('vtReport').hidden = true; $('vtNetwork').hidden=true; $('vtQuery').disabled = false;
    $('vtStatus').textContent = '';
  }
  function errorText(error) {
    if (['AbortError','TimeoutError'].includes(error.name)) return 'İstek iptal edildi veya zaman aşımına uğradı. Yeniden deneyebilirsiniz.';
    return error.vtMessage || 'Bağlantı kurulamadı. İnterneti ve VirusTotal erişim iznini kontrol edin.';
  }
  function fail(message) { const e = new Error('VT request failed'); e.vtMessage = message; return e; }
  function delay(ms, signal) {
    return new Promise((resolve, reject) => {
      if (signal.aborted) return reject(new DOMException('Aborted', 'AbortError'));
      const abort = () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); };
      const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve(); }, ms);
      signal.addEventListener('abort', abort, {once:true});
    });
  }
  async function api(path, key, signal, status) {
    // A cross-panel lock and session timestamp enforce spacing even after reopening.
    return navigator.locks.request('soc-vt-api', {signal}, async () => {
      const saved = await chrome.storage.session.get('vtNextRequest');
      const remaining = Math.max(0, Math.min(60000, (saved.vtNextRequest || 0) - Date.now()));
      if (remaining) { status('İstek sınırı için kısa bir bekleme…'); await delay(remaining, signal); }
      if (signal.aborted) throw new DOMException('Aborted','AbortError');
      await chrome.storage.session.set({vtNextRequest:Date.now() + 16000});
      status('VirusTotal raporu alınıyor…');
      const response = await fetch('https://www.virustotal.com/api/v3/' + (path.startsWith('ip_addresses/')||path.startsWith('domains/')||path.startsWith('urls/')?path:'files/'+path), {
        headers:{'x-apikey':key, Accept:'application/json'},
        signal:AbortSignal.any([signal, AbortSignal.timeout(30000)]),
        credentials:'omit', cache:'no-store', redirect:'error', referrerPolicy:'no-referrer'
      });
      if (!response.ok) {
        const messages = {401:'API anahtarı geçersiz. Anahtarınızı kontrol edin.',403:'Bu rapor alanına erişim izniniz yok. Hesabınızın API yetkilerini kontrol edin.',404:'VirusTotal’da bu sorgu için rapor bulunamadı. Bu sonuç dosyanın güvenli olduğunu göstermez.',429:'API kotası veya istek sınırı doldu. Daha sonra yeniden deneyin.'};
        if (response.status === 429) await chrome.storage.session.set({vtNextRequest:Date.now()+60000});
        throw fail(messages[response.status] || 'VirusTotal şu anda yanıt veremiyor. Daha sonra yeniden deneyin.');
      }
      return response.json();
    });
  }
  $('vtOpen').addEventListener('click', () => {
    const open = true; $('abArea').hidden=true;$('abOpen').setAttribute('aria-expanded','false');$('vtSettings').hidden=false; $('vtArea').hidden = !open;
    $('vtOpen').setAttribute('aria-expanded', String(open));
  });
  const keyReady=chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}).then(()=>chrome.storage.local.get('vtApiKey')).then(async v => {
    if(!v.vtApiKey){const previous=await chrome.storage.session.get('vtApiKey');if(previous.vtApiKey){v=previous;await chrome.storage.local.set({vtApiKey:v.vtApiKey});await chrome.storage.session.remove('vtApiKey');}}
    if (!$('vtKey').value && v.vtApiKey) $('vtKey').value = v.vtApiKey;
  }).catch(() => {});
  $('vtForget').addEventListener('click', async () => {
    await keyReady;
    reset(); $('vtKey').value = ''; await chrome.storage.local.remove('vtApiKey'); await chrome.storage.session.remove('vtApiKey');
    $('vtStatus').textContent = 'API anahtarı bu cihazdan silindi.';
  });
  $('vtKey').addEventListener('input', reset);
  chrome.storage.onChanged.addListener((changes,area)=>{
    if(area!=='local' || !changes.vtApiKey)return;
    const value=changes.vtApiKey.newValue||'';
    if($('vtKey').value!==value){reset();$('vtKey').value=value;$('vtStatus').textContent=value?'API anahtarı diğer panelde güncellendi.':'API anahtarı silindi.';}
  });
  $('vtHash').addEventListener('input', () => {
    reset(); selected = null; hashing = false;
    $('vtSelected').textContent = ''; $('vtFile').value = '';
  });
  async function selectFile(files) {
    reset(); selected = null; $('vtHash').value = ''; $('vtSelected').textContent = '';
    hashing = false;
    if (files.length !== 1) { $('vtStatus').textContent = 'Lütfen tek bir dosya seçin.'; return; }
    const file = files[0];
    if (file.size > 100 * 1024 * 1024) { $('vtStatus').textContent = 'Bu hafif sürümde dosya sınırı 100 MB. Daha büyük dosyalar için hash değerini girin.'; return; }
    const token = generation; hashing = true; $('vtQuery').disabled = true;
    $('vtStatus').textContent = 'Dosyanın SHA-256 değeri cihazınızda hesaplanıyor…';
    try {
      const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
      if (token !== generation) return;
      const hash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2,'0')).join('');
      selected = {name:file.name, hash}; $('vtHash').value = hash;
      $('vtSelected').textContent = 'Seçilen dosya: ' + file.name;
      $('vtStatus').textContent = 'Hash hazır. Dosya içeriği gönderilmedi.';
    } catch (_) { if (token === generation) $('vtStatus').textContent = 'Dosya okunamadı. Dosyayı yeniden seçin veya hash girin.'; }
    finally { if (token === generation) { hashing = false; $('vtQuery').disabled = false; } }
  }
  $('vtDrop').addEventListener('click', () => $('vtFile').click());
  $('vtFile').addEventListener('change', () => { const files = [...$('vtFile').files]; $('vtFile').value = ''; selectFile(files); });
  for (const event of ['dragenter','dragover']) $('vtDrop').addEventListener(event, e => {e.preventDefault(); $('vtDrop').classList.add('drag');});
  $('vtDrop').addEventListener('dragleave', () => $('vtDrop').classList.remove('drag'));
  $('vtDrop').addEventListener('drop', e => { e.preventDefault(); $('vtDrop').classList.remove('drag'); selectFile([...e.dataTransfer.files]); });
  // Prevent accidental navigation when a file misses the drop target.
  for (const event of ['dragover','drop']) window.addEventListener(event, e => {if ([...e.dataTransfer.types].includes('Files')) e.preventDefault();});
  function detections(a) {
    const target=$('vtDetectionBody');target.replaceChildren();
    const stats=a.last_analysis_stats;
    if(!stats || typeof stats!=='object'){text(target,'Tespit sonucu bulunamadı.');return;}
    const malicious=number(stats.malicious),suspicious=number(stats.suspicious);
    const total=malicious+suspicious+number(stats.undetected)+number(stats.harmless);
    const hero=document.createElement('div');hero.className='vt-score-head';target.append(hero);
    const ring=document.createElement('div');ring.className='vt-score-ring'+(malicious?'':' neutral');
    ring.style.setProperty('--score-angle',`${total?Math.round(malicious/total*360):0}deg`);
    const inside=document.createElement('div');ring.append(inside);text(inside,String(malicious),'strong');text(inside,'/ '+total,'small');hero.append(ring);
    const heading=document.createElement('div');hero.append(heading);text(heading,'Güvenlik motorları','h3');
    text(heading,`${suspicious} şüpheli · ${number(stats.undetected)} tespit yok`,'p','hint');
    text(heading,`${number(stats.harmless)} zararsız değerlendirmesi`,'p','hint');
    text(target,`${malicious} / ${total} motor zararlı işaretledi`,'p',malicious?'vt-score-banner':'vt-score-banner neutral');
    const rows=Object.entries(a.last_analysis_results||{}).filter(([,v])=>v&&typeof v==='object').sort((x,y)=>{
      const order={malicious:0,suspicious:1,undetected:2,harmless:3};return (order[x[1].category]??4)-(order[y[1].category]??4)||x[0].localeCompare(y[0]);
    });
    const grid=document.createElement('div');grid.className='vt-engine-grid';target.append(grid);
    const labels={malicious:'Zararlı',suspicious:'Şüpheli',undetected:'Tespit yok',harmless:'Zararsız',timeout:'Zaman aşımı','confirmed-timeout':'Zaman aşımı',failure:'Analiz hatası','type-unsupported':'Desteklenmiyor'};
    function render(){
      grid.replaceChildren();
      for(const [name,v] of rows.slice(0,10)){
        const card=document.createElement('div');card.className='vt-engine-card';
        const category=['malicious','suspicious','harmless','undetected'].includes(v.category)?v.category:'neutral';card.dataset.category=category;
        text(card,clean(v.engine_name)||name,'span','vt-engine-name');
        text(card,(['malicious','suspicious'].includes(v.category)?'⊗ ':['harmless','undetected'].includes(v.category)?'✓ ':'· ')+(labels[v.category]||'Sonuç yok'),'span','vt-engine-state');
        if(clean(v.result))text(card,clean(v.result),'small','vt-engine-label');
        grid.append(card);
      }
      if(!rows.length)text(grid,'Motor ayrıntıları bulunamadı.');

    }
    render();
    const note=document.createElement('div');note.className='vt-method';target.append(note);
    text(note,'Oran yalnız sonuç üreten motorları içerir; zararlılık olasılığı değildir. Sıfır tespit güvenli olduğunu kanıtlamaz.','p','hint');
    const other=number(stats.timeout)+number(stats['confirmed-timeout'])+number(stats.failure)+number(stats['type-unsupported']);
    if(other)text(note,`${other} motor sonuç üretemedi veya dosya türünü desteklemedi.`,'p','hint');
    if(Number.isFinite(a.last_analysis_date))text(target,'Son analiz: '+new Date(a.last_analysis_date*1000).toLocaleString('tr-TR'),'p','hint');
    reportLink(target,a.sha256,'detection','Tüm tespit sonuçlarını aç ↗');
  }
  function reportLink(target, hash, tab, label) {
    const link = text(target,label,'a','sourceLink');
    link.href = 'https://www.virustotal.com/gui/file/'+hash+'/'+tab;
    link.target = '_blank'; link.rel = 'noopener noreferrer';
  }
  function signature(a) {
    const target = $('vtSignatureBody'); target.replaceChildren();
    const info = a.signature_info;
    const verified=clean(info?.verified);
    if(/^signed$/i.test(verified.trim()))text(target,'✓ İmzalı (VirusTotal raporu)','p','vt-signature-empty vt-signed');
    else if(verified)text(target,'⚠ İmza durumu: '+verified,'p','vt-signature-empty');
    else text(target,'⚠ İmza bilgisi bulunamadı.','p','vt-signature-empty');
    const signers=clean(info?.signers).split(';').map(s=>s.trim()).filter(Boolean);
    if(signers.length){text(target,'İmzalayanlar','h3');const list=document.createElement('ul');list.className='vt-signers';target.append(list);for(const signer of signers)text(list,signer,'li');}
    const signing=document.createElement('dl');signing.className='vt-version';target.append(signing);
    for(const [key,label] of [['signing date','İmza tarihi'],['signers details','İmzalayan ayrıntısı']]){const value=clean(info?.[key]);if(value){text(signing,label,'dt');text(signing,value,'dd');}}
    text(target,'Dosya sürüm bilgileri','h3');
    const versionFields=[['product','Ürün'],['file version','Dosya sürümü'],['product version','Ürün sürümü'],['description','Açıklama'],['copyright','Telif hakkı'],['original name','Özgün dosya adı'],['internal name','İç ad']];
    const versions=document.createElement('dl');versions.className='vt-version';target.append(versions);let versionCount=0;
    for(const [key,label] of versionFields){const value=clean(info?.[key]);if(value){text(versions,label,'dt');text(versions,value,'dd');versionCount++;}}
    if(!versionCount)text(target,'Dosya sürüm bilgisi raporda bulunamadı.','p','hint');
    else text(target,'Sürüm ve ürün alanları dosya metadata bilgileridir; doğrulanmış imza veya güvenilirlik kanıtı değildir.','p','hint');
    text(target,'İmza bilgisi yokluğu dosyanın imzasız olduğunu göstermez. Dijital imza, güvenlik veya yazılım lisansı kanıtı değildir.', 'p','hint');
    reportLink(target, a.sha256, 'details', 'VirusTotal dosya ayrıntılarını aç ↗');
  }
  $('vtQuery').addEventListener('click', async () => {
    if (hashing) return;
    const hash = $('vtHash').value.trim(), key = $('vtKey').value.trim();
    const indicator=globalThis.SOC_NETWORK.parse(hash);
    if (!validHash(hash) && !indicator) { $('vtStatus').textContent = 'Geçerli bir hash, IP veya domain girin. URL/port yerine yalnız göstergeyi yazın.'; return; }
    if (!key || /\s/.test(key)) { $('vtStatus').textContent = 'API ayarlarından anahtarınızı girin; boşluk içermemelidir.'; $('vtSettings').open=true; $('vtKey').focus(); return; }
    reset(); const token = generation; const localName = selected?.hash === hash ? selected.name : '';
    controller = new AbortController(); const signal = controller.signal; $('vtQuery').disabled = true;
    try {
      const allowed = await chrome.permissions.contains({origins:[origin]}) || await chrome.permissions.request({origins:[origin]});
      if (token !== generation) return;
      if (!allowed) throw fail('VirusTotal erişim izni verilmedi. Çevrimdışı araştırmayı kullanmaya devam edebilirsiniz.');
      await chrome.storage.local.set({vtApiKey:key});
      const result = await api(indicator?indicator.path:hash,key,signal, message => {if (token===generation) $('vtStatus').textContent=message;});
      if (token !== generation) return;
      if(indicator){
        if(!result?.data?.attributes || globalThis.SOC_NETWORK.parse(indicator.type==='urls'?result.data.attributes.url:result.data.id)?.value!==indicator.value)throw fail('Rapordaki gösterge sorguyla eşleşmedi.');
        globalThis.SOC_NETWORK.renderVT($('vtNetwork'),indicator,{...result.data.attributes,_reportId:/^[a-f0-9]{64}$/i.test(result.data.id)?result.data.id:undefined});$('vtNetwork').hidden=false;$('vtStatus').textContent='Mevcut gösterge raporu alındı.';return;
      }
      const a = result?.data?.attributes;
      if (!a || !/^[a-f0-9]{64}$/i.test(a.sha256 || '')) throw fail('Rapor beklenen dosya bilgilerini içermiyor.');
      const returned = hash.length === 64 ? a.sha256 : hash.length === 40 ? a.sha1 : a.md5;
      if (typeof returned !== 'string' || returned.toLowerCase() !== hash.toLowerCase()) throw fail('Rapordaki hash sorguyla eşleşmedi; sonuç gösterilmedi.');
      const reportName = clean(a.meaningful_name) || (Array.isArray(a.names) ? clean(a.names.find(n => typeof n === 'string' && n)) : '');
      $('vtName').textContent = localName || reportName || 'Dosya adı raporda bulunamadı';
      $('vtIdentity').textContent = localName ? 'Seçilen dosya' + (reportName ? ' · VirusTotal adı: '+reportName : '') : 'VirusTotal raporundaki ad; aynı dosyanın farklı adları olabilir.';
      $('vtReportHash').textContent = 'SHA-256: '+a.sha256;
      $('vtLink').href = 'https://www.virustotal.com/gui/file/'+a.sha256;
      detections(a); signature(a);
      current = {sandbox:a.sandbox_verdicts,hash:a.sha256,key,token,signal,behaviourLoaded:false,behaviourLoading:false};
      $('vtBehaviour').open = false;
      $('vtBehaviourBody').replaceChildren(); text($('vtBehaviourBody'),'Davranış özeti bu dosyanın raporundan gösterilir.');
      activateTab(0); $('vtReport').hidden = false; $('vtStatus').textContent = 'Bağlantı doğrulandı. Mevcut rapor alındı; dosya yüklenmedi.';
    } catch (e) { if (token === generation) $('vtStatus').textContent = errorText(e); }
    finally { if (token === generation) $('vtQuery').disabled = false; }
  });
  function behaviour(data, target) {
    target.replaceChildren();
    text(target,'Etkinlik özeti','h3');
    const verdicts=current.sandbox || {};
    const labels=[...new Set(Object.values(verdicts).flatMap(v=>Array.isArray(v?.malware_classification)?v.malware_classification:[]).filter(v=>typeof v==='string'))];
    const translations={'ransom':'Fidye yazılımı','evader':'Analizden kaçınma','ransomware':'Fidye yazılımı','trojan':'Truva atı','malware':'Kötü amaçlı yazılım','downloader':'İndirici','dropper':'Yükleyici'};
    text(target,labels.length?labels.map(v=>translations[v.toLowerCase()]||v).join(' · '):'Etkinlik etiketi bulunamadı.');
    text(target,'Dinamik analiz sandbox değerlendirmeleri','h3');
    let count=0;
    for(const [name,v] of Object.entries(verdicts)) {
      if(!v || typeof v!=='object')continue;
      const labels=Array.isArray(v.malware_classification)?v.malware_classification.filter(x=>typeof x==='string'):[];
      const cat={malicious:'Zararlı',suspicious:'Şüpheli',harmless:'Zararsız',undetected:'Tespit yok'}[v.category]||'';
      const value=[cat,...labels.map(x=>translations[x.toLowerCase()]||x)].filter(Boolean).join(' · ');
      if(value){
        const row=document.createElement('div');row.className='vt-verdict';
        const icon=text(row,'⚠','span','vt-verdict-icon');icon.setAttribute('aria-hidden','true');
        const line=document.createElement('span');row.append(line);
        text(line,clean(v.sandbox_name)||name,'strong');
        text(line,' sanal ortamı bu dosyayı şöyle değerlendiriyor: ','span');
        text(line,value,'strong','vt-verdict-value');
        target.append(row);count++;
      }
    }
    if(!count)text(target,'Sandbox değerlendirmesi bulunamadı.');
    text(target,'Bunlar analiz ortamının değerlendirmeleridir; cihazınızda bulaşma olduğunu tek başına doğrulamaz.','p','hint');
    reportLink(target,current.hash,'behavior','VirusTotal davranış raporunu aç ↗');
  }
  $('vtBehaviour').addEventListener('toggle', async () => {
    const item = current;
    if (!$('vtBehaviour').open || !item || item.behaviourLoaded || item.behaviourLoading) return;
    item.behaviourLoading = true; const target=$('vtBehaviourBody');
    try {
      behaviour({},target); item.behaviourLoaded=true;
    } catch (e) {if(current===item) {target.replaceChildren();text(target,errorText(e));text(target,'Yeniden denemek için başlığı kapatıp açın.','p','hint');}}
    finally {item.behaviourLoading=false;}
  });
  const sections=['vtDetections','vtBehaviour','vtSignature'];
  function activateTab(index) {
    sections.forEach((id,i)=>{const panel=$(id);panel.hidden=i!==index;panel.open=i===index;panel.setAttribute('role','tabpanel');panel.setAttribute('aria-labelledby','vtTab'+i);$('vtTab'+i).setAttribute('aria-selected',String(i===index));$('vtTab'+i).tabIndex=i===index?0:-1;});
  }
  sections.forEach((_,i)=>{const tab=$('vtTab'+i);tab.addEventListener('click',()=>activateTab(i));tab.addEventListener('keydown',e=>{if(['ArrowLeft','ArrowRight'].includes(e.key)){e.preventDefault();const next=(i+(e.key==='ArrowRight'?1:2))%3;activateTab(next);$('vtTab'+next).focus();}});});
  $('vtHash').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();$('vtQuery').click();}});
  globalThis.SOC_VT_SELECT=async hash=>{
    reset();const token=generation;selected=null;$('abArea').hidden=true;$('abOpen').setAttribute('aria-expanded','false');$('vtSettings').hidden=false;$('vtArea').hidden=false;$('vtOpen').setAttribute('aria-expanded','true');$('vtHash').value=hash;$('vtSelected').textContent='';$('vtHash').focus();$('vtHash').scrollIntoView({block:'center'});
    await keyReady;if(token!==generation)return;
    if(!$('vtKey').value.trim()){$('vtSettings').open=true;$('vtStatus').textContent='Otomatik sorgu için API anahtarınızı girin, ardından Sorgula’ya basın.';return;}
    const allowed=await chrome.permissions.contains({origins:[origin]});if(token!==generation)return;
    if(!allowed){$('vtStatus').textContent='İlk kullanımda erişim izni için Sorgula’ya basın. Sonraki hash seçimleri otomatik sorgulanır.';return;}
    $('vtQuery').click();
  };
  if(globalThis.SOC_PENDING_HASH)globalThis.SOC_VT_SELECT(globalThis.SOC_PENDING_HASH);
  if(globalThis.SOC_PENDING_IP)globalThis.SOC_NETWORK_SELECT?.(globalThis.SOC_PENDING_IP);
  activateTab(0);
})();
