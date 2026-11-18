(()=>{
 const el=id=>document.getElementById(id);let epoch=0,windowId=null,lastSelectionId=null,buffer=[],saveQueue=Promise.resolve();
 const status=t=>{el('result').replaceChildren();const p=document.createElement('p');p.className='muted';p.textContent=t;el('result').append(p);};
 function save(value){if(windowId===null)return;const key='socPanel:'+windowId;saveQueue=saveQueue.catch(()=>{}).then(()=>chrome.storage.session.set({[key]:value}));saveQueue.catch(()=>{});}
 async function show(raw,selectionId=lastSelectionId){
  const mine=++epoch,value=SOC_INPUT.normalize(raw);el('suggest').hidden=true;
  if(!value){status('Tek bir dosya veya araç adı ya da tam dosya yolu gir.');return;}
  lastSelectionId=selectionId;
  if(/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value)){if(/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(el('procInput').value.trim()))el('procInput').value='';globalThis.SOC_PENDING_HASH=value;globalThis.SOC_VT_SELECT?.(value);save({value:el('procInput').value,lastSelectionId});return;}
  if(SOC_INPUT.ip(value)){if(SOC_INPUT.ip(el('procInput').value))el('procInput').value='';globalThis.SOC_PENDING_IP=value;globalThis.SOC_NETWORK_SELECT?.(value);save({value:el('procInput').value,lastSelectionId});return;}
  if(SOC_INPUT.url(value)||SOC_INPUT.domain(value)){if(SOC_INPUT.url(el('procInput').value)||SOC_INPUT.domain(el('procInput').value))el('procInput').value='';globalThis.SOC_PENDING_HASH=value;globalThis.SOC_VT_SELECT?.(value);save({value:el('procInput').value,lastSelectionId});return;}
  el('procInput').value=value;
  const name=value.replace(/\\/g,'/').split('/').pop().toLowerCase();
  status('Dosya adı araştırılıyor…');
  try{const r=await SOC_CATALOG.lookup(name);if(epoch!==mine)return;el('result').replaceChildren();renderResearch(el('result'),name,r.entry,r.from,{fullPath:value});save({value,lastSelectionId});}
  catch{if(epoch===mine)status('Kütüphane parçası yüklenemedi. Araştır düğmesine yeniden bas. Sorun sürerse uzantıyı yeniden yükle.');}
 }
 function consume(record){if(!record||record.id===lastSelectionId)return;void show(record.text,record.id);}
 chrome.storage.onChanged.addListener((changes,area)=>{if(area!=='session')return;if(windowId===null){buffer.push(changes);return;}consume(changes['socSelection:'+windowId]?.newValue);});
 el('analyzeBtn').addEventListener('click',()=>show(el('procInput').value));
 el('procInput').addEventListener('input',async()=>{const mine=++epoch,text=el('procInput').value.trim().toLowerCase();el('suggest').hidden=true;if(text.length<2||text.length>100)return;
  try{const names=await SOC_CATALOG.suggest(text);if(epoch!==mine)return;el('suggest').replaceChildren();for(const n of names){const b=document.createElement('button');b.type='button';b.textContent=n;b.setAttribute('role','option');b.addEventListener('click',()=>show(n));el('suggest').append(b);}el('suggest').hidden=!names.length;}catch{}
 });
 el('procInput').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();void show(el('procInput').value);}if(e.key==='Escape')el('suggest').hidden=true;if(e.key==='ArrowDown'&&!el('suggest').hidden){e.preventDefault();el('suggest').querySelector('button')?.focus();}});
 el('suggest').addEventListener('keydown',e=>{const buttons=[...el('suggest').querySelectorAll('button')],i=buttons.indexOf(document.activeElement);if(e.key==='Escape'){el('suggest').hidden=true;el('procInput').focus();}if(['ArrowDown','ArrowUp'].includes(e.key)){e.preventDefault();(buttons[i+(e.key==='ArrowDown'?1:-1)]||el('procInput')).focus();}});
 status('Kütüphane hazır. Dosya veya araç adı gir.');globalThis.SOC_STARTUP={library:'ready',readyMs:performance.now()};
 const initialEpoch=epoch;
 void(async()=>{
  const w=await chrome.windows.getCurrent();windowId=w.id;
  const selectionKey='socSelection:'+windowId,stateKey='socPanel:'+windowId;
  const stored=await chrome.storage.session.get([selectionKey,stateKey]);
  if(epoch!==initialEpoch){buffer=[];return;}
  let selected=stored[selectionKey];for(const changes of buffer)if(changes[selectionKey]?.newValue)selected=changes[selectionKey].newValue;buffer=[];
  const state=stored[stateKey];lastSelectionId=state?.lastSelectionId||null;
  if(selected&&selected.id!==lastSelectionId)consume(selected);else if(state?.value)void show(state.value);
 })().catch(()=>{});
})();

