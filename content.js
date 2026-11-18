(() => {
  'use strict';
  if (document.getElementById('soc-process-only-trigger-v4')) return;
  const button = document.createElement('button');
  button.id = 'soc-process-only-trigger-v4';
  button.type = 'button';
  // Single high-contrast blue gear, matching the application and Chrome icons.
  // Keep the SVG in the isolated content script: no external resources or page CSP dependencies.
  const ns = 'http://www.w3.org/2000/svg';
  function vector(tag, attributes, parent){
    const node = document.createElementNS(ns, tag);
    Object.entries(attributes).forEach(([key,value]) => node.setAttribute(key, String(value)));
    if(parent) parent.appendChild(node);
    return node;
  }
  const gear = vector('svg', {
    xmlns:ns, viewBox:'0 0 128 128', width:27, height:27,
    'aria-hidden':'true', focusable:'false'
  });
  gear.style.cssText='display:block;flex:0 0 27px;filter:drop-shadow(0 0 2px rgba(0,160,255,.34))';
  const defs=vector('defs',{},gear);
  function gradient(id,stops){
    const g=vector('linearGradient',{id,x1:'8%',y1:'0%',x2:'91%',y2:'100%'},defs);
    stops.forEach(([offset,color])=>vector('stop',{offset,'stop-color':color},g));
  }
  gradient('soc-single-gear-metal',[['0%','#9BEAFF'],['17%','#41C8FF'],['47%','#0877DF'],['74%','#1557B6'],['100%','#1FA6F2']]);
  gradient('soc-single-gear-spokes',[['0%','#A7F0FF'],['37%','#2CA9EF'],['100%','#0754B8']]);
  const well=vector('radialGradient',{id:'soc-single-gear-well',cx:'40%',cy:'32%',r:'78%'},defs);
  [['0%','#0D2950'],['100%','#020A18']].forEach(([offset,color])=>vector('stop',{offset,'stop-color':color},well));
  // Identical ten-tooth silhouette and five-spoke layout to the cover art.
  vector('path',{
    d:"M 64.000,20.000 L 67.039,20.105 L 71.546,12.146 L 85.112,16.041 L 84.711,25.179 L 89.638,28.241 L 89.863,28.403 L 92.259,30.274 L 100.584,26.485 L 109.270,37.610 L 103.574,44.767 L 105.760,50.141 L 105.846,50.403 L 106.686,53.326 L 115.648,55.153 L 116.135,69.259 L 107.321,71.701 L 105.931,77.334 L 105.846,77.597 L 104.808,80.454 L 110.984,87.201 L 103.087,98.899 L 94.521,95.694 L 90.086,99.434 L 89.863,99.597 L 87.342,101.298 L 88.374,110.386 L 75.109,115.209 L 70.063,107.580 L 64.276,107.999 L 64.000,108.000 L 60.961,107.895 L 56.454,115.854 L 42.888,111.959 L 43.289,102.821 L 38.362,99.759 L 38.137,99.597 L 35.741,97.726 L 27.416,101.515 L 18.730,90.390 L 24.426,83.233 L 22.240,77.859 L 22.154,77.597 L 21.314,74.674 L 12.352,72.847 L 11.865,58.741 L 20.679,56.299 L 22.069,50.666 L 22.154,50.403 L 23.192,47.546 L 17.016,40.799 L 24.913,29.101 L 33.479,32.306 L 37.914,28.566 L 38.137,28.403 L 40.658,26.702 L 39.626,17.614 L 52.891,12.791 L 57.937,20.420 L 63.724,20.001 Z",
    fill:'url(#soc-single-gear-metal)', stroke:'#74DFFF',
    'stroke-width':2.0,'stroke-linejoin':'round'
  },gear);
  vector('circle',{cx:64,cy:64,r:34,fill:'url(#soc-single-gear-well)',stroke:'#072B61','stroke-width':2.4},gear);
  vector('circle',{cx:64,cy:64,r:33,fill:'none',stroke:'#4FCBFF','stroke-width':1.4,opacity:.88},gear);
  for(let i=0;i<5;i++){
    const a=i*2*Math.PI/5-Math.PI/2;
    const x1=64+Math.cos(a)*20,y1=64+Math.sin(a)*20;
    const x2=64+Math.cos(a)*31,y2=64+Math.sin(a)*31;
    vector('line',{x1,y1,x2,y2,stroke:'url(#soc-single-gear-spokes)',
      'stroke-width':11.5,'stroke-linecap':'round'},gear);
  }
  vector('circle',{cx:64,cy:64,r:15.2,fill:'url(#soc-single-gear-spokes)',stroke:'#95E7FF','stroke-width':1.9},gear);
  vector('circle',{cx:64,cy:64,r:7.5,fill:'#04132A',stroke:'#78DAFF','stroke-width':1.7},gear);
  vector('circle',{cx:61.3,cy:61.7,r:1.7,fill:'#B3F2FF',opacity:.9},gear);
  const label = document.createElement('span');
  label.textContent = 'Analiz Et';
  label.style.cssText = 'display:block;white-space:nowrap;line-height:18px';
  button.append(gear,label);
  label.style.maxWidth='0';label.style.opacity='0';label.style.overflow='hidden';
  label.style.transition='max-width .18s ease,opacity .18s ease';
  function expandLabel(expanded){label.style.maxWidth=expanded?'85px':'0';label.style.opacity=expanded?'1':'0';button.style.gap=expanded?'6px':'0';}
  button.addEventListener('pointerenter',()=>expandLabel(true));
  button.addEventListener('pointerleave',()=>expandLabel(false));
  button.addEventListener('focus',()=>expandLabel(true));
  button.addEventListener('blur',()=>expandLabel(false));

  button.setAttribute('aria-label', 'Analiz Et — seçili dosya veya süreç için SOC analiz panelini aç');
  button.title = 'Analiz Et';
  Object.assign(button.style, {
    all:'initial', position:'fixed', display:'none', zIndex:'2147483647',
    background:'linear-gradient(115deg,#031022 0%,#071E3D 60%,#082850 100%)',
    color:'#f6fbff', border:'1px solid #2386D8',
    padding:'5px 8px', borderRadius:'999px',
    font:'700 12px/18px system-ui,sans-serif',
    boxShadow:'inset 0 1px 0 rgba(119,205,255,.14),0 0 0 1px rgba(14,77,151,.2),0 5px 17px rgba(0,53,138,.35),0 2px 8px rgba(0,0,0,.32)',
    cursor:'pointer', pointerEvents:'auto', whiteSpace:'nowrap', boxSizing:'border-box',
    alignItems:'center', justifyContent:'center', gap:'0', minHeight:'38px',
    textShadow:'0 1px 2px rgba(0,8,29,.55)'
  });
  button.addEventListener('pointerenter',()=>{button.style.filter='brightness(1.1)';});
  button.addEventListener('pointerleave',()=>{button.style.filter='none';});
  (document.body || document.documentElement).appendChild(button);
  let current = '', lastTimer = null, pointerOnButton = false;
  function hide(){button.style.display='none';}
  function readSelection(){
    const active = document.activeElement;
    if(active?.tagName==='INPUT' && /^(password|hidden)$/i.test(active.type))return '';
    if(active && (active.tagName === 'TEXTAREA' || active.tagName === 'INPUT')){
      try{
        const a=active.selectionStart,b=active.selectionEnd;
        if(Number.isInteger(a)&&Number.isInteger(b)&&a!==b) return active.value.slice(a,b).trim();
      }catch(_){/* password/input type unsupported */}
      return '';
    }
    return (window.getSelection()?.toString() || '').trim();
  }
  function selectionRect(){
    const s=window.getSelection();
    if(s && s.rangeCount && s.toString().trim()){
      const r=s.getRangeAt(0).getBoundingClientRect();
      if(r && (r.width || r.height)) return r;
    }
    return document.activeElement?.getBoundingClientRect?.() || null;
  }
  function update(){
    if(pointerOnButton) return;
    const value = readSelection();
    // Show for supported execution-related file types, not arbitrary words.
    if(!SOC_INPUT.offer(value)){hide();return;}
    const rect=selectionRect();
    if(!rect){hide();return;}
    current=value;label.textContent='Analiz Et';button.title='Analiz Et';label.textContent='Analiz Et';button.title='Analiz Et';
    button.style.display='flex';
    button.style.left=Math.max(8,Math.min(window.innerWidth-button.offsetWidth-8,rect.right+8))+'px';
    button.style.top=Math.max(8,Math.min(window.innerHeight-button.offsetHeight-8,rect.bottom+7))+'px';
  }
  function schedule(){clearTimeout(lastTimer);lastTimer=setTimeout(update,65);}
  document.addEventListener('selectionchange',schedule);
  document.addEventListener('mouseup',schedule,true);
  document.addEventListener('keyup',schedule,true);
  button.addEventListener('pointerdown',e=>{pointerOnButton=true;e.preventDefault();e.stopPropagation();});
  button.addEventListener('click',e=>{
    e.preventDefault();e.stopPropagation();
    const text=SOC_INPUT.normalize(current);pointerOnButton=false;hide();
    if(!text)return;
    const failure=error=>{expandLabel(true);
      label.textContent='Sayfayı yenile ve tekrar dene';
      button.title='Analiz paneli açılamadı: '+String(error?.message||error||'Bağlantı kesildi')+'. Uzantı güncellendiyse bu web sayfasını F5 ile yenile.';
      button.style.display='flex';
    };
    try{
      if(!chrome.runtime?.id)throw Error('Uzantı bağlantısı güncelleme nedeniyle yenilenmeli');
      chrome.runtime.sendMessage({type:'SOC_PROCESS_SELECTED',text}).then(r=>{if(!r?.ok)failure(r?.error);}).catch(failure);
    }catch(error){failure(error);}
  });
  document.addEventListener('pointerup',e=>{if(!button.contains(e.target)) pointerOnButton=false;},true);
  document.addEventListener('keydown',e=>{if(e.key==='Escape') hide();});
  document.addEventListener('scroll',hide,true);
  window.addEventListener('blur',()=>{pointerOnButton=false;hide();});
})();
