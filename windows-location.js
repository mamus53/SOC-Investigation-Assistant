'use strict';
(()=>{
 function assess(name,entry,context={}){
  if(!entry?.systemDirectories)return null;
  const expected=entry.systemDirectories.map(d=>'%SystemRoot%\\'+d+'\\'+name).join(' veya ');
  let raw=String(context.fullPath||'').trim().replace(/^(["'])(.*)\1$/,'$2').replace(/\//g,'\\');
  if(!raw||raw.toLowerCase()===name)return {status:'missing',text:'Konum karşılaştırması yapılmadı: yalnız dosya adı verildi. Beklenen etkin bileşen yolu: '+expected+'.'};
  raw=raw.replace(/^\\\\\?\\(?=[a-z]:\\)/i,'').replace(/^\\\?\?\\(?=[a-z]:\\)/i,'');
  const unresolved=()=>({status:'unresolved',text:'Konum çözümlenemedi: '+raw+'. Aygıt/UNC/göreli yol, değişken veya yönlendirmeyi hedef cihazda gerçek dosya yoluna dönüştürün. Beklenen etkin bileşen yolu: '+expected+'.'});
  if(/(?:^|\\)\.\.?($|\\)/.test(raw)||/\\sysnative\\/i.test(raw))return unresolved();
  const symbolic=/^(?:%systemroot%|%windir%|\\systemroot)\\/i;
  let tail,rootInferred=false;
  if(symbolic.test(raw))tail=raw.replace(symbolic,'');
  else if(/^[a-z]:\\/i.test(raw)){
   const actualRoot=String(context.windowsRoot||'').replace(/\//g,'\\').replace(/\\$/,'');
   if(actualRoot&&raw.toLowerCase().startsWith(actualRoot.toLowerCase()+'\\'))tail=raw.slice(actualRoot.length+1);
   else if(!actualRoot&&/^[a-z]:\\windows\\/i.test(raw)){tail=raw.slice(11);rootInferred=true;}
   else if(!actualRoot&&/^[a-z]:\\[^\\]+\\(?:system32|syswow64)\\/i.test(raw))return {status:'unresolved',text:'Windows kurulum kökü bilinmiyor: '+raw+'. Özel kurulum dizinini hedef cihazın SystemRoot değeriyle doğrulayın; yalnız standart dışı kök adına dayanarak zararlı saymayın. Beklenen yol: '+expected+'.'};
   else tail=null;
  }else return unresolved();
  const matches=tail&&entry.systemDirectories.some(d=>tail.toLowerCase()===(d+'\\'+name).toLowerCase());
  if(matches)return {status:'match',text:'Konum biçimi beklenen dizinle uyumlu: '+raw+'. '+(rootInferred?'Bu karşılaştırma Windows kurulum kökünün bu sürücüdeki Windows dizini olduğu varsayımına dayanır; hedef cihazın SystemRoot değerini doğrulayın. ':'')+'Konum uyumu dosyanın Microsoft bileşeni veya güvenli olduğunu kanıtlamaz; imza, hash ve çalıştırma bağlamını doğrulayın.'};
  return {status:'mismatch',text:'Konum uyarısı — yüksek araştırma önceliği: '+raw+' beklenen etkin Windows bileşeni konumuyla uyuşmuyor. Beklenen: '+expected+'; standart örnek: C:\\Windows\\'+entry.systemDirectories[0]+'\\'+name+'. Taklit veya yeniden adlandırılmış dosya olasılığını araştırın. Yedek/kurulum kopyası ile gerçekten çalışan süreç yolunu ayırın; yol farkı tek başına zararlı kanıtı değildir.'};
 }
 globalThis.SOC_WINDOWS_LOCATION={assess};
})();
