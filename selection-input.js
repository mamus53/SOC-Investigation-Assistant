(()=>{
 function normalize(raw){
  let value=String(raw||'').trim().replace(/^[*•`]+\s*/, '').replace(/[`]+$/, '');
  if(url(value)||ip(value))return value;
  if(!value||value.length>2048||/[\r\n]/.test(value)||/^[{[]/.test(value))return '';
  const quoted=value.match(/^["']([^"']+)["'](?:\s|$|:)/);if(quoted)value=quoted[1];
  else if(!/^[a-z]:[\\/]/i.test(value)){
   const leading=value.match(/^([^\s:]+\.[a-z0-9]{1,12})(?=[:\s]|$)/i);
   if(leading)value=leading[1];
   else value=value.replace(/\s+\((?:Meşru|Zararlı|Legitimate|Malicious)\).*$/i,'');
  }
  return value.replace(/^['"]|['"]$/g,'').replace(/:$/,'');
 }
 function ip(raw){const v=String(raw||'').trim();if(/^\d+(\.\d+){3}$/.test(v))return v.split('.').every(x=>/^(0|[1-9]\d{0,2})$/.test(x)&&+x<=255);if(!v.includes(':')||!/^\[?[0-9a-f:.]+\]?$/i.test(v))return false;try{return new URL('http://'+(v.startsWith('[')?v:'['+v+']')).hostname.includes(':');}catch{return false;}}
 function domain(raw){let v=String(raw||'').trim().toLowerCase();if(!v||v.length>253||/[\s/:@?#%\\]/.test(v)||v==='command.com'||/\.(exe|dll|sys|bat|cmd|ps1|psm1|psd1|ps1xml|vbs|vbe|js|jse|sh|py|pyc|so|dylib|pl|rb|jar|apk|msi|msp|msix|appx|cab|mui|drv|pyd|whl|config|manifest|scr|ocx|cpl|hta|inf|ini|conf|json|xml|yaml|yml|txt|log|zip|7z|rar|pdf|docx?|xlsx?|lnk|reg|bin|dat|db|sql|ts|c|h|cpp|cs|class|wasm|png|jpg|jpeg|gif|svg|css|html?)$/.test(v))return false;try{v=new URL('https://'+v).hostname;}catch{return false;}return v.includes('.')&&/[a-z]/.test(v.split('.').pop())&&v.split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x));}
 function url(raw){const v=String(raw||'').trim();if(!/^https?:\/\//i.test(v)||/[\r\n\t]/.test(v))return false;try{const u=new URL(v);return !!u.hostname&&!u.username&&!u.password;}catch{return false;}}
 globalThis.SOC_INPUT={normalize,ip,domain,url,offer(raw){const v=normalize(raw);return !!v&&(url(v)||ip(v)||domain(v)||/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(v)||/\.[a-z0-9]{1,10}$/i.test(v)&&!(/^[\w.-]+\.com$/i.test(v)&&v.toLowerCase()!=='command.com')||/^(system|system idle process|registry|memory compression|systemd|sshd|bash|zsh|python3|cron|launchd|nmap|netexec|nxc|mimikatz|emotet|hydra|hashcat|nuclei|masscan|certipy|bloodhound|ligolo-ng|nanocore|agenttesla)$/i.test(v));}};
})();
