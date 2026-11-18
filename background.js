'use strict';
let writes=Promise.resolve();
function setup(){
 chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}).catch(console.warn);
 chrome.contextMenus.removeAll(()=>chrome.contextMenus.create({id:'soc-process-only-selection',title:'SOC: Analiz Et',contexts:['selection']}));
 chrome.sidePanel.setPanelBehavior({openPanelOnActionClick:true}).catch(console.warn);
}
chrome.runtime.onInstalled.addListener(setup);chrome.runtime.onStartup.addListener(setup);
function openWithSelected(text,windowId){
 if(typeof text!=='string'||!text.trim()||!Number.isInteger(windowId))return Promise.reject(Error('Seçim veya pencere bulunamadı'));
 // Invoke within the original click gesture, before any await/storage operation.
 let opened;try{opened=chrome.sidePanel.open({windowId});}catch(e){opened=Promise.reject(e);}
 const record={id:crypto.randomUUID(),text:text.trim().slice(0,2048),issuedAt:Date.now()};
 writes=writes.catch(()=>{}).then(()=>chrome.storage.session.set({['socSelection:'+windowId]:record}));
 const saved=writes;
 return opened.then(()=>saved.then(()=>({ok:true,mode:'panel'})),async()=>{
  await saved;
  await chrome.tabs.create({windowId,url:chrome.runtime.getURL('panel.html')});
  return {ok:true,mode:'tab'};
 });
}
chrome.contextMenus.onClicked.addListener((info,tab)=>{if(info.menuItemId==='soc-process-only-selection')openWithSelected(info.selectionText,tab?.windowId).catch(console.warn);});
chrome.runtime.onMessage.addListener((msg,sender,reply)=>{
 if(msg?.type!=='SOC_PROCESS_SELECTED')return;
 openWithSelected(msg.text,sender.tab?.windowId).then(reply,e=>reply({ok:false,error:e.message}));return true;
});
chrome.windows.onRemoved.addListener(id=>{writes=writes.catch(()=>{}).then(()=>chrome.storage.session.remove(['socSelection:'+id,'socPanel:'+id]));writes.catch(console.warn);});
