(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const DB_KEY = "catlow-auth-vault-v1";
  const enc = new TextEncoder();
  let vault = [];
  let masterKey = null;
  let salt = null;
  let cameraStream = null;
  let selectedRemoval = null;
  let toastTimer = null;
  const b64 = {
    encode: (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))),
    decode: (value) => Uint8Array.from(atob(value), c => c.charCodeAt(0))
  };
  const normalizeSecret = (s) => s.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/,"");
  function base32ToBytes(value) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "", out = [];
    for (const c of normalizeSecret(value)) {
      const n = alphabet.indexOf(c);
      if (n < 0) throw new Error("That setup key contains an invalid character.");
      bits += n.toString(2).padStart(5, "0");
    }
    for (let i=0;i+8<=bits.length;i+=8) out.push(parseInt(bits.slice(i,i+8),2));
    if (!out.length) throw new Error("Enter a valid setup key.");
    return new Uint8Array(out);
  }
  async function deriveKey(password, saltBytes) {
    const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({name:"PBKDF2",salt:saltBytes,iterations:310000,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
  }
  async function encryptVault(items, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(JSON.stringify(items)));
    return {version:1,salt:b64.encode(salt),iv:b64.encode(iv),data:b64.encode(data)};
  }
  async function persist() {
    const payload = await encryptVault(vault, masterKey);
    localStorage.setItem(DB_KEY, JSON.stringify(payload));
  }
  async function unlock(password) {
    const stored = localStorage.getItem(DB_KEY);
    if (!stored) {
      salt = crypto.getRandomValues(new Uint8Array(16));
      masterKey = await deriveKey(password,salt);
      vault = [];
      await persist();
      return;
    }
    const payload = JSON.parse(stored);
    if (payload.version !== 1) throw new Error("This vault version is not supported.");
    salt = b64.decode(payload.salt);
    masterKey = await deriveKey(password,salt);
    try {
      const clear = await crypto.subtle.decrypt({name:"AES-GCM",iv:b64.decode(payload.iv)},masterKey,b64.decode(payload.data));
      vault = JSON.parse(new TextDecoder().decode(clear));
    } catch {
      masterKey = null;
      throw new Error("That password did not unlock this vault. Please try again.");
    }
  }
  function parseOtpAuth(uri) {
    const u = new URL(uri);
    if (u.protocol !== "otpauth:" || !["totp","hotp"].includes(u.hostname.toLowerCase())) throw new Error("This QR code is not a supported authenticator setup.");
    const p = u.searchParams;
    const label = decodeURIComponentSafe(u.pathname.slice(1));
    const split = label.indexOf(":");
    const issuer = p.get("issuer") || (split >= 0 ? label.slice(0,split) : "Account");
    const account = split >= 0 ? label.slice(split+1) : label;
    const secret = p.get("secret") || "";
    base32ToBytes(secret);
    return {id:crypto.randomUUID(),issuer,account,secret:normalizeSecret(secret),digits:Number(p.get("digits")||6),period:Number(p.get("period")||30),algorithm:(p.get("algorithm")||"SHA1").toUpperCase()};
  }
  function decodeURIComponentSafe(s){try{return decodeURIComponent(s)}catch{return s}}
  async function makeCode(item) {
    const counter = Math.floor(Date.now()/1000/(item.period||30));
    const keyBytes = base32ToBytes(item.secret);
    const cryptoKey = await crypto.subtle.importKey("raw",keyBytes,{name:"HMAC",hash:item.algorithm||"SHA-1"},false,["sign"]);
    const msg = new ArrayBuffer(8), view = new DataView(msg);
    view.setUint32(4,counter);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC",cryptoKey,msg));
    const offset = mac[mac.length-1]&15;
    const binary = ((mac[offset]&127)<<24)|(mac[offset+1]<<16)|(mac[offset+2]<<8)|mac[offset+3];
    const mod = 10 ** (item.digits||6);
    return String(binary%mod).padStart(item.digits||6,"0");
  }
  function showToast(message) {
    $("toast").textContent=message;$("toast").classList.add("show");
    clearTimeout(toastTimer);toastTimer=setTimeout(()=>$("toast").classList.remove("show"),1900);
  }
  function setUnlocked(on) {
    $("gate").hidden=on;$("vault").hidden=!on;$("lock-button").hidden=!on;
    $("lock-state").classList.toggle("unlocked",on);
    $("lock-state").innerHTML=on?"<i></i> Unlocked":"<i></i> Locked";
    if(on) render();
  }
  function lock() {
    masterKey=null;vault=[];stopCamera();setUnlocked(false);
    $("master-password").value="";$("gate-title").textContent="Welcome back.";
    $("gate-copy").textContent="Enter your vault password to access your verification codes.";
    $("password-label").textContent="Vault password";$("password-hint").textContent="Your vault is encrypted on this device.";
    $("unlock-submit").textContent="Unlock vault";
  }
  function accountCard(item) {
    const card=document.createElement("article");card.className="account-card";
    const top=document.createElement("div");top.className="account-top";
    const icon=document.createElement("div");icon.className="service-icon";icon.textContent=(item.issuer||"?").trim().charAt(0).toUpperCase();
    const meta=document.createElement("div");meta.className="account-meta";
    const title=document.createElement("strong");title.textContent=item.issuer||"Account";
    const sub=document.createElement("small");sub.textContent=item.account||"Authenticator code";
    meta.append(title,sub);
    const remove=document.createElement("button");remove.className="remove-button";remove.type="button";remove.textContent="···";remove.title="Remove account";remove.setAttribute("aria-label","Remove "+(item.issuer||"account"));
    remove.addEventListener("click",()=>{selectedRemoval=item.id;$("confirm-dialog").showModal()});
    top.append(icon,meta,remove);
    const codeRow=document.createElement("div");codeRow.className="code-row";
    const code=document.createElement("div");code.className="code";code.textContent="••••••";
    const copy=document.createElement("button");copy.className="copy-button";copy.type="button";copy.textContent="Copy code";
    copy.addEventListener("click",async()=>{const value=await makeCode(item);try{await navigator.clipboard.writeText(value);copy.textContent="Copied";showToast("Code copied")}catch{showToast("Clipboard access unavailable")}setTimeout(()=>copy.textContent="Copy code",1300)});
    codeRow.append(code,copy);
    const timerRow=document.createElement("div");timerRow.className="timer-row";
    const label=document.createElement("span");label.textContent="Refreshes in "+(item.period||30)+"s";
    const progress=document.createElement("div");progress.className="progress";const bar=document.createElement("span");progress.append(bar);
    timerRow.append(label,progress);card.append(top,codeRow,timerRow);
    card.dataset.accountId=item.id;card._code=code;card._label=label;card._bar=bar;card._item=item;
    return card;
  }
  async function renderCodes() {
    if(!masterKey)return;
    const now=Math.floor(Date.now()/1000);
    for(const card of $("account-list").children) {
      const item=card._item, period=item.period||30, remaining=period-(now%period);
      card._label.textContent="Refreshes in "+remaining+"s";
      card._bar.style.width=(remaining/period*100)+"%";
      if(card.dataset.counter!==String(Math.floor(now/period))) {
        card.dataset.counter=String(Math.floor(now/period));
        try { card._code.textContent=await makeCode(item); } catch {card._code.textContent="ERROR";}
      }
    }
  }
  function render() {
    const query=$("search").value.trim().toLowerCase();
    const list=$("account-list");list.replaceChildren();
    const filtered=vault.filter(a=>(a.issuer+" "+a.account).toLowerCase().includes(query));
    filtered.sort((a,b)=>(a.issuer||"").localeCompare(b.issuer||""));
    for(const item of filtered) list.append(accountCard(item));
    $("account-count").textContent=vault.length+" ACCOUNT"+(vault.length===1?"":"S");
    $("empty-state").hidden=vault.length>0;
    list.hidden=vault.length===0;
    renderCodes();
  }
  function stopCamera(){if(cameraStream){cameraStream.getTracks().forEach(t=>t.stop());cameraStream=null}if($("camera"))$("camera").srcObject=null}
  function openAccountDialog(){ $("account-error").hidden=true;$("account-form").reset();switchMethod("manual");$("account-dialog").showModal() }
  function switchMethod(method){
    document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("active",t.dataset.method===method));
    $("manual-panel").hidden=method!=="manual";$("scan-panel").hidden=method!=="scan";
    $("save-account").hidden=method!=="manual";
    if(method!=="scan")stopCamera();
  }
  async function scanCamera(){
    const status=$("scan-status");
    if(!("BarcodeDetector" in window)){status.textContent="QR scanning is not supported by this browser. Enter the setup key instead.";return}
    try{
      const detector=new BarcodeDetector({formats:["qr_code"]});
      cameraStream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:"environment"}},audio:false});
      $("camera").srcObject=cameraStream;await $("camera").play();status.textContent="Camera active. Hold the QR code in view.";
      const scan=async()=>{
        if(!cameraStream)return;
        try{const codes=await detector.detect($("camera"));if(codes.length&&codes[0].rawValue){const item=parseOtpAuth(codes[0].rawValue);vault.push(item);await persist();stopCamera();$("account-dialog").close();render();showToast("Account added");return}}catch(e){status.textContent=e.message}
        if(cameraStream)requestAnimationFrame(scan);
      };scan();
    }catch(e){status.textContent="Could not access the camera. Check browser permissions or enter the key manually."}
  }
  async function exportBackup(){
    const blob=new Blob([JSON.stringify({format:"catlow-authenticator-backup",version:1,vault:JSON.parse(localStorage.getItem(DB_KEY))},null,2)],{type:"application/json"});
    const url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download="catlow-authenticator-backup.json";a.click();URL.revokeObjectURL(url);showToast("Encrypted backup exported");
  }
  async function importBackup(file){
    try{
      const data=JSON.parse(await file.text());
      if(data.format!=="catlow-authenticator-backup"||data.version!==1||!data.vault?.data)throw new Error("That file is not a Catlow encrypted backup.");
      const payload=data.vault, backupSalt=b64.decode(payload.salt);
      const password=prompt("Enter the password used for this backup:");
      if(password===null)return;
      const key=await deriveKey(password,backupSalt);
      let decoded;
      try{decoded=await crypto.subtle.decrypt({name:"AES-GCM",iv:b64.decode(payload.iv)},key,b64.decode(payload.data))}
      catch{throw new Error("That password did not unlock the backup.")}
      const imported=JSON.parse(new TextDecoder().decode(decoded));
      if(!Array.isArray(imported))throw new Error("Backup contents are invalid.");
      if(!confirm("Replace the current Catlow vault with "+imported.length+" imported account(s)?"))return;
      localStorage.setItem(DB_KEY,JSON.stringify(payload));masterKey=key;salt=backupSalt;vault=imported;render();showToast("Backup imported");
    }catch(e){showToast(e.message||"Could not import backup")}
  }
  $("unlock-form").addEventListener("submit",async e=>{
    e.preventDefault();const password=$("master-password").value;
    if(!localStorage.getItem(DB_KEY)&&password.length<10){$("gate-error").textContent="Please use at least 10 characters for your new vault password.";$("gate-error").hidden=false;return}
    $("unlock-submit").disabled=true;$("gate-error").hidden=true;
    try{await unlock(password);$("master-password").value="";setUnlocked(true);showToast("Vault unlocked")}
    catch(err){$("gate-error").textContent=err.message;$("gate-error").hidden=false}
    finally{$("unlock-submit").disabled=false}
  });
  $("add-button").addEventListener("click",openAccountDialog);$("empty-add").addEventListener("click",openAccountDialog);
  $("lock-button").addEventListener("click",lock);$("search").addEventListener("input",render);
  document.querySelectorAll("[data-close]").forEach(b=>b.addEventListener("click",()=>{b.closest("dialog").close();stopCamera()}));
  document.querySelectorAll(".tab").forEach(b=>b.addEventListener("click",()=>switchMethod(b.dataset.method)));
  $("start-camera").addEventListener("click",scanCamera);
  $("account-form").addEventListener("submit",async e=>{
    e.preventDefault();$("account-error").hidden=true;
    try{
      const raw=$("secret").value.trim();
      let item;
      if(raw.toLowerCase().startsWith("otpauth://")) item=parseOtpAuth(raw);
      else {base32ToBytes(raw);item={id:crypto.randomUUID(),issuer:$("issuer").value.trim(),account:$("account-name").value.trim(),secret:normalizeSecret(raw),digits:Number($("digits").value),period:Number($("period").value),algorithm:"SHA1"}}
      if(!item.issuer)item.issuer="Account";
      if(item.algorithm!=="SHA1")throw new Error("Only SHA-1 TOTP is currently supported.");
      if(!Number.isInteger(item.digits)||![6,8].includes(item.digits)||![30,60].includes(item.period))throw new Error("The setup uses unsupported code settings.");
      vault.push(item);await persist();$("account-dialog").close();render();showToast("Account added to your vault");
    }catch(err){$("account-error").textContent=err.message;$("account-error").hidden=false}
  });
  $("confirm-remove").addEventListener("click",async()=>{vault=vault.filter(a=>a.id!==selectedRemoval);await persist();$("confirm-dialog").close();render();showToast("Account removed")});
  $("export-button").addEventListener("click",exportBackup);
  $("import-button").addEventListener("click",()=>$("import-file").click());
  $("import-file").addEventListener("change",e=>{if(e.target.files[0])importBackup(e.target.files[0]);e.target.value=""});
  document.addEventListener("visibilitychange",()=>{if(document.hidden&&masterKey)lock()});
  setInterval(()=>{if(masterKey)renderCodes()},1000);
  if("serviceWorker" in navigator && location.protocol!=="file:")window.addEventListener("load",()=>navigator.serviceWorker.register("./sw.js").catch(()=>{}));
  if(localStorage.getItem(DB_KEY)){
    $("gate-title").textContent="Welcome back.";$("gate-copy").textContent="Enter your vault password to access your verification codes.";
    $("password-label").textContent="Vault password";$("password-hint").textContent="Your vault is encrypted on this device.";$("unlock-submit").textContent="Unlock vault";
  }
})();