import {pathToFileURL, fileURLToPath} from 'node:url';
import path from 'node:path';
import {createHash} from 'node:crypto';
const checkout=process.argv[2];
const target=process.argv[3];
if(!checkout || !target) throw Error('Usage: node check_atlas.mjs /path/to/pinned-archify http://127.0.0.1:PORT/index.html');
const parsed=new URL(target);
if(parsed.protocol!=='http:' || parsed.hostname!=='127.0.0.1') throw Error('Only a loopback HTTP preview is supported.');
const {ChromeVisualBrowser,findChrome}=await import(pathToFileURL(path.resolve(checkout,'archify/bin/visual-check.mjs')));
import fs from 'node:fs';
const out=path.dirname(fileURLToPath(import.meta.url))+path.sep;
const chrome=findChrome();
if(!chrome) throw Error('Chrome/Chromium/Edge is required; set ARCHIFY_CHROME if needed.');
const b=new ChromeVisualBrowser(chrome);
const errors=[],network=[],checks=[];
try {
 const s=await b.sessionPromise;
 b.cdp.subscribe(e=>{if(e.method==='Runtime.exceptionThrown')errors.push(e.params.exceptionDetails);if(e.method==='Network.requestWillBeSent')network.push(e.params.request.url);});
 await b.cdp.send('Network.enable',{},s);
 await b.cdp.send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false},s);
 const loaded=b.cdp.waitFor('Page.loadEventFired',s); await b.cdp.send('Page.navigate',{url:target},s);await loaded;
 const ev=async code=>{const r=await b.cdp.send('Runtime.evaluate',{expression:code,awaitPromise:true,returnByValue:true},s);if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
 for(const slug of ['architecture','dataflow','request-sequence','recovery-sequence','hierarchy','lifecycle']) {
  await ev(`new Promise(resolve=>{const f=document.getElementById('diagram'); f.addEventListener('load',()=>resolve(true),{once:true}); document.getElementById('tab-${slug}').click();})`);
  await ev(`new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))`);
  const value=await ev(`(()=>{const f=document.getElementById('diagram'),d=f.contentDocument;return {title:d.title,svg:!!d.querySelector('svg'),outerOverflow:document.documentElement.scrollWidth>innerWidth,innerOverflow:d.documentElement.scrollWidth>f.contentWindow.innerWidth,motion:d.documentElement.dataset.motion};})()`);
  if(!value.svg||value.outerOverflow||value.innerOverflow)throw Error(JSON.stringify(value)); checks.push({slug,...value});
 }
 await ev(`new Promise(resolve=>{const f=document.getElementById('diagram');f.addEventListener('load',()=>resolve(true),{once:true});document.getElementById('tab-architecture').click();})`);
 await ev(`document.getElementById('diagram').contentDocument.getElementById('btn-motion').click()`);
 const motion=await ev(`(()=>{const d=document.getElementById('diagram').contentDocument;return {motion:d.documentElement.dataset.motion,capable:d.documentElement.dataset.motionCapable,animations:d.getAnimations().filter(a=>a.playState==='running').map(a=>({time:a.currentTime,target:a.effect?.target?.tagName}))};})()`);
 await ev(`new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))`);
 const later=await ev(`document.getElementById('diagram').contentDocument.getAnimations().filter(a=>a.playState==='running').map(a=>a.currentTime)`);
 const frame=await b.cdp.send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false},s);
 fs.writeFileSync(out+'atlas-preview.png',Buffer.from(frame.data,'base64'));
 const result={atlas_sha256:createHash('sha256').update(fs.readFileSync(out+'index.html')).digest('hex'),viewport:{width:1440,height:1000},checks,motion,later,errors,requests:network.filter(u=>!u.startsWith('data:')),externalRequests:network.filter(u=>/^https?:/.test(u)&&new URL(u).origin!==parsed.origin)};
 fs.writeFileSync(out+'atlas-browser-check.json',JSON.stringify(result,null,2)+'\n');
 console.log(JSON.stringify(result));
 if(errors.length||result.externalRequests.length||motion.motion!=='live'||!motion.animations.some(a=>a.target==='path')||!later.some(t=>t>0))process.exitCode=1;
} finally {await b.close();}
