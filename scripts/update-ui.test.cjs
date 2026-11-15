const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(require('node:path').join(__dirname,'../internal/app/dashboard/updates.js'),'utf8');
async function render(data){
 data={installing:false,...data};
 const nodes=new Map();const document={getElementById(id){if(!nodes.has(id))nodes.set(id,{textContent:'',hidden:false,disabled:false,addEventListener(){},removeAttribute(){},files:[]});return nodes.get(id)}};
 vm.runInNewContext(source,{document,dashboardFetch:async()=>({ok:true,json:async()=>data}),setTimeout(){},confirm:()=>true});
 await new Promise(setImmediate);return document.getElementById;
}
test('completed current update never asks for another refresh or reinstall',async()=>{
 const node=await render({current:'v0.2.22',arch:'arm64',supported:true,download:{state:'current',version:'v0.2.22',message:'飞牛应用中心升级完成，请刷新面板'},job:{state:'complete',message:'飞牛应用中心升级完成，请刷新面板'}});
 assert.equal(node('download-version').textContent,'当前版本 v0.2.22');assert.equal(node('apply-update').hidden,true);assert.equal(node('download-update').hidden,true);
 assert.doesNotMatch(node('download-message').textContent,/刷新|新版本/);assert.doesNotMatch(node('update-message').textContent,/刷新/);
});
test('ready package still offers install and failures remain visible',async()=>{
 let node=await render({current:'v0.2.21',supported:true,download:{state:'ready',version:'v0.2.22',message:'更新已下载并验证'}});
 assert.equal(node('apply-update').disabled,false);assert.equal(node('apply-update').hidden,false);assert.match(node('download-version').textContent,/新版本 v0.2.22/);
 node=await render({current:'v0.2.21',supported:true,download:{state:'failed'},job:{state:'failed',message:'实际运行版本仍为 0.2.19'}});
 assert.match(node('update-message').textContent,/实际运行版本/);
});

test('restart during installation shows the active task and completed job stops requesting refresh',async()=>{
 let node=await render({current:'v0.2.22',supported:true,installing:true,download:{state:'idle'},job:{state:'installing',version:'v0.2.22',message:'等待版本核验'}});
 assert.equal(node('download-state').textContent,'正在更新');assert.equal(node('download-version').textContent,'正在安装 v0.2.22');assert.equal(node('apply-update').disabled,true);
 node=await render({current:'v0.2.22',supported:true,download:{state:'complete'},job:{state:'complete',version:'v0.2.22'}});
 assert.equal(node('download-state').textContent,'更新完成');assert.equal(node('download-version').textContent,'当前版本 v0.2.22');assert.equal(node('apply-update').hidden,true);
});
