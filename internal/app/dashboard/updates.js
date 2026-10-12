(() => {
 const node=id=>document.getElementById(id);
 const message=text=>{node('update-message').textContent=text;};
 const headers={'X-NKNGuard-UI':'1'};
 let busy=false;
 async function action(route,body){
  const response=await dashboardFetch('/api/updates/'+route,{method:'POST',headers:body?{...headers,'Content-Type':'application/json'}:headers,body:body?JSON.stringify(body):undefined});
  if(!response.ok)throw new Error(await response.text());
  return response.json();
 }
 async function info(){
  const response=await dashboardFetch('/api/updates');if(!response.ok)throw new Error('无法读取更新状态');
  const data=await response.json(),download=data.download||{},state=download.state||'idle';
  node('update-version').textContent=`${data.current} · ${data.arch==='arm64'?'ARM64':data.arch==='amd64'?'x86_64':data.arch}`;
  busy=['checking','downloading','verifying','installing'].includes(state)||data.installing;
  const labels={idle:'等待检查',checking:'正在检查',current:'已是最新',downloading:'正在下载',verifying:'正在验证',ready:'已准备好',failed:'可以重试',installing:'正在更新'};
  node('download-state').textContent=labels[state]||'等待检查';
  node('download-state').className='pill '+(state==='ready'?'good':'neutral');
  node('download-version').textContent=download.version?`新版本 ${download.version}`:'更新准备';
  node('download-message').textContent=download.message||'后台下载完成后，可直接点击更新。';
  const progress=node('update-progress');progress.hidden=state!=='downloading';
  if(download.total>0)progress.value=Math.min(100,100*download.bytes/download.total);else progress.removeAttribute('value');
  if(state==='downloading'&&download.bytes)node('download-message').textContent=`已下载 ${(download.bytes/1048576).toFixed(1)} MB${download.total>0?' / '+(download.total/1048576).toFixed(1)+' MB':''}`;
  node('apply-update').disabled=!data.supported||state!=='ready'||data.installing;
  node('download-update').disabled=!data.supported||busy||state==='ready';
  node('check-update').disabled=busy;
  node('auto-download').checked=data.auto_download!==false;
  for(const id of ['update-file','choose-update','upload-update'])node(id).disabled=!data.supported||busy;
  if(!data.supported)message('当前安装方式请通过安装管理器更新。');else if(data.job)message(data.job.message);
  return data;
 }
 node('auto-download').addEventListener('change',async()=>{try{await action('preferences',{auto_download:node('auto-download').checked});}catch(error){message(error.message);await info();}});
 node('check-update').addEventListener('click',async()=>{
  node('check-update').disabled=true;message('正在检查正式发布版本…');
  try{const data=await action('check');message(data.available?`发现新版本 ${data.latest}，正在准备更新。`:`当前已是最新正式发布版本（${data.current}）。`);await info();}catch(error){message('检查失败：'+error.message);}finally{node('check-update').disabled=busy;}
 });
 node('download-update').addEventListener('click',async()=>{node('download-update').disabled=true;try{await action('download');await info();}catch(error){message('下载失败：'+error.message);node('download-update').disabled=false;}});
 node('apply-update').addEventListener('click',async()=>{node('apply-update').disabled=true;try{const data=await action('apply');busy=true;message(data.message);node('download-message').textContent='服务正在重启，请稍候…';}catch(error){message('更新失败：'+error.message);await info();}});
 node('choose-update').addEventListener('click',()=>node('update-file').click());
 node('update-file').addEventListener('change',()=>{node('update-filename').textContent=node('update-file').files[0]?.name||'尚未选择更新包';});
 node('upload-update').addEventListener('click',async()=>{
  const file=node('update-file').files[0];if(!file){message('请先选择 NAS 更新包（.zip）。');return;}if(file.size>160*1048576){message('更新包不能超过 160 MB。');return;}
  if(!confirm('验证成功后会暂时断开连接并更新 NAS 服务，原有配置和配对会保留。继续？'))return;
  node('upload-update').disabled=true;message('正在上传并验证更新包…');
  try{const response=await dashboardFetch('/api/updates/upload',{method:'POST',headers:{...headers,'Content-Type':'application/zip'},body:file});if(!response.ok)throw new Error(await response.text());const data=await response.json();busy=true;message(data.message);}catch(error){message('更新失败：'+error.message);node('upload-update').disabled=false;}
 });
 async function poll(){try{await info();}catch(error){if(busy)message('服务正在重启，请稍候…');}setTimeout(poll,busy?3000:30000);}
 poll();
})();
