// Updating is owner-initiated. No background poll downloads release packages.
(() => {
  const node = id => document.getElementById(id);
  const message = text => { node('update-message').textContent = text; };
  async function info() {
    const response = await fetch('/api/updates');
    if (!response.ok) throw new Error('无法读取更新状态');
    const data = await response.json();
    node('update-version').textContent = `${data.current} · ${data.arch === 'arm64' ? 'ARM64' : data.arch === 'amd64' ? 'x86_64' : data.arch}`;
    node('update-file').disabled = !data.supported;
    node('upload-update').disabled = !data.supported;
    if (!data.supported) message('当前安装方式请通过安装管理器更新。');
    else if (data.job) message(data.job.message);
  }
  node('check-update').addEventListener('click', async () => {
    const button = node('check-update'); button.disabled = true; message('正在检查 GitHub 发布版本…');
    try {
      const response = await fetch('/api/updates/check', {method:'POST', headers:{'X-NKNGuard-UI':'1'}});
      if (!response.ok) throw new Error(await response.text());
      const data = await response.json();
      message(data.available ? `发现新版本 ${data.latest}，请从发布页下载对应架构的 NAS 更新包。` : `当前已是最新发布版本（${data.current}）。`);
    } catch (error) { message(`检查失败：${error.message}`); }
    finally { button.disabled = false; }
  });
  node('upload-update').addEventListener('click', async () => {
    const file = node('update-file').files[0];
    if (!file) { message('请先选择 NAS 更新包（.zip）。'); return; }
    if (file.size > 160*1024*1024) { message('更新包不能超过 160 MB。'); return; }
    if (!confirm('验证成功后会暂时断开连接并更新 NAS 服务，原有配置和配对会保留。继续？')) return;
    const button = node('upload-update'); button.disabled = true; message('正在上传并验证更新包…');
    try {
      const response = await fetch('/api/updates/upload', {method:'POST',headers:{'Content-Type':'application/zip','X-NKNGuard-UI':'1'},body:file});
      if (!response.ok) throw new Error(await response.text());
      const data = await response.json(); message(data.message);
      // Short-lived polling exists only during an explicit upgrade, in memory.
      let attempts = 0;
      const timer = setInterval(async () => {
        try { await info(); } catch (_) { message('服务正在重启，请稍候…'); }
        if (++attempts >= 24) { clearInterval(timer); button.disabled = false; }
      }, 5000);
    } catch (error) { message(`更新失败：${error.message}`); button.disabled = false; }
  });
  info().catch(error => message(error.message));
})();
