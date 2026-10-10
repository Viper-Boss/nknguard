// Public receiving addresses come from the authenticated local dashboard.
(async () => {
  const list = document.getElementById('support-wallets');
  const assets = [['usdt','USDT','TRC20 · Tron'],['btc','BTC','Bitcoin'],['eth','ETH','Ethereum'],['sol','SOL','Solana']];
  try {
    const response = await dashboardFetch('/api/support');
    if (!response.ok) throw new Error('address unavailable');
    const addresses = await response.json();
    list.replaceChildren();
    for (const [key, label, network] of assets) {
      if (!addresses[key]) continue;
      const card = document.createElement('article'); card.className = 'support-wallet';
      const title = document.createElement('h3'); title.textContent = label;
      const caption = document.createElement('p'); caption.textContent = network;
      const image = document.createElement('img'); image.src = `/api/support/qr/${key}`; image.alt = `${label} 收款地址二维码`; image.loading = 'lazy';
      const address = document.createElement('code'); address.textContent = addresses[key]; address.tabIndex = 0;
      const copy = document.createElement('button'); copy.className = 'secondary-button'; copy.textContent = '复制地址';
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(addresses[key]); copy.textContent = '已复制'; }
        catch { const range = document.createRange(); range.selectNodeContents(address); const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); copy.textContent = '已选中，请复制'; }
        setTimeout(() => { copy.textContent = '复制地址'; }, 2500);
      });
      card.append(title, caption, image, address, copy); list.append(card);
    }
  } catch { list.textContent = '收款地址暂时无法读取，请刷新页面。'; }
  const dialog = document.getElementById('support-dialog');
  document.querySelectorAll('[data-support-image]').forEach(button => button.addEventListener('click', () => {
    const image = document.getElementById('support-large'); image.src = button.dataset.supportImage; image.alt = button.getAttribute('aria-label'); dialog.showModal();
  }));
  document.getElementById('support-close').addEventListener('click', () => dialog.close());
})();
