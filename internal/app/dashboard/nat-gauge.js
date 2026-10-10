/* Mapping-only STUN observations cannot distinguish cone filtering classes.
 * The dial shows a qualitative mapping hint, never a measured NAT1-4 score. */
(() => {
  const states = {
    open: {angle:76,label:'公网 · 无地址转换',hint:'没有检测到地址转换；防火墙仍可能限制直连。',chip:'映射条件开放',color:'#62dfb2'},
    'endpoint-independent': {angle:34,label:'映射稳定',hint:'多目标返回相同映射。锥型的具体类别尚未测定。',chip:'利于尝试直连',color:'#7ddcc5'},
    'address-dependent': {angle:-72,label:'映射随目标变化',hint:'具备对称型映射特征，直连难度较高；仍会尝试。',chip:'映射条件受限',color:'#f48b8b'},
    unknown: {angle:0,label:'尚未测定',hint:'连接后自动探测；暂无足够结果，指针保持灰色。',chip:'等待网络探测',color:'#7e91a9'}
  };
  function update(status) {
    const key = Object.hasOwn(states,status?.nat_behaviour) ? status.nat_behaviour : 'unknown';
    const value = states[key];
    const panel = document.getElementById('nat-panel');
    if (!panel) return;
    panel.dataset.mapping = key;
    document.getElementById('nat-current-text').textContent = key === 'endpoint-independent' ? '当前：映射稳定 · 以下三种锥型待区分' : key === 'address-dependent' ? '当前：映射受限 · 具有对称型映射特征' : key === 'open' ? '当前：公网 · 无地址转换' : '当前：尚未测定';
    panel.querySelectorAll('[data-nat-class]').forEach(card => {
      const active = key === 'endpoint-independent' ? card.dataset.natClass === 'cone' : key === 'address-dependent' && card.dataset.natClass === 'symmetric';
      card.classList.toggle('mapping-match', active);
      card.setAttribute('aria-label', card.querySelector('b').textContent + (active ? key === 'endpoint-independent' ? '：映射特征相符，具体过滤类别待测定' : '：映射特征相符' : '：条件参考'));
    });
    const needle = panel.querySelector('.nat-needle');
    needle.style.transform = `rotate(${value.angle}deg)`;
    needle.style.color = value.color;
    document.getElementById('nat-gauge-label').textContent = value.label;
    document.getElementById('nat-gauge-hint').textContent = value.hint;
    document.getElementById('nat-chip-text').textContent = value.chip;
    document.getElementById('nat-gauge-port').textContent = status?.wireguard?.listen_port > 0 ? `UDP ${status.wireguard.listen_port}` : '尚未监听';
    panel.querySelector('svg').setAttribute('aria-label',`NAT 映射条件：${value.label}。${value.hint}`);
  }
  window.addEventListener('nknguard-status', event => update(event.detail));
  window.addEventListener('nknguard-status-unavailable', () => update(null));
})();
