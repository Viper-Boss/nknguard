'use strict';
const form = document.getElementById('login-form');
const password = document.getElementById('password');
const visibility = document.getElementById('show-password');
const message = document.getElementById('login-message');
const submit = document.getElementById('login-submit');
const params = new URLSearchParams(location.search);
if (params.has('password_changed') || params.has('expired')) {
  message.classList.add('info');
  message.textContent = params.has('password_changed') ? '密码已更新，请使用新密码登录。' : '登录已过期，请重新登录。';
  history.replaceState(null, '', '/login');
}
visibility.addEventListener('click', () => {
  const show = password.type === 'password';
  password.type = show ? 'text' : 'password';
  visibility.setAttribute('aria-pressed', String(show));
  visibility.setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
  password.focus();
});
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (submit.disabled) return;
  submit.disabled = true;
  message.textContent = '';
  message.classList.remove('info');
  submit.querySelector('.submit-label').textContent = '正在登录…';
  try {
    const response = await fetch('/api/auth/login', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json','X-NKNGuard-UI':'1'}, body:JSON.stringify({username:document.getElementById('username').value.trim(),password:password.value})});
    if (!response.ok) {
      if (response.status === 429) throw new Error(`尝试次数较多，请 ${response.headers.get('Retry-After') || '60'} 秒后重试。`);
      throw new Error((await response.text()).trim() || '暂时无法登录，请稍后重试。');
    }
    password.value = '';
    location.replace('/');
  } catch (error) {
    message.textContent = error instanceof TypeError ? '连接中断，请检查后台是否正在运行。' : error.message;
    submit.disabled = false;
    submit.querySelector('.submit-label').textContent = '登录管理后台';
  }
});
