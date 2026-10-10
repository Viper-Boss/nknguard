'use strict';
async function dashboardFetch(input, options) {
  const response = await fetch(input, {...options, credentials:'same-origin'});
  if (response.status === 401) {
    location.replace('/login?expired=1');
    throw new Error('登录已过期');
  }
  return response;
}
