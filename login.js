// /app/assets/js/login.js
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('loginForm');
  const btn  = document.getElementById('btnLogin');
  if (!form || !btn) return;

  form.addEventListener('submit', () => {
    const btnText    = btn.querySelector('.btn-text');
    const btnLoading = btn.querySelector('.btn-loading');

    btn.disabled = true;
    if (btnText) btnText.classList.add('hidden');
    if (btnLoading) btnLoading.classList.remove('hidden');
  });
});
