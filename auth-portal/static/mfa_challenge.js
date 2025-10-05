document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('mfa-challenge-form');
  const codeInput = document.getElementById('mfa-code');
  const submitBtn = document.getElementById('mfa-submit');
  const errorBox = document.getElementById('mfa-error');

  if (codeInput) {
    setTimeout(() => codeInput.focus({ preventScroll: true }), 50);
  }

  const showError = (message) => {
    if (!errorBox) return;
    errorBox.textContent = message || 'Verification failed. Please try again.';
    errorBox.style.display = 'block';
  };

  const hideError = () => {
    if (!errorBox) return;
    errorBox.textContent = '';
    errorBox.style.display = 'none';
  };

  const setLoading = (loading) => {
    if (!submitBtn) return;
    submitBtn.disabled = loading;
    submitBtn.textContent = loading ? 'Verifying...' : 'Verify and continue';
  };

  async function verify(event) {
    event.preventDefault();
    const code = codeInput?.value?.trim();
    hideError();
    if (!code) {
      showError('Enter your authenticator or recovery code.');
      codeInput?.focus();
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('/mfa/challenge/verify', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data && data.ok) {
        window.location.assign(data.redirect || '/home');
        return;
      }
      const message = (data && data.error) || 'Verification failed. Check your code and try again.';
      showError(message);
      codeInput?.focus();
      codeInput?.select();
    } catch (err) {
      console.error('mfa challenge verify failed', err);
      showError('Could not verify the code. Check your connection and try again.');
    } finally {
      setLoading(false);
    }
  }

  form?.addEventListener('submit', verify);
});
