export const createStatusBannerController = (statusBanner) => {
  const clear = () => {
    if (!statusBanner) {
      return;
    }
    statusBanner.textContent = '';
    statusBanner.className = 'status-banner';
  };

  const show = (message, type = 'info') => {
    if (!statusBanner) {
      return;
    }
    statusBanner.textContent = message;
    statusBanner.className = `status-banner ${type} show`;
  };

  return {
    clear,
    show,
  };
};

export const createLoadedAtController = (loadedAtEl) => {
  const update = (loadedAt) => {
    if (!loadedAtEl) {
      return;
    }
    if (!loadedAt) {
      loadedAtEl.textContent = '-';
      return;
    }
    try {
      loadedAtEl.textContent = new Date(loadedAt).toLocaleString();
    } catch {
      loadedAtEl.textContent = String(loadedAt);
    }
  };

  return {
    update,
  };
};
