export const createHelpModalController = ({
  button,
  modal,
  closeButton,
  titleEl,
  bodyEl,
  labels,
  isConfigSection,
  getCurrentSection,
  helpContent,
  defaultHelpContent = {
    title: 'Configuration Help',
    body: '<p>No help content is available for this section yet.</p>',
  },
}) => {
  let isOpen = false;

  const getContent = (section) => helpContent[section] || defaultHelpContent;

  const close = () => {
    if (!isOpen || !modal) {
      return;
    }
    modal.hidden = true;
    isOpen = false;
    document.body.classList.remove('modal-open');
    document.removeEventListener('keydown', onKeydown);
    if (button && !button.hidden) {
      button.focus();
    }
  };

  const open = (section) => {
    if (!modal || !bodyEl || !titleEl) {
      return;
    }
    const content = getContent(section);
    titleEl.textContent = content.title || defaultHelpContent.title;
    bodyEl.innerHTML = (content.body || defaultHelpContent.body).trim();
    modal.hidden = false;
    isOpen = true;
    document.body.classList.add('modal-open');
    document.addEventListener('keydown', onKeydown);
    if (closeButton) {
      closeButton.focus();
    }
  };

  const updateButton = (section) => {
    if (!button) {
      return;
    }
    const show = isConfigSection(section);
    button.hidden = !show;
    button.disabled = !show;
    if (show) {
      const label = labels[section] || section;
      button.dataset.section = section;
      button.setAttribute('aria-label', `Show help for ${label} configuration`);
      button.title = `Show ${label} help`;
      return;
    }
    delete button.dataset.section;
    button.removeAttribute('aria-label');
    button.removeAttribute('title');
    if (isOpen) {
      close();
    }
  };

  const onKeydown = (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      close();
    }
  };

  const bind = () => {
    if (button) {
      button.addEventListener('click', () => {
        const targetSection =
          button.dataset.section || (isConfigSection(getCurrentSection()) ? getCurrentSection() : '');
        open(targetSection || getCurrentSection());
      });
    }
    if (closeButton) {
      closeButton.addEventListener('click', () => {
        close();
      });
    }
    if (modal) {
      modal.addEventListener('click', (event) => {
        const target = event.target;
        const isClose = target?.dataset?.helpClose !== undefined;
        if (target === modal || isClose) {
          close();
        }
      });
    }
  };

  return {
    bind,
    close,
    open,
    updateButton,
  };
};
