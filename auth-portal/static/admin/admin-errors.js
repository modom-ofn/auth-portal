export const toUserMessage = (err, fallback) => {
  const msg = err?.message;
  if (typeof msg === 'string' && msg.trim()) {
    return msg;
  }
  return fallback;
};

export const buildAPIError = ({ fallback, status, serverError }) => {
  const detail = typeof serverError === 'string' && serverError.trim() ? serverError.trim() : '';
  if (detail) {
    return new Error(detail);
  }
  if (typeof status === 'number' && Number.isFinite(status)) {
    return new Error(`${fallback} (${status})`);
  }
  return new Error(fallback);
};
