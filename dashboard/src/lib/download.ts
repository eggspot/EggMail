/**
 * Hands bytes to the browser to save. The file is never opened or rendered by the page: it goes through a Blob and an anchor with the download attribute, so
 * received mail (hostile by definition) cannot run in the dashboard's origin whatever its type claims to be.
 */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = safeFileName(filename);
  a.rel = 'noopener';
  a.className = 'offscreen';
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoked after the click has been handled; the browser keeps the data it already started saving.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** A name for the saved file: no path, no characters a file system or a shell treats specially, never empty. */
export function safeFileName(name: string | null | undefined, fallback = 'download'): string {
  const leaf = (name ?? '').split(/[\\/]/).pop() ?? '';
  const cleaned = leaf.replace(/[^A-Za-z0-9._() -]/g, '_').replace(/^\.+/, '').trim().slice(0, 100);
  return cleaned || fallback;
}
