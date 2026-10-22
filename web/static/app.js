// Comportements mineurs (aucune dépendance externe ; compatible CSP « script-src 'self' »).
document.addEventListener('submit', function (ev) {
  var msg = ev.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) { ev.preventDefault(); }
});
document.addEventListener('click', function (ev) {
  var t = ev.target.closest('[data-copy]');
  if (!t) return;
  var el = document.getElementById(t.getAttribute('data-copy'));
  if (el && navigator.clipboard) { navigator.clipboard.writeText(el.textContent.trim()); t.textContent = '✓'; }
});
document.addEventListener('change', function (ev) {
  var name = ev.target.getAttribute('data-select-all');
  if (!name) return;
  document.querySelectorAll('input[type=checkbox][name="' + name + '"]').forEach(function (c) { c.checked = ev.target.checked; });
});
