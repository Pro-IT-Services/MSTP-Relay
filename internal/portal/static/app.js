// Ask for confirmation on forms marked with data-confirm (e.g. delete buttons).
document.addEventListener("submit", (e) => {
  const msg = e.target.dataset && e.target.dataset.confirm;
  if (msg && !window.confirm(msg)) e.preventDefault();
});

// "Generate" buttons: fill the target password field with a random password and show it.
document.addEventListener("click", (e) => {
  const id = e.target.dataset && e.target.dataset.generate;
  if (!id) return;
  const field = document.getElementById(id);
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  field.value = Array.from(bytes, (b) => chars[b % chars.length]).join("");
  field.type = "text";
  field.select();
});
