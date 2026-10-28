// Copy-to-clipboard for IDs, URLs and keys. Pages work without it: the buttons are
// rendered hidden and only revealed when the clipboard API is available.
(function () {
  if (!navigator.clipboard || !window.isSecureContext) {
    return;
  }

  var status = document.getElementById('copy-status');
  var timer = null;

  document.querySelectorAll('button.copy[data-copy]').forEach(function (button) {
    button.hidden = false;

    button.addEventListener('click', function () {
      navigator.clipboard.writeText(button.dataset.copy).then(function () {
        button.dataset.state = 'copied';
        if (status) {
          status.textContent = 'Copied to clipboard';
        }

        clearTimeout(timer);
        timer = setTimeout(function () {
          delete button.dataset.state;
          if (status) {
            status.textContent = '';
          }
        }, 1800);
      }).catch(function () {
        // Permission denied or no focus: leave the button as it was, the text stays selectable
      });
    });
  });
})();
