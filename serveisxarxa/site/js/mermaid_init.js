(function() {
  function renderMermaid() {
    document.querySelectorAll('pre > code.language-mermaid, code.language-mermaid').forEach(function(codeBlock) {
      if (codeBlock.dataset.mermaidProcessed) return;
      var pre = codeBlock.closest('pre') || codeBlock.parentElement;
      var mermaidDiv = document.createElement('div');
      mermaidDiv.className = 'mermaid';
      mermaidDiv.textContent = codeBlock.textContent;
      pre.parentNode.replaceChild(mermaidDiv, pre);
      try { mermaid.init(undefined, mermaidDiv); } catch (e) { console.error('Mermaid render error', e); }
      mermaidDiv.dataset.mermaidProcessed = true;
    });
  }

  function start() {
    if (typeof mermaid === 'undefined') {
      // si mermaid encara no està carregat, esperar al load
      window.addEventListener('load', function() {
        if (typeof mermaid !== 'undefined') {
          mermaid.initialize({ startOnLoad: false });
          renderMermaid();
        } else {
          console.error('Mermaid no s\'ha carregat (CDN bloquejat?)');
        }
      });
    } else {
      mermaid.initialize({ startOnLoad: false });
      renderMermaid();
    }

    // Re-render quan la pàgina canvia (single-page nav)
    var mo = new MutationObserver(renderMermaid);
    mo.observe(document.body, { childList: true, subtree: true });
    window.addEventListener('hashchange', renderMermaid);
  }

  start();
})();
