// Client-side filtering for the exported HTML report. No fetches: an exported
// file has to work from disk, offline, with no server behind it.
(function () {
  var search = document.getElementById('search');
  var nsSel = document.getElementById('nsfilter');
  var teamSel = document.getElementById('teamfilter');
  var chips = Array.prototype.slice.call(document.querySelectorAll('.chip'));

  function apply() {
    var q = search.value.toLowerCase();
    var ns = nsSel.value;
    var team = teamSel ? teamSel.value : '';
    var active = {};
    chips.forEach(function (c) { if (c.classList.contains('active')) active[c.dataset.sev] = true; });
    document.querySelectorAll('details.card').forEach(function (card) {
      if (ns && card.dataset.ns && card.dataset.ns !== ns) { card.style.display = 'none'; return; }
      if (team && card.dataset.ns && card.dataset.team !== team) { card.style.display = 'none'; return; }
      var visible = 0;
      card.querySelectorAll('li[data-sev]').forEach(function (li) {
        var show = !!active[li.dataset.sev] && (!q || li.textContent.toLowerCase().indexOf(q) !== -1);
        li.style.display = show ? '' : 'none';
        if (show) visible++;
      });
      card.style.display = visible ? '' : 'none';
    });
  }
  search.addEventListener('input', apply);
  nsSel.addEventListener('change', apply);
  if (teamSel) teamSel.addEventListener('change', apply);
  chips.forEach(function (c) {
    c.addEventListener('click', function () { c.classList.toggle('active'); apply(); });
  });
})();
