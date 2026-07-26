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

  var apiBase = document.body.getAttribute('data-api') || '/api';
  var trendCard = document.getElementById('trendcard');
  if (trendCard) {
    fetch(apiBase + '/history').then(function (r) { return r.json(); }).then(function (h) {
      var e = h.entries || [];
      if (e.length < 2) return;
      trendCard.hidden = false;
      var svg = document.getElementById('trend');
      var max = 1;
      e.forEach(function (x) { max = Math.max(max, x.summary.totalFindings); });
      var draw = function (get, color) {
        var pts = e.map(function (x, i) {
          var px = (i * 600 / (e.length - 1)).toFixed(1);
          var py = (125 - get(x.summary) / max * 118).toFixed(1);
          return px + ',' + py;
        }).join(' ');
        var p = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
        p.setAttribute('points', pts);
        p.setAttribute('fill', 'none');
        p.setAttribute('stroke', color);
        p.setAttribute('stroke-width', '2');
        svg.appendChild(p);
      };
      draw(function (s) { return s.totalFindings; }, '#888');
      draw(function (s) { return s.warnings; }, '#c79100');
      draw(function (s) { return s.critical; }, '#c62828');
    }).catch(function () {});
    fetch(apiBase + '/history/diff').then(function (r) { return r.json(); }).then(function (d) {
      var added = (d.new || []).length, resolved = (d.resolved || []).length;
      if (added || resolved) {
        document.getElementById('diffline').textContent =
          'since previous run: ' + added + ' new, ' + resolved + ' resolved';
      }
    }).catch(function () {});
  }

  var auto = document.getElementById('autorefresh');
  if (auto) {
    var timer = null;
    var setTimer = function (on) {
      if (timer) { clearInterval(timer); timer = null; }
      if (on) { timer = setInterval(function () { window.location = window.location.pathname + '?refresh=true'; }, 60000); }
    };
    auto.checked = localStorage.getItem('cg-autorefresh') === '1';
    setTimer(auto.checked);
    auto.addEventListener('change', function () {
      localStorage.setItem('cg-autorefresh', auto.checked ? '1' : '0');
      setTimer(auto.checked);
    });
  }
})();
