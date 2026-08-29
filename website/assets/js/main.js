/* ============================================================
   UpClaw — 共用交互脚本
   依赖：无（原生 JS）
   ============================================================ */
(function(){
  'use strict';

  /* ===== 1. 终端打字机动画（仅首页 Hero） ===== */
  (function(){
    var term = document.getElementById('heroTerm');
    if(!term) return;
    var cmd = 'upclaw "对 https://target.htb 发起授权渗透"';
    var steps = [
      ['Reason','攻击面假设 ×4'],
      ['Explore','nmap · 指纹 · POC'],
      ['Fact','flag 逐字符核对'],
      ['Report','证据链输出']
    ];
    var i = 0, done = false;
    function typeCmd(){
      if(i <= cmd.length){
        term.innerHTML = '<div><span class="prompt">$</span> <span class="cmd">' +
          cmd.slice(0, i) + '</span><span class="cursor"></span></div>';
        i++;
        setTimeout(typeCmd, 28);
      } else { showSteps(0); }
    }
    function showSteps(k){
      if(k < steps.length){
        term.insertAdjacentHTML('beforeend',
          '<div class="dim">▸ <span class="step">' + steps[k][0] + '</span> ' + steps[k][1] + '</div>');
        setTimeout(function(){ showSteps(k + 1); }, 420);
      } else if(!done){
        done = true;
        term.insertAdjacentHTML('beforeend',
          '<div class="ok">✓ 发现 3 个有效漏洞，证据已落盘</div>' +
          '<div style="margin-top:8px"><span class="prompt">$</span> <span class="cursor"></span></div>');
      }
    }
    setTimeout(typeCmd, 500);
  })();

  /* ===== 2. 全局光标跟随光源 ===== */
  (function(){
    var light = document.getElementById('cursorLight');
    if(!light) return;
    var mx = window.innerWidth / 2, my = window.innerHeight / 2, cx = mx, cy = my;
    function set(){
      light.style.setProperty('--mx', cx + 'px');
      light.style.setProperty('--my', cy + 'px');
    }
    document.addEventListener('mousemove', function(e){ mx = e.clientX; my = e.clientY; });
    document.addEventListener('touchmove', function(e){
      if(e.touches.length){ mx = e.touches[0].clientX; my = e.touches[0].clientY; }
    }, {passive:true});
    function loop(){ cx += (mx - cx) * 0.12; cy += (my - cy) * 0.12; set(); requestAnimationFrame(loop); }
    set(); loop();
  })();

  /* ===== 3. 代码块一键复制 ===== */
  document.querySelectorAll('.copy-btn').forEach(function(btn){
    btn.addEventListener('click', function(){
      var pre = btn.parentElement.querySelector('pre');
      if(!pre) return;
      var text = pre.innerText;
      var ok = function(){
        var old = btn.textContent;
        btn.textContent = '已复制';
        setTimeout(function(){ btn.textContent = old; }, 1200);
      };
      if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(text).then(ok, fallback);
      } else { fallback(); }
      function fallback(){
        var ta = document.createElement('textarea');
        ta.value = text; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); ok(); } catch(e){}
        document.body.removeChild(ta);
      }
    });
  });

  /* ===== 4. 明暗主题切换（记忆到 localStorage） ===== */
  (function(){
    var btn = document.getElementById('themeToggle');
    var KEY = 'upclaw-theme';
    var saved = null;
    try { saved = localStorage.getItem(KEY); } catch(e){}
    if(saved) apply(saved);
    if(!btn) return;
    btn.addEventListener('click', function(){
      var isLight = document.body.getAttribute('data-theme') === 'light';
      apply(isLight ? 'dark' : 'light');
      try { localStorage.setItem(KEY, isLight ? 'dark' : 'light'); } catch(e){}
    });
    function apply(t){
      document.body.setAttribute('data-theme', t);
      if(btn) btn.textContent = (t === 'light') ? '☀️' : '🌙';
    }
  })();

  /* ===== 5. 滚动揭示 ===== */
  var io = new IntersectionObserver(function(es){
    es.forEach(function(e){
      if(e.isIntersecting){ e.target.classList.add('show'); io.unobserve(e.target); }
    });
  }, {threshold:.12});
  document.querySelectorAll('.reveal').forEach(function(el){ io.observe(el); });

  /* ===== 6. 数字递增 ===== */
  var cio = new IntersectionObserver(function(es){
    es.forEach(function(e){
      if(!e.isIntersecting) return;
      var el = e.target;
      var target = parseInt(el.getAttribute('data-count'), 10);
      var suf = el.getAttribute('data-suffix') || '';
      var pre = el.getAttribute('data-prefix') || '';
      if(isNaN(target)) return;
      var cur = 0, step = Math.max(1, Math.floor(target / 30));
      var t = setInterval(function(){
        cur += step;
        if(cur >= target){ cur = target; clearInterval(t); }
        el.textContent = pre + cur + suf;
      }, 30);
      cio.unobserve(el);
    });
  }, {threshold:.5});
  document.querySelectorAll('[data-count]').forEach(function(el){ cio.observe(el); });

  /* ===== 7. 定价：月付 / 年付切换 ===== */
  (function(){
    var sw = document.getElementById('billingSwitch');
    if(!sw) return;
    var prices = document.querySelectorAll('[data-monthly]');
    function setMode(mode){
      prices.forEach(function(el){
        var v = (mode === 'yearly') ? el.getAttribute('data-yearly') : el.getAttribute('data-monthly');
        el.textContent = v;
      });
      document.querySelectorAll('.per-unit').forEach(function(el){
        el.textContent = (mode === 'yearly') ? '/ 月（按年付）' : '/ 月';
      });
      document.querySelectorAll('.price-note').forEach(function(el){
        var n = (mode === 'yearly') ? el.getAttribute('data-note-yearly') : el.getAttribute('data-note-monthly');
        if(n) el.textContent = n;
      });
      sw.querySelectorAll('button').forEach(function(b){
        b.classList.toggle('on', b.getAttribute('data-mode') === mode);
      });
    }
    sw.addEventListener('click', function(e){
      var b = e.target.closest('button[data-mode]');
      if(b) setMode(b.getAttribute('data-mode'));
    });
  })();

  /* ===== 8. 当前页导航高亮 ===== */
  (function(){
    var path = location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.navlinks a').forEach(function(a){
      var href = a.getAttribute('href');
      if(href === path || (path === '' && href === 'index.html')) a.classList.add('active');
    });
  })();

})();
