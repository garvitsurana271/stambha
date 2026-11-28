// Word reveal, the "Will it run?" checker, the tested-machines list and the FAQ.
(function () {
  const DISCORD = 'https://discord.gg/M66z9fPJy5';

  // ---------- word reveal: words light up as the section scrolls past ----------
  const words = document.getElementById('words');
  if (words) {
    const text = words.textContent.trim().split(/\s+/);
    words.textContent = '';
    const spans = text.map(w => {
      const s = document.createElement('span');
      s.textContent = w;
      words.append(s, ' ');
      return s;
    });
    const section = words.closest('.reveal');
    const update = () => {
      const r = section.getBoundingClientRect();
      const p = Math.min(1, Math.max(0, -r.top / Math.max(1, r.height - innerHeight)));
      const lit = Math.round(p * 1.25 * spans.length);
      spans.forEach((s, i) => s.classList.toggle('on', i < lit));
    };
    addEventListener('scroll', update, { passive: true });
    update();
  }

  // ---------- checker ----------
  const GPU = {
    gtx16: 'NVIDIA GTX 16', rtx20: 'NVIDIA RTX 20', rtx30: 'NVIDIA RTX 30', rtx40: 'NVIDIA RTX 40', rtx50: 'NVIDIA RTX 50',
  };
  const form = document.getElementById('checker');
  const out = document.getElementById('verdict');
  const esc = s => s.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
  function verdict() {
    const f = new FormData(form);
    const type = f.get('type'), gpu = f.get('gpu'), mux = f.get('mux'), net = f.get('net'), ram = f.get('ram'), disk = f.get('disk');
    form.querySelector('.only-laptop').hidden = type !== 'laptop';
    if (!gpu) return;
    const notes = [];
    const add = (kind, text) => notes.push([kind, text]);
    if (GPU[gpu]) add('ok', `${GPU[gpu]}: supported, with GPU acceleration.`);
    else if (gpu === 'oldnv') add('no', 'NVIDIA cards older than the GTX 16 series aren’t supported.');
    else if (gpu === 'amd') add('warn', 'AMD Radeon: experimental. RX 6000/7000 boot macOS in the AMD & Intel build; RX 9000 is in testing. Vega and newer only.');
    else if (gpu === 'intel') add('warn', 'Intel graphics: experimental. Iris Xe, UHD and Arc reach the macOS desktop in test builds.');
    else add('ask', 'Check Task Manager → Performance → GPU to see your card.');
    if (type === 'laptop') {
      if (mux === 'yes') add('ok', 'Switch it to NVIDIA-only mode before you start Stambha.');
      else if (mux === 'no') add('warn', 'Without an NVIDIA-only mode, results vary. Ask on Discord with your model.');
      else add('ask', 'Look for a GPU mode or MUX switch in your laptop’s app: Armoury Crate, Vantage, MSI Center or Omen Hub.');
    }
    if (net === 'eth') add('ok', 'Ethernet works for the install.');
    else if (net === 'rtl') add('ok', 'Your Wi-Fi works for the install. No cable needed.');
    else add('warn', 'Your Wi-Fi chip isn’t supported yet. A common USB Ethernet adapter works for the install.');
    if (ram === 'lt8') add('no', 'macOS needs at least 8 GB of memory.');
    else if (ram === '8') add('ok', '8 GB works. 16 GB is smoother.');
    else add('ok', 'Plenty of memory.');
    if (disk === 'vmd') add('warn', 'Intel VMD or RAID needs changing in the BIOS. Ask on Discord first: done the wrong way, Windows won’t start.');
    else if (disk === 'unsure') add('ask', 'Device Manager → Storage controllers shows which one you have.');
    const blocked = notes.some(n => n[0] === 'no');
    const tweak = notes.some(n => n[0] === 'warn' || n[0] === 'ask');
    const [title, sub, cta] = blocked
      ? ['Not yet.', 'Something here isn’t supported yet. Join to hear the moment it is.', 'Get notified on Discord']
      : tweak
        ? ['Probably, with a tweak.', 'Sort out the notes below and you’re in.', 'Join the testers on Discord']
        : ['Yes. It should run.', 'Your PC has everything Stambha needs.', 'Join the testers on Discord'];
    const mark = { ok: '✓', no: '✕', warn: '!', ask: '?' };
    out.innerHTML =
      `<p class="v-title">${title}</p><p class="v-sub">${sub}</p>` +
      `<ul>${notes.map(([k, t]) => `<li class="${k}"><b aria-hidden="true">${mark[k]}</b><span>${esc(t)}</span></li>`).join('')}` +
      `<li class="ask"><b aria-hidden="true">i</b><span>You’ll also need 60 GB of empty disk space, and Secure Boot turned off.</span></li></ul>` +
      `<a class="pill pill-lg" href="${DISCORD}">${cta}</a>` +
      `<p class="fine">Stambha is experimental. Back up anything you care about first.</p>`;
  }
  if (form) { form.addEventListener('change', verdict); verdict(); }

  // ---------- tested machines ----------
  const MACHINES = [
    { name: 'ASUS TUF Gaming A16 (FA608PP)', kind: 'Laptop, AMD Ryzen 9 8940HX', gpu: 'NVIDIA RTX 5070 Laptop', gpuNote: 'NVIDIA-only (Ultimate) mode',
      net: 'Realtek RTL8852CE Wi-Fi', status: 'Installs and boots', when: 'November 2026' },
  ];
  const list = document.getElementById('compat-list');
  if (list) {
    for (const m of MACHINES) {
      const row = document.createElement('div');
      row.className = 'compat-row'; row.setAttribute('role', 'row');
      row.innerHTML =
        `<span role="cell"><strong>${esc(m.name)}</strong><small>${esc(m.kind)}</small></span>` +
        `<span role="cell">${esc(m.gpu)}<small>${esc(m.gpuNote)}</small></span>` +
        `<span role="cell">${esc(m.net)}</span>` +
        `<span role="cell"><span class="status">${esc(m.status)}</span><small>${esc(m.when)}</small></span>`;
      list.appendChild(row);
    }
  }

  // ---------- FAQ ----------
  const FAQ = [
    ['Is this a Hackintosh?', 'No. A Hackintosh runs the Intel version of macOS with patches and kexts. Stambha runs the Apple-silicon version, unmodified, by translating its Arm code to your PC’s x86 processor as it runs.'],
    ['How fast is it?', 'Stambha 0.6.0 is about 1.5x faster than Stela 0.5.0 — a comparison with the previous version, not with a Mac. It is still slower than a real Mac, since it translates macOS’s Arm code as it runs, and speed is the focus of the next release.'],
    ['Will it touch Windows?', 'The installer only uses empty (unallocated) space: it never resizes, moves or deletes a partition, checks every write, and has a Check only dry run that writes nothing. You make the empty space yourself in Windows Disk Management.'],
    ['AMD or Intel graphics?', 'Experimental, in the separate AMD & Intel build: AMD Radeon RX 6000/7000 boot macOS (RX 9000 in testing; Vega and newer only), and Intel Iris Xe, UHD and Arc reach the desktop in test builds. NVIDIA remains the supported path.'],
    ['Does it work on laptops?', 'Yes. Laptops with an NVIDIA-only (MUX) mode work best. The touchpad works and Wi-Fi works on the Realtek RTL8852CE; battery, brightness keys, lid and Bluetooth are coming next.'],
    ['Which Wi-Fi works?', 'Realtek RTL8852CE works today, for installing over Wi-Fi with no cable. Intel and other Wi-Fi chips aren’t supported yet: use Ethernet or a USB Ethernet adapter.'],
    ['How long does an install take?', 'About an hour over a decent connection. Keep the charger in and the network up.'],
    ['I used Stela. Do I start over?', 'No. Stambha uses the same USB stick format as Stela 0.5.0, so your installed macOS stays. You only update the boot program on the stick.'],
    ['Is it legal?', 'Stambha contains no Apple software and downloads macOS from Apple. You’re responsible for following Apple’s software license agreement.'],
    ['Virtual machines?', 'Not supported: Stambha needs a real NVIDIA GPU and a real NVMe or SATA disk.'],
  ];
  const faq = document.getElementById('faq-list');
  if (faq) {
    faq.innerHTML = FAQ.map(([q, a]) => `<details><summary>${esc(q)}</summary><p>${esc(a)}</p></details>`).join('');
  }

  // ---------- boot log: lines appear one by one when the panel scrolls into view ----------
  const log = document.getElementById('log');
  if (log && !matchMedia('(prefers-reduced-motion: reduce)').matches && 'IntersectionObserver' in window) {
    document.documentElement.classList.add('js-log');
    const lines = [...log.querySelectorAll('.l')];
    const io = new IntersectionObserver(([e]) => {
      if (!e.isIntersecting) return;
      io.disconnect();
      lines.forEach((l, i) => setTimeout(() => l.classList.add('on'), 250 + i * 520));
    }, { threshold: 0.4 });
    io.observe(log);
  }
})();
