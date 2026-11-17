let windowCount = 0;
let alertCount = 0;
let alertTypesSeen = new Set();
let pendingReplayResolve = null;

const ppsChart = new Chart(document.getElementById('ppsChart'), {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      data: [],
      borderColor: '#45B39D',
      borderWidth: 2,
      pointRadius: 0,
      tension: 0.2,
      fill: false
    }]
  },
  options: {
    responsive: true,
    animation: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#9AA5B8', font: { size: 10 } }, grid: { color: '#3A4457' } },
      y: { ticks: { color: '#9AA5B8', font: { size: 10 } }, grid: { color: '#3A4457' }, beginAtZero: true }
    }
  }
});

let currentScenario = null;
let captureStart = null;

// Replayed PCAPs carry a fixed fake start time, so show time into the capture, not wall-clock time
function relTime(iso) {
  const t = new Date(iso).getTime();
  if (captureStart === null) captureStart = t;
  return '+' + Math.round((t - captureStart) / 1000) + 's';
}

function setStatus(running, text) {
  document.getElementById('statusDot').className = 'status-dot ' + (running ? 'running' : 'idle');
  document.getElementById('statusText').textContent = text;
}

function renderStats(s) {
  windowCount++;
  document.getElementById('windowValue').textContent = windowCount;

  if (currentScenario) {
    const from = relTime(s.window_start);
    const to = relTime(s.window_end);
    setStatus(true, `Replaying "${currentScenario}" — window ${windowCount} — analyzing traffic from ${from} to ${to}`);
  }

  const t = relTime(s.window_start);
  ppsChart.data.labels.push(t);
  ppsChart.data.datasets[0].data.push(s.packets_per_sec);
  if (ppsChart.data.labels.length > 24) {
    ppsChart.data.labels.shift();
    ppsChart.data.datasets[0].data.shift();
  }
  ppsChart.update();
  document.getElementById('ppsValue').textContent = s.packets_per_sec.toFixed(1);

  const total = Object.values(s.protocol_counts).reduce((a, b) => a + b, 0) || 1;
  const protoList = document.getElementById('protoList');
  protoList.innerHTML = Object.entries(s.protocol_counts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => {
      const cls = ['TCP', 'UDP', 'DNS', 'ICMP', 'ARP'].includes(name) ? name.toLowerCase() : 'other';
      return `
      <div class="proto-row">
        <span class="proto-name">${name}</span>
        <span class="proto-track"><span class="proto-fill ${cls}" style="width:${(count / total * 100).toFixed(0)}%"></span></span>
        <span class="proto-count">${count}</span>
      </div>`;
    })
    .join('');

  document.getElementById('talkersBody').innerHTML = s.top_talkers
    .map(t => `<tr><td>${t.ip}</td><td>${t.packets}</td><td>${t.bytes}</td></tr>`)
    .join('');

  document.getElementById('portsBody').innerHTML = s.top_ports
    .map(p => `<tr><td>${p.port}</td><td>${p.packets}</td></tr>`)
    .join('');
}

function renderAlert(a) {
  alertCount++;
  alertTypesSeen.add(a.type);
  document.getElementById('alertValue').textContent = alertCount;

  const body = document.getElementById('alertsBody');
  const emptyRow = body.querySelector('.empty-row');
  if (emptyRow) emptyRow.remove();

  const time = relTime(a.timestamp);
  const row = document.createElement('tr');
  row.className = 'alert-row';
  row.innerHTML = `
    <td>${time}</td>
    <td class="sev-${a.severity}">${a.severity}</td>
    <td>${a.type}</td>
    <td>${a.src_ip || '\u2014'}</td>
    <td>${a.description}</td>
  `;

  const detailRow = document.createElement('tr');
  detailRow.className = 'alert-detail';
  detailRow.style.display = 'none';
  const td = document.createElement('td');
  td.colSpan = 5;
  td.innerHTML = `<pre>${JSON.stringify(a.evidence, null, 2)}</pre>`;
  detailRow.appendChild(td);

  row.addEventListener('click', () => {
    detailRow.style.display = detailRow.style.display === 'none' ? '' : 'none';
  });

  body.prepend(detailRow);
  body.prepend(row);
}

async function startReplay() {
  const scenario = document.getElementById('scenario').value;
  const speed = parseFloat(document.getElementById('speed').value);
  currentScenario = scenario;
  setStatus(true, `Starting replay of "${scenario}"...`);
  await fetch('/api/replay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario, speed })
  });
}

async function clearData() {
  await fetch('/api/data', { method: 'DELETE' });

  ppsChart.data.labels = [];
  ppsChart.data.datasets[0].data = [];
  ppsChart.update();

  document.getElementById('ppsValue').textContent = '0';
  document.getElementById('protoList').innerHTML = '';
  document.getElementById('talkersBody').innerHTML = '';
  document.getElementById('portsBody').innerHTML = '';
  document.getElementById('alertsBody').innerHTML =
    '<tr class="empty-row"><td colspan="5">No alerts yet. Run a replay to see detections here.</td></tr>';

  windowCount = 0;
  alertCount = 0;
  alertTypesSeen = new Set();
  captureStart = null;
  document.getElementById('windowValue').textContent = '0';
  document.getElementById('alertValue').textContent = '0';
  setStatus(false, 'Idle — no replay running');
}

async function loadHistory() {
  try {
    const stats = await (await fetch('/api/stats?limit=20')).json();
    stats.forEach(renderStats);

    const alerts = await (await fetch('/api/alerts?limit=20')).json();
    alerts.reverse().forEach(renderAlert);
  } catch (e) {
    console.error('failed to load history', e);
  }
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/live`);
  const status = document.getElementById('connection');

  ws.onopen = () => {
    status.textContent = 'connected';
    status.classList.add('connected');
  };
  ws.onclose = () => {
    status.textContent = 'disconnected, retrying';
    status.classList.remove('connected');
    setTimeout(connectWS, 2000);
  };
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'stats') renderStats(msg.data);
    if (msg.type === 'alert') renderAlert(msg.data);
    if (msg.type === 'replay_done' && pendingReplayResolve) {
      setStatus(false, `Finished replaying "${msg.data.scenario}" — ${windowCount} windows processed, ${alertCount} alerts raised`);
      pendingReplayResolve(msg.data.scenario);
      pendingReplayResolve = null;
    }
  };
}

function waitForReplayDone() {
  return new Promise((resolve) => { pendingReplayResolve = resolve; });
}

const SCENARIOS_FOR_EVAL = ['normal', 'port_scan', 'syn_flood', 'arp_spoof', 'dns_tunnel', 'mixed'];

async function runAllScenarios() {
  const runAllBtn = document.getElementById('runAllBtn');
  runAllBtn.disabled = true;
  const evalSection = document.getElementById('evaluation');
  const evalBody = document.getElementById('evalBody');
  evalBody.innerHTML = '';
  evalSection.hidden = false;

  for (const scenario of SCENARIOS_FOR_EVAL) {
    await clearData();
    document.getElementById('scenario').value = scenario;
    currentScenario = scenario;
    setStatus(true, `Run all: starting "${scenario}"...`);

    const done = waitForReplayDone();
    await fetch('/api/replay', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario, speed: 10.0 })
    });
    await done;
    await new Promise(r => setTimeout(r, 300)); // let the backend fully close out the previous replay task

    const typesList = [...alertTypesSeen]
      .map(t => `<span class="type-tag">${t}</span>`)
      .join('') || '\u2014';

    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${scenario}</td>
      <td>${windowCount}</td>
      <td>${alertCount}</td>
      <td>${typesList}</td>
    `;
    evalBody.appendChild(row);
  }

  runAllBtn.disabled = false;
  setStatus(false, 'Run all scenarios complete — see evaluation summary below');
}

document.getElementById('runBtn').addEventListener('click', startReplay);
document.getElementById('runAllBtn').addEventListener('click', runAllScenarios);
document.getElementById('clearBtn').addEventListener('click', clearData);

loadHistory();
connectWS();
let windowCount = 0;
let alertCount = 0;
let alertTypesSeen = new Set();
let pendingReplayResolve = null;

const ppsChart = new Chart(document.getElementById('ppsChart'), {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      data: [],
      borderColor: '#45B39D',
      borderWidth: 2,
      pointRadius: 0,
      tension: 0.2,
      fill: false
    }]
  },
  options: {
    responsive: true,
    animation: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#9AA5B8', font: { size: 10 } }, grid: { color: '#3A4457' } },
      y: { ticks: { color: '#9AA5B8', font: { size: 10 } }, grid: { color: '#3A4457' }, beginAtZero: true }
    }
  }
});

let currentScenario = null;
let captureStart = null;

// Replayed PCAPs carry a fixed fake start time, so show time into the capture, not wall-clock time
function relTime(iso) {
  const t = new Date(iso).getTime();
  if (captureStart === null) captureStart = t;
  return '+' + Math.round((t - captureStart) / 1000) + 's';
}

function setStatus(running, text) {
  document.getElementById('statusDot').className = 'status-dot ' + (running ? 'running' : 'idle');
  document.getElementById('statusText').textContent = text;
}

function renderStats(s) {
  windowCount++;
  document.getElementById('windowValue').textContent = windowCount;

  if (currentScenario) {
    const from = relTime(s.window_start);
    const to = relTime(s.window_end);
    setStatus(true, `Replaying "${currentScenario}" — window ${windowCount} — analyzing traffic from ${from} to ${to}`);
  }

  const t = relTime(s.window_start);
  ppsChart.data.labels.push(t);
  ppsChart.data.datasets[0].data.push(s.packets_per_sec);
  if (ppsChart.data.labels.length > 24) {
    ppsChart.data.labels.shift();
    ppsChart.data.datasets[0].data.shift();
  }
  ppsChart.update();
  document.getElementById('ppsValue').textContent = s.packets_per_sec.toFixed(1);

  const total = Object.values(s.protocol_counts).reduce((a, b) => a + b, 0) || 1;
  const protoList = document.getElementById('protoList');
  protoList.innerHTML = Object.entries(s.protocol_counts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => {
      const cls = ['TCP', 'UDP', 'DNS', 'ICMP', 'ARP'].includes(name) ? name.toLowerCase() : 'other';
      return `
      <div class="proto-row">
        <span class="proto-name">${name}</span>
        <span class="proto-track"><span class="proto-fill ${cls}" style="width:${(count / total * 100).toFixed(0)}%"></span></span>
        <span class="proto-count">${count}</span>
      </div>`;
    })
    .join('');

  document.getElementById('talkersBody').innerHTML = s.top_talkers
    .map(t => `<tr><td>${t.ip}</td><td>${t.packets}</td><td>${t.bytes}</td></tr>`)
    .join('');

  document.getElementById('portsBody').innerHTML = s.top_ports
    .map(p => `<tr><td>${p.port}</td><td>${p.packets}</td></tr>`)
    .join('');
}

function renderAlert(a) {
  alertCount++;
  alertTypesSeen.add(a.type);
  document.getElementById('alertValue').textContent = alertCount;

  const body = document.getElementById('alertsBody');
  const emptyRow = body.querySelector('.empty-row');
  if (emptyRow) emptyRow.remove();

  const time = relTime(a.timestamp);
  const row = document.createElement('tr');
  row.className = 'alert-row';
  row.innerHTML = `
    <td>${time}</td>
    <td class="sev-${a.severity}">${a.severity}</td>
    <td>${a.type}</td>
    <td>${a.src_ip || '\u2014'}</td>
    <td>${a.description}</td>
  `;

  const detailRow = document.createElement('tr');
  detailRow.className = 'alert-detail';
  detailRow.style.display = 'none';
  const td = document.createElement('td');
  td.colSpan = 5;
  td.innerHTML = `<pre>${JSON.stringify(a.evidence, null, 2)}</pre>`;
  detailRow.appendChild(td);

  row.addEventListener('click', () => {
    detailRow.style.display = detailRow.style.display === 'none' ? '' : 'none';
  });

  body.prepend(detailRow);
  body.prepend(row);
}

async function startReplay() {
  const scenario = document.getElementById('scenario').value;
  const speed = parseFloat(document.getElementById('speed').value);
  currentScenario = scenario;
  setStatus(true, `Starting replay of "${scenario}"...`);
  await fetch('/api/replay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario, speed })
  });
}

async function clearData() {
  await fetch('/api/data', { method: 'DELETE' });

  ppsChart.data.labels = [];
  ppsChart.data.datasets[0].data = [];
  ppsChart.update();

  document.getElementById('ppsValue').textContent = '0';
  document.getElementById('protoList').innerHTML = '';
  document.getElementById('talkersBody').innerHTML = '';
  document.getElementById('portsBody').innerHTML = '';
  document.getElementById('alertsBody').innerHTML =
    '<tr class="empty-row"><td colspan="5">No alerts yet. Run a replay to see detections here.</td></tr>';

  windowCount = 0;
  alertCount = 0;
  alertTypesSeen = new Set();
  captureStart = null;
  document.getElementById('windowValue').textContent = '0';
  document.getElementById('alertValue').textContent = '0';
  setStatus(false, 'Idle — no replay running');
}

async function loadHistory() {
  try {
    const stats = await (await fetch('/api/stats?limit=20')).json();
    stats.forEach(renderStats);

    const alerts = await (await fetch('/api/alerts?limit=20')).json();
    alerts.reverse().forEach(renderAlert);
  } catch (e) {
    console.error('failed to load history', e);
  }
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/live`);
  const status = document.getElementById('connection');

  ws.onopen = () => {
    status.textContent = 'connected';
    status.classList.add('connected');
  };
  ws.onclose = () => {
    status.textContent = 'disconnected, retrying';
    status.classList.remove('connected');
    setTimeout(connectWS, 2000);
  };
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'stats') renderStats(msg.data);
    if (msg.type === 'alert') renderAlert(msg.data);
    if (msg.type === 'replay_done' && pendingReplayResolve) {
      setStatus(false, `Finished replaying "${msg.data.scenario}" — ${windowCount} windows processed, ${alertCount} alerts raised`);
      pendingReplayResolve(msg.data.scenario);
      pendingReplayResolve = null;
    }
  };
}

function waitForReplayDone() {
  return new Promise((resolve) => { pendingReplayResolve = resolve; });
}

const SCENARIOS_FOR_EVAL = ['normal', 'port_scan', 'syn_flood', 'arp_spoof', 'dns_tunnel', 'mixed'];

async function runAllScenarios() {
  const runAllBtn = document.getElementById('runAllBtn');
  runAllBtn.disabled = true;
  const evalSection = document.getElementById('evaluation');
  const evalBody = document.getElementById('evalBody');
  evalBody.innerHTML = '';
  evalSection.hidden = false;

  for (const scenario of SCENARIOS_FOR_EVAL) {
    await clearData();
    document.getElementById('scenario').value = scenario;
    currentScenario = scenario;
    setStatus(true, `Run all: starting "${scenario}"...`);

    const done = waitForReplayDone();
    await fetch('/api/replay', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario, speed: 10.0 })
    });
    await done;
    await new Promise(r => setTimeout(r, 300)); // let the backend fully close out the previous replay task

    const typesList = [...alertTypesSeen]
      .map(t => `<span class="type-tag">${t}</span>`)
      .join('') || '\u2014';

    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${scenario}</td>
      <td>${windowCount}</td>
      <td>${alertCount}</td>
      <td>${typesList}</td>
    `;
    evalBody.appendChild(row);
  }

  runAllBtn.disabled = false;
  setStatus(false, 'Run all scenarios complete — see evaluation summary below');
}

document.getElementById('runBtn').addEventListener('click', startReplay);
document.getElementById('runAllBtn').addEventListener('click', runAllScenarios);
document.getElementById('clearBtn').addEventListener('click', clearData);

loadHistory();
connectWS();
