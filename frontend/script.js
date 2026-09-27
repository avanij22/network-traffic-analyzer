let windowCount = 0;
let alertCount = 0;

const ppsChart = new Chart(document.getElementById('ppsChart'), {
  type: 'line',
  data: {
    labels: [],
    datasets: [{
      data: [],
      borderColor: '#4A9B8E',
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
      x: { ticks: { color: '#8A8F98', font: { size: 10 } }, grid: { color: '#2A2F38' } },
      y: { ticks: { color: '#8A8F98', font: { size: 10 } }, grid: { color: '#2A2F38' }, beginAtZero: true }
    }
  }
});

function renderStats(s) {
  windowCount++;
  document.getElementById('windowValue').textContent = windowCount;

  const t = new Date(s.window_start).toLocaleTimeString();
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
  document.getElementById('alertValue').textContent = alertCount;

  const body = document.getElementById('alertsBody');
  const emptyRow = body.querySelector('.empty-row');
  if (emptyRow) emptyRow.remove();

  const time = new Date(a.timestamp).toLocaleTimeString();
  const row = document.createElement('tr');
  row.innerHTML = `
    <td>${time}</td>
    <td class="sev-${a.severity}">${a.severity}</td>
    <td>${a.type}</td>
    <td>${a.src_ip || '\u2014'}</td>
    <td>${a.description}</td>
  `;
  body.prepend(row);
}

async function startReplay() {
  const scenario = document.getElementById('scenario').value;
  await fetch('/api/replay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario, speed: 5.0 })
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
  document.getElementById('windowValue').textContent = '0';
  document.getElementById('alertValue').textContent = '0';
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
  };
}

document.getElementById('runBtn').addEventListener('click', startReplay);
document.getElementById('clearBtn').addEventListener('click', clearData);

loadHistory();
connectWS();