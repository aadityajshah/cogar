const log = document.getElementById('log');
const input = document.getElementById('input');
const form = document.getElementById('composer');
let myName = null;

function addLine(html) {
  const div = document.createElement('div');
  div.className = 'msg';
  div.innerHTML = html;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

function fmtTs(ts){
  try { return new Date(ts).toLocaleTimeString(); } catch { return '' }
}

const proto = location.protocol === 'https:' ? 'wss' : 'ws';
const ws = new WebSocket(proto + '://' + location.host + '/ws');

ws.onopen = () => addLine('<div class="sys">Connected. Your messages will self destruct in 72 hours. </div>');
ws.onclose = () => addLine('<div class="sys">Disconnected.</div>');

ws.onmessage = (ev) => {
  try {
    const data = JSON.parse(ev.data);
    const { type, kind, username, text, ts } = data;
    if (type === 'hello') {
      myName = data.username || null;
      return;
    }
    if (type === 'history' || type === 'event') {
      if (kind === 'system') {
        addLine(`<span class="sys">[${fmtTs(ts)}] ${text}</span>`);
      } else if (kind === 'chat') {
        const mine = myName && username === myName;
        const nameClass = mine ? 'own' : 'other';
        addLine(`<span class="name ${nameClass}">${username}</span> <span class="text">${text}</span> <span class="ts">${fmtTs(ts)}</span>`);
      }
    }
  } catch {}
};

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const v = input.value.trim();
  if (!v) return;
  ws.send(v);
  input.value = '';
});
