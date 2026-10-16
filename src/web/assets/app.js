/* Let me see see 前端：加载即扫描，真实数据来自 /api/scan。
   离线报告模式：导出的单文件 HTML 内嵌 window.__LMSS_REPORT__，
   无服务运行也能完整交互（时间线/搜索/过滤/规则/进程树/导出 CSV·JSON） */
const OFFLINE_REPORT = typeof window.__LMSS_REPORT__ !== 'undefined';
if (OFFLINE_REPORT) document.body.classList.add('offline');
const TOKEN = OFFLINE_REPORT ? '' : (new URLSearchParams(location.search).get('t') || '');
let REPORT = {events: [], modules: [], rules: []};
const state = {q:'', mod:'all', sortKey:'time', sortDir:'desc', from:'', to:'', view:'raw', tool:null}; // view=有原表的模块默认'raw'；tool=工具视图
const sevOrder = {red:3, yellow:2, gray:1, none:0};
// 模块大类：侧边栏按此归并（数据保留原始 module 字段）
const GROUPS = {
  '程序运行记录（UserAssist）': '程序运行记录',
  '程序启动缓存（MUICache）': '程序运行记录',
  '程序执行缓存（ShimCache）': '程序运行记录',
  '首次执行记录（AmCache）': '程序运行记录',
  '后台活动监控（BAM/DAM）': '程序运行记录',
  '程序预读取（Prefetch）': '程序运行记录',
  '最近文档（RecentDocs）': '文件访问记录',
  '文件对话框记录（OpenSave）': '文件访问记录',
  '文件夹浏览记录（ShellBags）': '文件访问记录',
  '事件日志（系统/应用/网络）': '系统与软件事件',
  '软件安装': '系统与软件事件',
  '崩溃记录（WER/Minidump）': '系统与软件事件',
  '安全日志（Security）': '安全日志（Security）',
  'PowerShell 日志（4104）': 'PowerShell 日志（4104）',
  '自启动项': '入侵痕迹排查',
  '计划任务': '入侵痕迹排查',
  '系统服务': '入侵痕迹排查',
  'WMI事件订阅': '入侵痕迹排查',
  '账号安全': '入侵痕迹排查',
  'USB 设备历史': '入侵痕迹排查',
  '高级持久化检查': '入侵痕迹排查',
  'Defender 防护与检出': '入侵痕迹排查',
  'RDP 客户端历史': '入侵痕迹排查',
  '落盘文件扫描': '入侵痕迹排查',
  '回收站': '文件访问记录',
  '进程现场': '现场快照（进程/网络）',
  '网络现场（连接/DNS/hosts）': '现场快照（进程/网络）',
  'Sysmon 日志': 'Sysmon 日志',
};
const GROUP_ORDER = ['入侵痕迹排查', '现场快照（进程/网络）', '程序运行记录', '文件访问记录', '系统与软件事件', '安全日志（Security）', 'PowerShell 日志（4104）', 'Sysmon 日志'];
const groupOf = m => {
  // 兼容两种输入：模块摘要对象（用后端 group 字段）/ 模块名字符串（查映射表）
  if (m && typeof m === 'object') {
    return m.group || GROUPS[m.module] || m.module;
  }
  return GROUPS[m] || m;
};
const sevLabel = {red:'高危', yellow:'关注', gray:'信息'};

async function scan(full, forcedGroup){
  // 离线报告：数据已内嵌，直接渲染；依赖服务的功能由 .offline CSS 隐藏
  if (OFFLINE_REPORT) {
    REPORT = window.__LMSS_REPORT__;
    refreshMeta(REPORT.events.length, 0);
    initModuleFilter(); render(); renderModules(); renderRules(); renderTree(); renderModuleLog();
    document.getElementById('permBanner').style.display = (REPORT.elevated === false) ? '' : 'none';
    return;
  }
  // 分组重扫：选中某模块/大类时只重扫该分组并与缓存合并（秒级）；选"全部模块"
  // 或点"全量重扫"时全量。forcedGroup：进程树刷新等场景指定分组，完成后回到发起页
  const group = forcedGroup || (full || state.mod === 'all' ? null : (groupOf(state.mod) || null));
  const url = group
    ? `/api/scan?group=${encodeURIComponent(group)}&t=${encodeURIComponent(TOKEN)}`
    : `/api/scan?t=${encodeURIComponent(TOKEN)}`;
  document.getElementById('meta').textContent = group ? `正在扫描（${group}）…` : '正在扫描（全量）…';
  try{
    const r = await fetch(url, {method:'POST'});
    if(!r.ok) throw new Error('HTTP ' + r.status);
    REPORT = await r.json();
    EV_TIMES = null; // 扫描结果已变，±10s 关联的时间缓存重建
    const total = REPORT.events.length;
    const ms = REPORT.modules.reduce((s,m)=>s+m.duration_ms,0);
    refreshMeta(total, ms);
    initModuleFilter(); render(); renderModules(); renderRules();
    renderTree(); renderModuleLog();
    document.getElementById('permBanner').style.display = (REPORT.elevated === false) ? '' : 'none';
    if(forcedGroup === TREE_GROUP) showTreePage();
  }catch(e){
    document.getElementById('meta').textContent = '扫描失败：' + e.message + '（请从控制台输出的 URL 进入）';
  }
}

// "数据截至"按当前选中模块显示：分组重扫后各模块新鲜度不同，全局单一时间戳会误导
function refreshMeta(total, ms){
  const mods = REPORT.modules.filter(m =>
    state.mod === 'all' || m.module === state.mod || groupOf(m) === state.mod);
  const ts = mods.map(m => m.scanned_at).filter(Boolean).sort();
  const asOf = ts.length ? ts[ts.length-1] : '';
  const host = REPORT.sysinfo?.hostname || '';
  document.getElementById('meta').innerHTML =
    `${OFFLINE_REPORT ? '📎 离线报告 · ' : ''}扫描完成 · ${total} 条记录${OFFLINE_REPORT ? '' : ' · ' + ms + 'ms'}` +
    (asOf ? ` · 当前视图数据截至 ${asOf}` : '') +
    (host ? ` · ${host}` : '');
}

function fmtLocal(d){
  const p = n => String(n).padStart(2,'0');
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds())+'.000';
}
function rangeBounds(){
  return [state.from, state.to];
}
function normTime(v, isTo){
  v = v.trim();
  if (!v) return '';
  let m = v.match(/^(\d{4}-\d{2}-\d{2})( (\d{2}):(\d{2})(?::(\d{2}))?)?$/);
  if (!m) return null;
  const d = m[1];
  if (!m[2]) return isTo ? d + ' 23:59:59.999' : d + ' 00:00:00.000';
  const hh = m[3], mm = m[4];
  const ss = m[5] || (isTo ? '59' : '00');
  const ms = isTo ? '999' : '000';
  return `${d} ${hh}:${mm}:${ss}.${ms}`;
}

/* ---- 时间戳解析与 ±N 秒关联（demo：事件上下文） ---- */
function parseTs(t){
  const m = String(t).match(/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})$/);
  if(!m) return null;
  return new Date(+m[1], +m[2]-1, +m[3], +m[4], +m[5], +m[6], +m[7]).getTime();
}
let EV_TIMES = null; // 扫描结果变化时置空重建
function ensureTimes(){
  if(EV_TIMES && EV_TIMES.len === REPORT.events.length) return;
  EV_TIMES = {len: REPORT.events.length, ms: REPORT.events.map(e=>parseTs(e.time))};
}
/** 与目标事件时间相差 ≤secs 的其他事件（按间隔升序，最多 limit 条） */
function nearby(ev, secs, limit){
  ensureTimes();
  const t = parseTs(ev.time);
  if(t == null) return [];
  const out = [];
  for(let i=0;i<REPORT.events.length;i++){
    const ms = EV_TIMES.ms[i];
    if(ms == null) continue;
    const d = Math.abs(ms - t);
    if(d > 0 && d <= secs*1000) out.push({d, e: REPORT.events[i]});
  }
  out.sort((a,b)=>a.d-b.d);
  return out.slice(0, limit||30);
}

function filtered(){
  const [rangeMin, rangeMax] = rangeBounds();
  const out = REPORT.events.filter(r=>{
    if(state.mod!=='all' && r.module!==state.mod && groupOf(r.module)!==state.mod) return false;
    const rt = r.time;
    const noTime = !/^\d/.test(rt);
    // 无时间戳的行不受时间范围过滤（否则按时间段排查时 R-009 证据缺失提示恰好在
    // 最需要看到的时候消失）；仍受模块与关键字过滤
    if(!noTime){
      if(rangeMin && rt < rangeMin) return false;
      if(rangeMax && rt > rangeMax) return false;
    }
    if(state.q){
      const q = state.q.toLowerCase();
      const hay = (r.desc+' '+r.info+' '+r.module+' '+r.type).toLowerCase();
      if(!hay.includes(q)) return false;
    }
    return true;
  });
  const k = state.sortKey, d = state.sortDir==='asc'?1:-1;
  const noTime = t => !/^\d/.test(t);
  out.sort((a,b)=>{
    // 无时间戳的行永远沉底，不参与升降序
    const an = noTime(a.time), bn = noTime(b.time);
    if(an && bn) return 0;
    if(an) return 1;
    if(bn) return -1;
    let va=a[k], vb=b[k];
    if(k==='sev'){va=sevOrder[a.sev];vb=sevOrder[b.sev]}
    return va<vb?-1*d:va>vb?1*d:0;
  });
  return out;
}

function sevChip(sev){
  return sev && sev!=='none' ? `<span class="chip ${sev}">${sevLabel[sev]||sev}</span>` : '';
}

// 模块 → Windows 原生管理工具映射（点「打开系统工具」唤起，继承提权）
const NATIVE_TOOLS = {
  '自启动项': 'regedit',                 // regedit 定位到 HKLM Run 键
  '计划任务': 'taskschd',                // 任务计划程序
  '系统服务': 'services',                // 服务管理器
  '账号安全': 'lusrmgr',                 // 本地用户和组
  '安全日志（Security）': 'eventvwr',
  '事件日志（系统/应用/网络）': 'eventvwr',
  'PowerShell 日志（4104）': 'eventvwr',
};
document.getElementById('btnNative').addEventListener('click', async ()=>{
  const tool = NATIVE_TOOLS[state.mod];
  if (!tool) return;
  const r = await fetch(`/api/open?tool=${tool}&t=${encodeURIComponent(TOKEN)}`)
    .then(x=>x.json()).catch(()=>null);
  if (!r || !r.ok) alert('唤起系统工具失败（tool=' + tool + '）');
});

function render(){
  // 工具（注册表浏览器）打开时只显示工具视图
  const tool = state.tool;
  // 模块专用原表视图：选中的模块带有结构化原表时默认展示（可切回时间线）
  const tbl = (REPORT.tables || []).find(t => t.module === state.mod);
  const showRaw = !tool && !!tbl && state.view === 'raw';
  const showChips = !tool && !!tbl; // 有原表的模块始终显示切换按钮
  document.getElementById('regView').style.display = tool === 'reg' ? '' : 'none';
  document.getElementById('viewChips').style.display = showChips ? '' : 'none';
  document.getElementById('rawView').style.display = showRaw ? '' : 'none';
  document.getElementById('timelineWrap').style.display = showRaw || tool ? 'none' : '';
  document.getElementById('countInfo').style.display = showRaw || tool ? 'none' : '';
  document.getElementById('mainToolbar').style.display = tool ? 'none' : '';
  document.getElementById('btnNative').style.display =
    (!tool && NATIVE_TOOLS[state.mod]) ? '' : 'none';
  document.getElementById('chipRaw').classList.toggle('active', showRaw);
  document.getElementById('chipTimeline').classList.toggle('active', !showRaw);
  if (tool) return;
  if (showRaw){
    const t = document.getElementById('rawTable');
    // 原表应用与时间线一致的过滤（搜索关键字 + 时间范围）：
    // 行内任意列匹配关键字；时间取该行第一个"YYYY-MM-DD …"样式的列
    const [rangeMin, rangeMax] = rangeBounds();
    const q = state.q.trim().toLowerCase();
    const timeOf = row => row.find(c => /^\d{4}-\d{2}-\d{2}/.test(c)) || '';
    const keep = row => {
      const hay = row.join(' ').toLowerCase();
      if (q && !hay.includes(q)) return false;
      const rt = timeOf(row);
      // 无时间列同样放行（与时间线一致：不因时间范围而隐藏无时间戳行）
      if(/^\d/.test(rt)){
        if (rangeMin && rt && rt < rangeMin) return false;
        if (rangeMax && rt && rt > rangeMax) return false;
      }
      return true;
    };
    const rowsIdx = tbl.table.rows.map((row, i) => ({row, i})).filter(x => keep(x.row));
    t.querySelector('thead').innerHTML = `<tr>${tbl.table.columns.map(c=>`<th>${esc(c)}</th>`).join('')}</tr>`;
    t.querySelector('tbody').innerHTML = rowsIdx.map(({row, i})=>{
      const ref = (tbl.table.refs || [])[i];
      return `<tr>${row.map((cell, ci)=>
        (ci === 0 && ref && !OFFLINE_REPORT)
          ? `<td class="linkcell" data-ref="${esc(ref)}" title="${esc(cell)}">🔍 ${esc(cell) || '—'}</td>`
          : `<td title="${esc(cell)}">${esc(cell) || '—'}</td>`
      ).join('')}</tr>`;
    }).join('') || (tbl.table.rows.length === 0
      ? '<tr><td colspan="99" style="color:#5f6368">该模块原表无内容（数据见时间线 / 模块日志）</td></tr>'
      : '<tr><td colspan="99" style="color:#5f6368">（当前搜索/时间条件下无匹配行——清除时间范围或搜索词可见全部）</td></tr>');
    // 带引用的行（计划任务完整 XML 等）→ 点击下方面板查看详情
    document.getElementById('rawDetail').style.display = 'none';
    t.querySelectorAll('.linkcell').forEach(td=>{
      td.addEventListener('click', async ()=>{
        const ref = td.dataset.ref;
        const r = await fetch(`/api/taskxml?ref=${encodeURIComponent(ref)}&t=${encodeURIComponent(TOKEN)}`)
          .then(x=>x.json()).catch(()=>null);
        const d = document.getElementById('rawDetail');
        d.style.display = '';
        d.textContent = (r && r.xml) ? r.xml : '⚠ ' + ((r && r.error) || '读取失败');
        d.scrollIntoView({behavior:'smooth', block:'nearest'});
      });
    });
    document.getElementById('rawCount').textContent =
      `${state.mod}：显示 ${rowsIdx.length} / 共 ${tbl.table.rows.length} 条（与时间线同规则过滤：搜索 + 时间范围）`;
    return;
  }
  const list = filtered();
  document.getElementById('tbody').innerHTML = list.map((r,i)=>`
    <tr class="row-normal ${r.sev && r.sev!=='none' ? 'sev-'+r.sev : ''}" data-i="${i}" data-time="${esc(r.time)}" data-desc="${esc(r.desc)}" data-info="${esc(r.info)}" title="点击展开完整内容与 ±10 秒关联事件">
      <td class="time mono">${esc(r.time)}</td><td>${r.type}</td>
      <td class="mono" title="${esc(r.desc)}">${esc(r.desc)}</td>
      <td class="info" title="${esc(r.info)}">${esc(r.info)}</td>
      <td>${r.module}</td>
      <td>${sevChip(r.sev)}${(r.tags||[]).map(t=>`<span class="tag">${esc(t.text)}</span>`).join('')}</td>
    </tr>`).join('');
  // 点击行 → 展开完整描述/附加信息 + ±10 秒关联事件（攻击链上下文，demo）
  document.querySelectorAll('#tbody tr.row-normal').forEach(tr=>{
    tr.addEventListener('click', ()=>{
      const next = tr.nextElementSibling;
      if (next && next.classList.contains('row-detail')) { next.remove(); return; }
      document.querySelectorAll('#tbody tr.row-detail').forEach(d=>d.remove());
      const r = list[+tr.dataset.i];
      const near = r ? nearby(r, 10, 30) : [];
      const ctx = near.length
        ? `<div class="ctx-title">🕐 ±10 秒关联事件（${near.length} 条${near.length>=30?'，取最近 30 条':''}）</div>
<div class="ctx-list">${near.map(x=>`<div class="ctx-line"><span class="mono ctx-t">${esc(x.e.time.slice(11))}</span> <span class="ctx-type">${esc(x.e.type)}</span> <span title="${esc(x.e.desc)}">${esc((x.e.desc||'').slice(0,80))}</span></div>`).join('')}</div>`
        : `<div class="ctx-title dim">（±10 秒内无其他事件）</div>`;
      const detail = document.createElement('tr');
      detail.className = 'row-detail';
      detail.innerHTML = `<td colspan="6"><b>${esc(tr.dataset.desc)}</b>
${esc(tr.dataset.info)}
${ctx}</td>`;
      tr.after(detail);
    });
  });
  document.getElementById('countInfo').textContent =
    `显示 ${list.length} / ${REPORT.events.length} 条记录`;
}

function renderModules(){
  // 左侧垂直模块列表：全部 + 大类（可折叠）+ 大类下的具体模块（两级，点击过滤/进入模块视图）
  const box = document.getElementById('moduleSidebar');
  const total = REPORT.events.length;
  const byGroup = {};
  for(const m of REPORT.modules){
    if(m.hidden) continue; // 隐藏模块（进程现场）：展示由进程树页承接，不进侧边栏与计数
    const g = groupOf(m);
    byGroup[g] = byGroup[g] || {count:0, ok:false, logs:[], mods:[]};
    byGroup[g].count += m.count;
    byGroup[g].ok = byGroup[g].ok || m.status === 'ok';
    byGroup[g].logs.push('[' + m.module + '] ' + (m.logs||[]).join(' | '));
    byGroup[g].mods.push(m);
  }
  const items = [{key:'all', name:'全部模块', status:'ok', count: total}]
    .concat(GROUP_ORDER.filter(g=>byGroup[g]).map(g=>({key:g, name:g, status: byGroup[g].ok?'ok':'warn', count: byGroup[g].count, mods: byGroup[g].mods})));
  // 折叠状态：localStorage 记忆；选中模块所在的组强制展开（防"选了看不见"）
  let collapsed = new Set();
  try { collapsed = new Set(JSON.parse(localStorage.getItem('lmss-collapsed-groups')||'[]')); } catch(e){}
  box.innerHTML = items.map(it=>{
    // 大类下的具体模块（缩进二级；带原表的模块点击进入原表视图）
    const subs = (it.mods || []).map(m=>`
      <div class="mod-item mod-sub ${state.mod===m.module && state.tool!=='reg' ?'active':''}" data-mod="${esc(m.module)}" title="${esc(m.module)}：${m.count} 条（${m.status==='ok'?'正常':m.status==='warn'?'注意':'异常'}）">
        <span class="dot ${m.status}"></span>
        <span class="m-name">${esc(m.module)}</span>
        <span class="m-count">${m.count}</span>
      </div>`).join('');
    // 现场快照组：进程树入口（取代已隐藏的进程现场模块，显示当前进程数）
    const treeEntry = it.key === '现场快照（进程/网络）' ? `
      <div class="mod-item mod-sub mod-tree-entry" id="treeEntry" title="当前存活进程的父子树（扫描时刻快照）">
        <span class="dot ok" style="background:#1a73e8"></span>
        <span class="m-name">🌲 进程树</span>
        <span class="m-count">${(REPORT.proc_tree && REPORT.proc_tree.nodes ? REPORT.proc_tree.nodes.length : '—')} 进程</span>
      </div>` : '';
    if (!it.mods) {
      return `
    <div class="mod-item mod-group ${state.mod===it.key && state.tool!=='reg' ?'active':''}" data-mod="${esc(it.key)}" title="${esc(it.name)}">
      <span style="width:14px;flex-shrink:0"></span>
      <span class="dot ${it.status}"></span>
      <span class="m-name">${esc(it.name)}</span>
      <span class="m-count">${it.count}</span>
    </div>`;
    }
    const activeInside = it.mods.some(m=>m.module===state.mod);
    const isCollapsed = collapsed.has(it.key) && !activeInside;
    return `
    <div class="mod-item mod-group ${state.mod===it.key && state.tool!=='reg' ?'active':''}" data-mod="${esc(it.key)}" title="${esc(it.name)}：点击展开/收起">
      <span class="chev${isCollapsed?' collapsed':''}">${isCollapsed?'▸':'▾'}</span>
      <span class="dot ${it.status}"></span>
      <span class="m-name">${esc(it.name)}</span>
      <span class="m-count">${it.count}</span>
    </div><div class="mod-subs${isCollapsed?' collapsed':''}">${treeEntry}${subs}</div>`;
  }).join('');
  box.querySelectorAll('.mod-item[data-mod]').forEach(el=>{
    el.addEventListener('click', ()=>{
      hideTreeMarks();
      // 组行（带折叠箭头的）：整行点击只切换展开/收起，不做选中——
      // 选中+切换并存会在单模块大类上造成"点了没反应"的歧义
      if (el.querySelector('.chev')) {
        let s = new Set();
        try { s = new Set(JSON.parse(localStorage.getItem('lmss-collapsed-groups')||'[]')); } catch(err){}
        if (s.has(el.dataset.mod)) s.delete(el.dataset.mod); else s.add(el.dataset.mod);
        try { localStorage.setItem('lmss-collapsed-groups', JSON.stringify([...s])); } catch(err){}
        renderModules();
        return;
      }
      state.mod = el.dataset.mod;
      state.view = 'raw'; // 有原表的模块默认进原表视图；无原表自动落回时间线
      state.tool = null;
      renderModules(); render(); renderModuleLog();
      refreshMeta(REPORT.events.length, 0); // 切模块时刷新"当前视图数据截至"
    });
  });
  // 进程树入口：切换到进程树页（顶部页签已移除，入口统一走侧边栏）
  const treeBtn = document.getElementById('treeEntry');
  if(treeBtn){
    treeBtn.addEventListener('click', ()=>{
      showTreePage();
      renderTree();
    });
  }
  // 工具区：注册表浏览器（非扫描模块，按需交互；离线报告不显示）
  if (OFFLINE_REPORT) return;
  const tools = document.createElement('div');
  tools.className = 'mod-item' + (state.tool === 'reg' ? ' active' : '');
  tools.id = 'toolReg';
  tools.title = '浏览任意注册表键（regedit 前端化）';
  tools.innerHTML = `<span class="dot ok" style="background:#1a73e8"></span>
    <span class="m-name">🗂 注册表浏览器</span>`;
  box.appendChild(tools);
  tools.addEventListener('click', ()=>{
    state.tool = state.tool === 'reg' ? null : 'reg'; // 再点一次收起
    if (state.tool === 'reg'){ if (REG_PATH) regBrowse(REG_PATH); else regHome(); }
    renderModules(); render();
  });
}

function renderModuleLog(){
  const log = document.getElementById('moduleLog');
  if(state.mod === 'all'){
    log.textContent = '选择一个模块查看日志';
    return;
  }
  const lines = [];
  for(const m of REPORT.modules){
    if(m.module === state.mod){
      lines.push(...(m.logs||[]));
    } else if(groupOf(m) === state.mod){
      lines.push('[' + m.module + '] ' + (m.logs||[]).join(' | '));
    }
  }
  log.textContent = lines.length ? lines.join('\n') : '（无日志）';
}

function renderRules(){
  const rules = REPORT.rules || [];
  document.getElementById('rulesBody').innerHTML = rules.map(r=>`
    <tr><td class="mono">${esc(r.id)}</td>
      <td>${sevChip(r.sev)}</td>
      <td><b>${esc(r.name)}</b></td>
      <td>${esc(r.detail)}</td>
      <td><b>${r.hits}</b></td></tr>`).join('');
  const total = rules.reduce((s,r)=>s+r.hits,0);
  const red = rules.filter(r=>r.sev==='red').reduce((s,r)=>s+r.hits,0);
  document.getElementById('rulesCount').textContent =
    `共 ${rules.length} 条规则 · 总命中 ${total}（红 ${red}）`;
}

function initModuleFilter(){
  // 侧边栏承担模块过滤；当前选择（大类或具体模块）在新结果中不存在才复位
  if(state.mod !== 'all'){
    const still = REPORT.modules.some(m => m.module === state.mod || groupOf(m) === state.mod);
    if(!still){ state.mod = 'all'; }
  }
}

// HTML 转义：& < 之外必须转义引号——desc/info/注册表键名等攻击者可控数据
// 会进入 title="…"/data-xxx="…" 属性上下文，不转义引号即可属性逃逸注入事件处理器
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}

/* ---- 事件绑定 ---- */
document.getElementById('q').addEventListener('input', e=>{state.q=e.target.value;render()});
// 重新扫描：只重扫当前选中分组（选中"全部模块"时为全量）；全量重扫：一律全量
document.getElementById('btnRescan').addEventListener('click', ()=>scan(false));
document.getElementById('btnRescanFull').addEventListener('click', ()=>scan(true));
// ---- 时间筛选：下拉=快捷填充；输入框=直接生效 ----
const rangeSel = document.getElementById('rangeSel');
const fromDT = document.getElementById('fromDT');
const toDT = document.getElementById('toDT');
const p2 = n => String(n).padStart(2,'0');
const fmtFull = d => `${d.getFullYear()}-${p2(d.getMonth()+1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;

function applyTimes(from, to){
  state.from = from; state.to = to;
  fromDT.value = from ? from.slice(0, 19) : '';
  toDT.value = to ? to.slice(0, 19) : '';
  fromDT.classList.remove('invalid'); toDT.classList.remove('invalid');
  render();
}

rangeSel.addEventListener('change', ()=>{
  const r = rangeSel.value;
  const now = new Date();
  const todayA = `${now.getFullYear()}-${p2(now.getMonth()+1)}-${p2(now.getDate())}`;
  if (r === 'all') return applyTimes('', '');
  if (r === 'today') return applyTimes(todayA + ' 00:00:00.000', todayA + ' 23:59:59.999');
  if (r === 'yesterday'){
    const y = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
    const a = `${y.getFullYear()}-${p2(y.getMonth()+1)}-${p2(y.getDate())}`;
    return applyTimes(a + ' 00:00:00.000', a + ' 23:59:59.999');
  }
  const hours = parseInt(r, 10);
  applyTimes(fmtFull(new Date(Date.now() - hours*3600e3)) + '.000', '');
});

function onTimeEdit(el, isTo){
  const v = normTime(el.value, isTo);
  if (v === null){ el.classList.add('invalid'); return; }
  el.classList.remove('invalid');
  if (isTo) state.to = v; else state.from = v;
  render();
}
fromDT.addEventListener('input', ()=>onTimeEdit(fromDT, false));
toDT.addEventListener('input', ()=>onTimeEdit(toDT, true));

// ---- 点击时间框：弹出原生日期时间选择器（日历选年月日 + 滚轮选时分秒） ----
// 文本框保持可手输；透明叠加的 datetime-local(step=1) 负责弹窗
function bindPicker(txt, pick, defTime){
  const sync = ()=>{
    const m = (txt.value || '').match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2})?)/);
    if (m){
      pick.value = m[1] + 'T' + (m[2] + ':00').slice(0, 8);
    } else {
      const n = new Date();
      pick.value = `${n.getFullYear()}-${p2(n.getMonth()+1)}-${p2(n.getDate())}T${defTime}`;
    }
  };
  txt.addEventListener('click', ()=>{
    sync();
    try { pick.showPicker(); } catch(e) { /* 浏览器不支持时仍可直接键入 */ }
  });
  pick.addEventListener('change', ()=>{
    if (!pick.value) return;
    txt.value = pick.value.replace('T', ' ');
    txt.dispatchEvent(new Event('input', {bubbles:true}));
  });
}
bindPicker(fromDT, document.getElementById('fromPick'), '00:00:00');
bindPicker(toDT, document.getElementById('toPick'), '23:59:59');

// 初始默认：今天全天（填入输入框，直观可见）
rangeSel.value = 'today';
rangeSel.dispatchEvent(new Event('change'));
document.addEventListener('keydown', e=>{
  if(e.ctrlKey && e.key.toLowerCase()==='q'){e.preventDefault();document.getElementById('q').focus()}
});
document.querySelectorAll('#mainTable thead th').forEach(th=>{
  th.addEventListener('click', ()=>{
    const k = th.dataset.k;
    if(state.sortKey===k){state.sortDir = state.sortDir==='asc'?'desc':'asc'}
    else{state.sortKey=k;state.sortDir='asc'}
    document.querySelectorAll('#mainTable thead th').forEach(h=>{
      h.textContent = h.textContent.replace(/[ ▲▼]+$/,'');
    });
    th.textContent = th.textContent.replace(/[ ▲▼]+$/,'') + (state.sortDir==='asc'?' ▲':' ▼');
    render();
  });
});
document.querySelectorAll('.tabs button').forEach(b=>{
  b.addEventListener('click', ()=>{
    hideTreeMarks();
    document.querySelectorAll('.tabs button').forEach(x=>x.classList.remove('active'));
    document.querySelectorAll('.page').forEach(x=>x.classList.remove('active'));
    b.classList.add('active');
    document.getElementById('page-'+b.dataset.tab).classList.add('active');
  });
});

/* ---- 导出 ---- */
function download(name, mime, content){
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], {type:mime}));
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}
function q(s){
  // CSV 公式注入防护：证据内容攻击者可控，= + - @ 开头的单元格在 Excel 中
  // 会被当公式执行——前置单引号使其始终按文本处理
  s = String(s);
  if(/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"'+s.replace(/"/g,'""')+'"';
}
document.getElementById('btnCsv').onclick = ()=>{
  const list = filtered();
  const csv = '\uFEFF' + ['时间','动作类型','描述','附加信息','来源模块','可疑等级'].map(q).join(',')+'\n'
    + list.map(r=>[r.time,r.type,r.desc,r.info,r.module,r.sev==='none'?'':r.sev].map(q).join(',')).join('\n');
  download('LetMeSeeSee-时间线.csv','text/csv',csv);
};
document.getElementById('btnJson').onclick = ()=>download('LetMeSeeSee-时间线.json','application/json',JSON.stringify(filtered(),null,2));
// 证据包：完整 ScanReport（时间线+原表+模块日志+规则命中+采集环境 sysinfo）
// —— 出报告/归档用，比时间线导出多出全部模块原表与采集链要素
document.getElementById('btnBundle').onclick = ()=>{
  const bundle = {
    ...REPORT,
    events: REPORT.events, // 完整未过滤
    export_time: new Date().toLocaleString('zh-CN', {hour12:false}),
    exported_by: 'Let me see see v' + (REPORT.sysinfo?.tool_version || ''),
  };
  const name = 'LetMeSeeSee-证据包-' + (REPORT.sysinfo?.hostname || 'HOST') + '-' +
    (REPORT.sysinfo?.scan_time || '').replace(/[-: ]/g,'').slice(0,14) + '.json';
  download(name,'application/json',JSON.stringify(bundle,null,2));
};

// ---- 单文件交互式报告：界面+数据打包成一个离线 HTML ----
// 隔离网场景：目标机现场导出 → 拷出 → 自己电脑双击即完整交互（时间线/搜索/
// 过滤/规则/进程树/±10s 关联全部可用），依赖服务的功能在报告模式自动隐藏
document.getElementById('btnInteractive').onclick = async ()=>{
  const meta = document.getElementById('meta');
  const old = meta.textContent;
  meta.textContent = '正在生成交互式报告（内嵌全部数据，约几秒）…';
  try{
    const [html, js, css] = await Promise.all([
      fetch('/').then(r=>r.text()),
      fetch('/app.js').then(r=>r.text()),
      fetch('/style.css').then(r=>r.text()),
    ]);
    // 数据内嵌：JSON 字符串里的 "</" 转义为 "<\/"（JSON 合法转义，防 </script> 逃逸）
    const data = JSON.stringify(REPORT).replace(/<\//g, '<\/');
    const jsCode = js.replace(/<\/script/gi, '<\/script');
    const host = REPORT.sysinfo?.hostname || 'HOST';
    const st = (REPORT.sysinfo?.scan_time || '').replace(/[-: ]/g,'').slice(0,14);
    const out = html
      .replace('<title>Let me see see</title>',
               `<title>Let me see see 报告 · ${host} · ${REPORT.sysinfo?.scan_time || ''}</title>`)
      .replace('<link rel="stylesheet" href="style.css">',
               '<style>' + css + '</style>')
      .replace('<script src="app.js"></script>',
               '<script>window.__LMSS_REPORT__=' + data + ';</script><script>' + jsCode + '</script>');
    download(`LetMeSeeSee-交互式报告-${host}-${st}.html`, 'text/html', out);
    meta.textContent = old;
  }catch(e){
    meta.textContent = '交互式报告生成失败：' + e.message;
  }
};

// ---- 时间线表格：列宽拖拽调节（记忆到 localStorage，双击手柄恢复默认） ----
const COL_DEFAULT = [16, 9, 29, 25, 13, 8]; // 初始百分比（载入时像素化）
(function initColResize(){
  const table = document.getElementById('mainTable');
  if (!table) return;
  const cols = [...table.querySelectorAll('colgroup col')];
  if (!cols.length) return;
  // 像素锁定：前 N-1 列拖成多宽就固定多宽，互不影响；最后一列吸收剩余空间
  const flex = cols.length - 1; // 最后一列（无宽度，自动伸缩）
  const applyDefault = ()=>{
    const w = table.clientWidth || 1000;
    COL_DEFAULT.slice(0, flex).forEach((p, i) => {
      cols[i].style.width = Math.round(w * p / 100) + 'px';
    });
    // 最后一列必须保持自动宽度：固定布局下由它吸收剩余空间，
    // 若被钉死（百分比/像素）则浏览器会按比例重排所有列，拖动增量被吃掉
    cols[flex].style.width = 'auto';
  };
  applyDefault();
  try {
    const saved = JSON.parse(localStorage.getItem('LetMeSeeSee-colw-px') || 'null');
    if (Array.isArray(saved) && saved.length === flex) {
      saved.forEach((w, i) => { if (w >= 40) cols[i].style.width = Math.round(w) + 'px'; });
    }
  } catch(e) {}
  const save = ()=>{
    try {
      localStorage.setItem('LetMeSeeSee-colw-px',
        JSON.stringify(cols.slice(0, flex).map(c => parseFloat(c.style.width))));
    } catch(e) {}
  };
  const reset = ()=>{
    applyDefault();
    try { localStorage.removeItem('LetMeSeeSee-colw-px'); } catch(e) {}
  };
  // 实现方式：不往表头塞任何子元素（排序的 textContent 重写会销毁子元素——
  // 旧版手柄 div 就是这么被干掉的），改为"表头右缘 EDGE 像素内"直接响应：
  // 悬停变 ↔ 光标、按下即拖、双击恢复默认。
  const EDGE = 12;
  let dragging = false;
  let suppressClick = false;
  table.querySelectorAll('thead th').forEach((th, i) => {
    if (i >= flex) return; // 最后一列由剩余空间决定，不拖
    const nearEdge = e => th.getBoundingClientRect().right - e.clientX <= EDGE;
    th.addEventListener('mousemove', e => {
      if (dragging) return;
      th.style.cursor = nearEdge(e) ? 'col-resize' : 'pointer';
    });
    th.addEventListener('mouseleave', ()=>{ if (!dragging) th.style.cursor = 'pointer'; });
    th.addEventListener('dblclick', e => {
      if (nearEdge(e)) { e.stopPropagation(); reset(); }
    });
    th.addEventListener('mousedown', e => {
      if (!nearEdge(e)) return; // 非边缘区域：留给排序点击
      e.preventDefault(); e.stopPropagation();
      dragging = true;
      th.style.cursor = 'col-resize';
      const startX = e.clientX;
      const startW = parseFloat(cols[i].style.width) || th.getBoundingClientRect().width;
      // 不设总宽上限：列可以拖到超出可视区，表格区横向滚动条负责查看
      const onMove = ev => {
        const w = Math.max(40, startW + (ev.clientX - startX));
        cols[i].style.width = Math.round(w) + 'px';
      };
      const onUp = ()=>{
        dragging = false;
        th.style.cursor = 'pointer';
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        save();
        // 抑制松手后紧跟的 click，避免误触排序
        suppressClick = true;
        setTimeout(()=>{ suppressClick = false; }, 200);
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });
  });
  // 捕获阶段拦截拖拽后的 click（排序处理器挂在同一批 th 上）
  table.querySelector('thead').addEventListener('click', e => {
    if (suppressClick) { e.stopImmediatePropagation(); e.stopPropagation(); }
  }, true);
})();

// ---- 原表/时间线视图切换 ----
document.getElementById('chipRaw').addEventListener('click', ()=>{ state.view='raw'; render(); });
document.getElementById('chipTimeline').addEventListener('click', ()=>{ state.view='timeline'; render(); });

// ---- 注册表浏览器（regedit 前端化）----
let REG_PATH = '';
const REG_ROOTS = ['HKLM', 'HKU', 'HKCU', 'HKCR', 'HKCC'];
function regHome(){
  REG_PATH = '';
  document.getElementById('regPath').value = '';
  document.getElementById('regMeta').textContent = '选择一个根开始浏览，或输入完整键路径后点「转到」';
  document.querySelector('#regKeys tbody').innerHTML = REG_ROOTS.map(r=>
    `<tr data-p="${r}"><td>📁 ${r}</td><td></td></tr>`).join('');
  document.querySelector('#regVals tbody').innerHTML =
    '<tr><td colspan="3" style="color:#5f6368">点击左侧子键逐层展开；路径可直接粘贴到上方输入框</td></tr>';
  document.querySelectorAll('#regKeys tbody tr').forEach(tr=>{
    tr.addEventListener('click', ()=>regBrowse(tr.dataset.p));
  });
}
async function regBrowse(path){
  REG_PATH = path;
  document.getElementById('regPath').value = path;
  document.getElementById('regMeta').textContent = '加载中…';
  const r = await fetch(`/api/reg?path=${encodeURIComponent(path)}&t=${encodeURIComponent(TOKEN)}`)
    .then(x=>x.json()).catch(()=>null);
  const kbody = document.querySelector('#regKeys tbody');
  const vbody = document.querySelector('#regVals tbody');
  if (!r || r.error){
    kbody.innerHTML = '';
    document.getElementById('regMeta').textContent = '⚠ ' + ((r && r.error) || '请求失败');
    return;
  }
  document.getElementById('regMeta').textContent =
    `${r.path} · 键最后写入 ${r.last_write || '—'} · 子键 ${r.subkeys.length} · 值 ${r.values.length}`
    + (r.note ? ` · ⚠ ${r.note}` : '');
  kbody.innerHTML = r.subkeys.map(k=>
    `<tr data-p="${esc(r.path + '\\' + k.name)}"><td>📁 ${esc(k.name)}</td><td class="time">${esc(k.last_write)}</td></tr>`).join('')
    || '<tr><td style="color:#5f6368">（无子键）</td><td></td></tr>';
  vbody.innerHTML = r.values.map(v=>
    `<tr title="${esc(v.data)}"><td class="mono">${esc(v.name)}</td><td>${esc(v.ty)}</td><td class="mono">${esc(v.data)}</td></tr>`).join('')
    || '<tr><td colspan="3" style="color:#5f6368">（无值）</td></tr>';
  kbody.querySelectorAll('tr[data-p]').forEach(tr=>{
    tr.addEventListener('click', ()=>regBrowse(tr.dataset.p));
  });
}
document.getElementById('regGo').addEventListener('click', ()=>{
  const p = document.getElementById('regPath').value.trim();
  if (p) regBrowse(p);
});
document.getElementById('regPath').addEventListener('keydown', e=>{
  if (e.key === 'Enter') document.getElementById('regGo').click();
});
document.getElementById('regUp').addEventListener('click', ()=>{
  if (!REG_PATH) return;
  const i = REG_PATH.lastIndexOf('\\');
  if (i <= 0) regHome(); else regBrowse(REG_PATH.slice(0, i));
});

/* ---- 程序档案（demo）：按程序名聚合全部证据源 ---- */
function runProg(){
  const query = document.getElementById('progQ').value.trim().toLowerCase();
  const out = document.getElementById('progResult');
  if(!query){ out.innerHTML = '<div class="hint" style="margin:14px 2px">请输入程序名或路径片段</div>'; return; }
  const evs = REPORT.events.filter(e => (e.desc||'').toLowerCase().includes(query));
  if(!evs.length){ out.innerHTML = `<div class="hint" style="margin:14px 2px">全部证据源中未找到包含「${esc(query)}」的痕迹</div>`; return; }
  const byModule = {};
  for(const e of evs){
    const b = byModule[e.module] = byModule[e.module] || {count:0, last:''};
    b.count++;
    if(/^\d/.test(e.time) && e.time > b.last) b.last = e.time;
  }
  const times = evs.filter(e=>/^\d/.test(e.time)).map(e=>e.time).sort();
  const kinds = [...new Set(evs.map(e=>e.type))];
  out.innerHTML = `
    <div class="ov-cards">
      <div class="ov-card"><div class="ov-num">${evs.length}</div><div class="ov-lbl">痕迹总数</div></div>
      <div class="ov-card"><div class="ov-num">${Object.keys(byModule).length}</div><div class="ov-lbl">命中证据源</div></div>
      <div class="ov-card"><div class="ov-num">${kinds.length}</div><div class="ov-lbl">事件类型数</div></div>
      <div class="ov-card"><div class="ov-num ov-ts">${esc(times[0]||'—')}</div><div class="ov-lbl">最早记录</div></div>
      <div class="ov-card"><div class="ov-num ov-ts">${esc(times[times.length-1]||'—')}</div><div class="ov-lbl">最近记录</div></div>
    </div>
    <div class="toolbar" style="margin:10px 0">
      <button class="btn" id="btnProgTimeline" type="button">↗ 在时间线中查看（带搜索词）</button>
    </div>
    <div class="prog-srcs">${Object.entries(byModule).sort((a,b)=>b[1].count-a[1].count).map(([m,v])=>`
      <div class="prog-src"><b>${esc(m)}</b> <span class="tag">${v.count} 条</span>${v.last?`<span class="hint mono">最近 ${esc(v.last)}</span>`:''}</div>`).join('')}</div>
    <h3 class="prog-h3">合并时间序列（全部来源，新→旧，前 60 条）</h3>
    <div class="tablewrap" style="max-height:420px"><table>
      <thead><tr><th style="width:170px">时间</th><th style="width:110px">类型</th><th style="width:240px">来源</th><th>内容</th></tr></thead>
      <tbody>${evs.slice().sort((a,b)=>b.time.localeCompare(a.time)).slice(0,60).map(e=>`
        <tr><td class="mono time">${esc(e.time)}</td><td>${esc(e.type)}</td><td>${esc(e.module)}</td><td class="mono" title="${esc(e.desc)}">${esc(e.desc)}</td></tr>`).join('')}</tbody>
    </table></div>
    <div class="hint" style="margin:8px 2px">（程序档案为 demo 预览：按描述字段聚合；正式版可按映像名/哈希精确归一）</div>`;
  document.getElementById('btnProgTimeline').addEventListener('click', ()=>{
    state.q = query;
    document.getElementById('q').value = query;
    document.querySelector('.tabs button[data-tab="timeline"]').click();
    render();
  });
}
document.getElementById('btnProg').addEventListener('click', runProg);
document.getElementById('progQ').addEventListener('keydown', e=>{ if(e.key==='Enter') runProg(); });

/* ---- 进程树（demo）：Sysmon / 4688 / 现场快照三档降级 ---- */
let TREE_STATE = {expanded: new Set(), selected: null, data: null, initDone: false};
const treeBasename = p => String(p||'').split('\\').pop() || p;

function renderTree(){
  const pt = REPORT.proc_tree;
  const tierEl = document.getElementById('treeTier');
  const main = document.getElementById('treeMain');
  const det = document.getElementById('treeDetail');
  if(!pt || pt.tier === 'none'){
    tierEl.textContent = '';
    main.innerHTML = `<div class="tree-guide">
      <h3>无法获取当前进程快照</h3>
      <p>${esc(pt?.tier_note || '进程现场模块未返回数据（PowerShell 不可用或超时）。')}</p>
      <p class="hint">进程树展示的是扫描时刻的存活进程；历史进程创建（4688/Sysmon）事件请查看总时间线。</p>
    </div>`;
    det.innerHTML = '';
    return;
  }
  if(TREE_STATE.data !== pt){
    TREE_STATE = {expanded: new Set(), selected: null, data: pt, initDone: false};
  }
  tierEl.innerHTML = `${esc(pt.tier_note)}${pt.coverage ? ' · 覆盖 ' + esc(pt.coverage) : ''}`;
  // 组装嵌套 + 子树统计
  const q = document.getElementById('treeQ').value.trim().toLowerCase();
  const onlySus = document.getElementById('treeSus').checked;
  const byKey = {};
  pt.nodes.forEach(n => byKey[n.key] = {...n, children: [], maxSev: 0, susCnt: 0, qMatch: false});
  const roots = [];
  pt.nodes.forEach(n => {
    if(n.parentKey && byKey[n.parentKey]) byKey[n.parentKey].children.push(byKey[n.key]);
    else roots.push(byKey[n.key]);
  });
  const calc = n => {
    let mx = sevOrder[n.sev] || 0, cnt = mx >= 2 ? 1 : 0;
    let qm = !q || (n.image + ' ' + n.cmd).toLowerCase().includes(q);
    for(const c of n.children){
      const r = calc(c);
      mx = Math.max(mx, r.mx); cnt += r.cnt; qm = qm || r.qm;
    }
    n.maxSev = mx; n.susCnt = cnt; n.qMatch = qm;
    n.children.sort((a,b) => (b.maxSev - a.maxSev) || String(b.start).localeCompare(String(a.start)));
    return {mx, cnt, qm};
  };
  roots.forEach(calc);
  roots.sort((a,b) => (b.maxSev - a.maxSev) || String(b.start).localeCompare(String(a.start)));
  // 首次渲染默认展开：深度≤2 或 子树含红/黄
  if(!TREE_STATE.initDone){
    const mark = (n, depth) => {
      if(depth < 2 || n.maxSev >= 2){
        TREE_STATE.expanded.add(n.key);
        n.children.forEach(c => mark(c, depth + 1));
      }
    };
    roots.forEach(r => mark(r, 0));
    TREE_STATE.initDone = true;
  }
  const visible = n => (!onlySus || n.maxSev >= 2) && (!q || n.qMatch);
  const rowHtml = (n, depth) => {
    if(!visible(n)) return '';
    const sus = (sevOrder[n.sev] || 0) >= 2;
    const expanded = TREE_STATE.expanded.has(n.key);
    const hiddenKids = n.children.filter(visible).length;
    const caret = hiddenKids ? `<span class="tree-caret" data-toggle="${esc(n.key)}">${expanded ? '▾' : '▸'}</span>` : '<span class="tree-caret tree-leaf">·</span>';
    const kids = expanded ? n.children.map(c => rowHtml(c, depth + 1)).join('') : '';
    const folded = !expanded && hiddenKids ? `<span class="hint">+${hiddenKids}</span>` : '';
    return `<div class="tree-row ${sus ? 'sus-' + n.sev : ''} ${TREE_STATE.selected === n.key ? 'sel' : ''}"
              data-key="${esc(n.key)}" style="padding-left:${8 + depth * 16}px" title="${esc(n.image)}${n.cmd ? '\n' + n.cmd : ''}">
      ${caret}<span class="mono tree-img">${esc(treeBasename(n.image))}</span>
      ${sevChip(n.sev)}<span class="tree-pid">${n.pid}</span>
      <span class="tree-time mono">${esc(String(n.start).slice(5,19))}</span>${folded}
    </div>${kids}`;
  };
  main.innerHTML = roots.map(r => rowHtml(r, 0)).join('') ||
    '<div class="hint" style="margin:14px">当前过滤条件下无匹配进程</div>';
  // 交互：caret 展开/收起、行选中出详情
  main.querySelectorAll('.tree-caret[data-toggle]').forEach(el=>{
    el.addEventListener('click', e => {
      e.stopPropagation();
      const k = el.dataset.toggle;
      TREE_STATE.expanded.has(k) ? TREE_STATE.expanded.delete(k) : TREE_STATE.expanded.add(k);
      renderTree();
    });
  });
  main.querySelectorAll('.tree-row[data-key]').forEach(el=>{
    el.addEventListener('click', () => {
      TREE_STATE.selected = el.dataset.key;
      renderTree();
    });
  });
  // 详情面板
  const n = byKey[TREE_STATE.selected];
  if(n){
    det.innerHTML = `
      <h3 class="mono" style="margin:0 0 6px;word-break:break-all">${esc(n.image)}</h3>
      <table class="kv"><tbody>
        <tr><td>命令行</td><td class="mono" style="word-break:break-all">${esc(n.cmd) || '—'}</td></tr>
        <tr><td>PID / 父 PID</td><td class="mono">${n.pid} / ${n.ppid}${n.parentKey ? '' : '（父已退出或未在快照中）'}</td></tr>
        <tr><td>启动</td><td class="mono">${esc(n.start)}</td></tr>
        <tr><td>可疑标记</td><td>${n.tags.length ? n.tags.map(t=>`<span class="tag">${esc(t)}</span>`).join(' ') : '—'}</td></tr>
        <tr><td>子进程</td><td>${n.children.length} 个（可疑 ${n.susCnt}）</td></tr>
      </tbody></table>
      <div class="tree-detail-actions">
        <button class="btn" id="btnTreeTimeline" type="button">↗ 时间线查看 ±60s</button>
        <button class="btn" id="btnTreeProg" type="button">📁 程序档案</button>
      </div>`;
    document.getElementById('btnTreeTimeline').addEventListener('click', ()=>{
      const t = String(n.start);
      const m = t.match(/^(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2}):(\d{2})/);
      if(!m) return;
      const d = new Date(+m[1], +m[2]-1, +m[3], +m[4], +m[5], +m[6]);
      const fmt = x => `${x.getFullYear()}-${p2(x.getMonth()+1)}-${p2(x.getDate())} ${p2(x.getHours())}:${p2(x.getMinutes())}:${p2(x.getSeconds())}`;
      state.from = fmt(new Date(d.getTime() - 60000)) + '.000';
      state.to = fmt(new Date(d.getTime() + 60000)) + '.999';
      fromDT.value = state.from.slice(0,19); toDT.value = state.to.slice(0,19);
      fromDT.classList.remove('invalid'); toDT.classList.remove('invalid');
      document.querySelector('.tabs button[data-tab="timeline"]').click();
      render();
    });
    document.getElementById('btnTreeProg').addEventListener('click', ()=>{
      document.getElementById('progQ').value = treeBasename(n.image);
      document.querySelector('.tabs button[data-tab="prog"]').click();
      runProg();
    });
  } else {
    det.innerHTML = '<div class="hint" style="margin:14px">点击左侧进程节点查看详情<br><br>▾/▸ 展开收起 · 嫌疑子树默认展开 · 干净子树默认折叠（+N）</div>';
  }
}
document.getElementById('treeQ').addEventListener('input', renderTree);
document.getElementById('treeSus').addEventListener('change', renderTree);
// 刷新进程树：只重扫现场快照组（进程+网络，秒级），完成后回到进程树页
const TREE_GROUP = '现场快照（进程/网络）';
document.getElementById('btnTreeRefresh').addEventListener('click', ()=>scan(false, TREE_GROUP));

// 进程树页显隐（无顶部页签，由侧边栏入口/刷新按钮驱动）
function showTreePage(){
  document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-tree').classList.add('active');
  const te = document.getElementById('treeEntry');
  if(te) te.classList.add('active');
}
function hideTreeMarks(){
  const te = document.getElementById('treeEntry');
  if(te) te.classList.remove('active');
}

// 头部显示版本号（单一来源：Cargo 包版本）
OFFLINE_REPORT ? Promise.resolve(null) : fetch(`/api/version?t=${encodeURIComponent(TOKEN)}`)
  .then(r => (r && r.ok) ? r.text() : '')
  .then(v => { if (v) document.getElementById('brandVer').textContent = ' v' + v; })
  .catch(() => {});

scan();

/* ===================== 模块使用帮助 =====================
 * 数据内嵌前端：单文件交互式报告导出后离线可用（隔离网场景）。
 * 结构：purpose 作用 / source 数据来源 / fields 字段表 / time 时间语义 / tips 解读提示
 */
const MODULE_HELP = {
  '程序运行记录（UserAssist）': {
    purpose: '记录用户通过资源管理器/开始菜单/Win+R 启动过的 GUI 程序及次数——"谁在什么时候用过什么程序"的最直接证据。',
    source: 'HKU\\<SID>\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist（值名 ROT13 编码，已知文件夹 GUID 已还原为真实路径）',
    fields: [['描述', '程序完整路径（如 C:\\Windows\\System32\\cmd.exe）'], ['GUI 执行 N 次', '该程序被 GUI 方式启动的总次数（系统累计，可信度高）'], ['用户', '所属账户']],
    time: '最后一次 GUI 执行的时间（准确）。',
    tips: [
      '只记 Explorer 发起的 GUI 启动；命令行里启动的程序、服务程序不在此列（去看 Prefetch/AmCache/4688）。',
      '执行次数是累计值：可疑工具显示"执行 37 次"说明被反复使用，不是误触。',
      '某用户 0 条 = 该账户从未用资源管理器启动过程序，属异常（正常使用不可能为零），可能被工具清除。']
  },
  '程序执行缓存（ShimCache）': {
    purpose: '证明"某个程序文件曾经存在于某个路径"——即使文件已被删除，记录仍在。排查已删除恶意样本落地位置的第一线索。',
    source: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache（二进制块，Win10/Win7 两种布局自动识别）',
    fields: [['描述', '可执行文件当时的完整路径'], ['大小/修改时间', '文件当时的大小与修改时间（部分条目含）']],
    time: 'Win10 条目无可靠时间戳（显示"（无时间戳）"是机制如此，不是缺陷）；只能证明存在过，不能证明何时。',
    tips: [
      'ShimCache 证明存在 ≠ 证明执行过；要证明执行，与 UserAssist/AmCache/Prefetch/4688 交叉。',
      '攻击者删除工具后清空工作目录，ShimCache 里的路径是搜文件系统找不到时的关键线索。',
      'SIGN.MEDIA= 开头的条目是安装媒体的合法形态，不是乱码。']
  },
  '首次执行记录（AmCache）': {
    purpose: '程序的首次执行时间 + 文件 SHA1——"这个程序第一次跑是什么时候、样本哈希是多少"。',
    source: 'C:\\Windows\\appcompat\\Programs\\Amcache.hve（需管理员直读；被锁时按提示手动复制）',
    fields: [['描述', '程序完整路径'], ['附加信息', '含 SHA1 哈希与首次执行时间——SHA1 可自行到威胁情报平台比对']],
    time: '首次执行时间（准确，来自系统记录）。',
    tips: [
      'AmCache 是"执行过"的证据（比 ShimCache 的"存在过"强一级）。',
      '拿到 SHA1 后建议到内外部威胁平台比对，样本已删除时这是唯一可查哈希的源。',
      '0 条通常是权限不足（需管理员），见模块日志说明。']
  },
  '后台活动监控（BAM/DAM）': {
    purpose: '每个程序的"最后一次后台活动时间"——程序最近一次活跃于何时。',
    source: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\<SID>（值名即程序完整路径）',
    fields: [['描述', '程序完整路径'], ['用户', '所属账户']],
    time: '该程序最后一次后台活动时间（准确）。',
    tips: [
      '需要管理员权限；Win11 22H2+ 系统已移除该键，0 条且日志提示属正常。',
      '判断"恶意程序最后一次活动是什么时候"——处置后复查应无新增时间。']
  },
  '程序预读取（Prefetch）': {
    purpose: '程序运行次数、首次/最后运行时间、以及它加载过哪些文件——程序执行行为最完整的文件层证据。',
    source: 'C:\\Windows\\Prefetch\\*.pf（含 Win10+ MAM 压缩格式自动解压；需管理员）',
    fields: [['运行次数', '累计执行次数（清缓存会重置）'], ['最后/首次运行', '最近一次与第一次运行时间（准确）'], ['加载文件', '该程序运行时访问过的 DLL/数据文件列表——恶意样本的配套文件在这里现形']],
    time: '运行时间槽由系统维护，准确可信。',
    tips: [
      '运行次数 × 首次运行可以刻画攻击者工具的使用强度和时间窗口。',
      '加载列表里出现可疑路径（Temp/Public/用户目录下的 DLL）是 DLL 劫持/白加黑的线索。',
      '需要管理员权限读取；Prefetch 目录被整体删除本身就是反取证痕迹。']
  },
  '程序启动缓存（MUICache）': {
    purpose: '程序首次以 GUI 方式启动的路径记录——"这个路径上的程序曾经跑起来过"的弱佐证。',
    source: 'HKU\\<SID>\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache',
    fields: [['描述', '程序完整路径'], ['附加信息', '程序显示名等元数据']],
    time: '无时间戳（机制如此）。',
    tips: [
      '无时间、只证明启动过；与其他执行证据交叉使用。',
      '临时目录/可疑路径出现在这里说明该路径的程序被执行过（哪怕文件已删）。']
  },
  '最近文档（RecentDocs）': {
    purpose: '用户打开过的文档记录（双击打开、最近文件菜单）——"谁动过哪些文件"。',
    source: 'HKU\\<SID>\\...\\Explorer\\RecentDocs（注册表）+ Recent 文件夹 LNK 双源合并',
    fields: [['描述', '文档完整路径'], ['用户', '所属账户']],
    time: '最后打开时间。',
    tips: [
      '用户在系统设置里清空/关闭"最近文件"后为空——0 条先确认是否被清理。',
      '敏感文件名（账号表/密码/拓扑）出现在这里是数据触碰的直接证据。']
  },
  '文件对话框记录（OpenSave）': {
    purpose: '任何程序弹出"打开/保存文件"对话框时选择过的文件——"程序内选过什么文件"。',
    source: 'HKU\\<SID>\\...\\Explorer\\ComDlg32\\OpenSavePidlMRU（按扩展名分桶）',
    fields: [['描述', '对话框里选择过的文件完整路径'], ['扩展名', '该记录所在的扩展名分组'], ['（已不存在）', '路径已核验不存在——文件已被删除/移动/重命名或盘符变更，记录本身是真实历史']],
    time: '该扩展名桶的注册表最后写入时间——同一扩展的所有记录共享这一个时间（机制如此：条目本身不带独立时间）。',
    tips: [
      '只记程序内的打开/保存对话框；资源管理器里浏览文件夹不记这里（那是 ShellBags）。',
      '浏览器下载另存为的落点、工具打开样本的路径都在这——文件删了记录还在。',
      '（前缀未知）开头的条目：PIDL 根是未注册的连接点，盘符无法还原，按相对路径理解。']
  },
  '文件夹浏览记录（ShellBags）': {
    purpose: '用户在资源管理器里打开过的文件夹全集——"去过哪些目录"，包括已删除的目录。',
    source: 'HKU\\<SID>_Classes\\...\\Shell\\BagMRU（主存储）+ HKU\\...\\Shell\\BagMRU（旧位置），SHITEMID 结构化解析',
    fields: [['描述', '文件夹完整路径；（已不存在）= 路径已核验不存在（历史记录，目录可能已删/改名）'], ['桌面\\ 前缀', '挂在桌面命名空间下的相对碎片按用户主目录推定还原（前缀为推定）'], ['附加信息', '含用户 SID——哪个账户浏览的']],
    time: '★关键语义：时间 = 该文件夹视图状态最后变更时间，不是访问时间！重复访问旧文件夹不刷新其时间戳（视图无变化时 Windows 零写入），只有导航路径上的部分祖先节点会刷新。',
    tips: [
      '查"今天去过哪"不要用时间过滤——用搜索框按路径搜；祖先链的今天时间本身就是当天导航足迹（刷新到哪层说明当天活动到哪层）。',
      '今天首次打开的新文件夹才有今天的准确时间——攻击者新建目录首次打开的暴露时刻是本模块最有价值的场景。',
      '现存路径与已删除路径显式区分，绝不混排。']
  },
  '回收站': {
    purpose: '被删除到回收站的文件清单——删除时刻、原路径、删除者。',
    source: '各盘 \\$Recycle.Bin\\<SID>\\$I* 删除元数据文件',
    fields: [['原路径', '删除前的完整路径'], ['删除时间', '按 Delete 的准确时刻'], ['删除者 SID', '哪个账户删的'], ['大小', '删除时文件大小']],
    time: '删除时刻（准确）。',
    tips: [
      '★清空回收站 = 证据消失（$I 文件被物理删除），清空后再扫必然 0 条——工具如实反映。',
      '可执行文件被删标黄（R-021）：攻击者用完工具删文件的典型动作。',
      '其他账户的删除记录需要管理员权限。']
  },
  'Defender 防护与检出': {
    purpose: 'Defender 的配置现状（排除项/实时保护）+ 历史检出/处置记录——免杀配置和病毒对抗的时间线。',
    source: '注册表 Exclusions 两处键 + Defender 操作日志（1116 检出 / 1117 处置 / 5007 配置变更 / 5001 关闭实时保护 / 5013 添加排除）',
    fields: [['原表-类别', '排除项/检出/配置变更/防护事件/实时保护（原表=全部数据源，时间线=聚合后的重点）'], ['检出 N 次（首 ~ 末）', '同一威胁反复检出的聚合（实时监控每次触碰都记一条，聚合防刷屏）'], ['常规配置变更', '引擎/签名更新类不进时间线只计数——安全相关变更（关闭防护/加排除）才保留']],
    time: '检出/变更为聚合首末时间（准确）；排除项 = 注册表键最后写入时间。',
    tips: [
      '排除项是免杀最常见配置：出现非系统目录/进程名即重点关注（黄色 R-018）。',
      '"实时保护被关闭"的时段内恶意文件不会被扫描——把关闭时段与文件落盘时间对齐。',
      'Defender 日志不可读（第三方杀软接管或被清也会如此），结合安全日志 1102 判断。']
  },
  'WMI事件订阅': {
    purpose: '无文件持久化（WMI 事件订阅）检查——不落盘的攻击驻留方式。',
    source: 'root\\subscription 命名空间四类对象（__EventFilter / CommandLineEventConsumer / ActiveScriptEventConsumer / __FilterToConsumerBinding），COM 直调查询',
    fields: [['类', 'WMI 对象类型'], ['名称', '对象名（系统默认的 SCM Event Log 两项为灰=豁免）'], ['查询/命令行/脚本/过滤器/消费者', '触发条件与执行内容——非默认的命令行/脚本消费者为红色 R-014']],
    time: '无时间戳属机制如此（WMI 订阅不带创建时间），不是缺陷。',
    tips: [
      '干净机器通常只有 2 条灰色的系统默认 SCM 订阅。',
      '命中的红色订阅要结合命令行内容判断：下载器/脚本启动=典型攻击驻留。']
  },
  '高级持久化检查': {
    purpose: '四大注册表劫持类持久化落点：IFEO 映像劫持 / AppInit_DLLs 全局注入 / LSA 假安全包（mimikatz 类）/ 屏保劫持。',
    source: 'HKLM Image File Execution Options、AppInit_DLLs、Lsa\\SecurityPackages、每用户屏保键',
    fields: [['类型/位置/数据', '劫持类型、注册表位置、被写入的值'], ['键最后写入时间', '该劫持何时建立的线索']],
    time: '注册表键最后写入时间（落点建立时间线索）。',
    tips: [
      '0 条且状态正常 = 干净（这四项正常机器本应为空）——命中任何一条都需立即处置。',
      'LSA SecurityPackages 多出的任何非默认成员都是高危（lsass 内加载恶意包）。']
  },
  '事件日志（系统/应用/网络）': {
    purpose: '系统层事件时间线：开关机、服务安装、网络连接历史、任务计划留痕。',
    source: 'System / Application / Microsoft-Windows-NetworkProfile/Operational / TaskScheduler/Operational 通道（Win32 API 导出副本解析，非提权自动降级）',
    fields: [['动作类型', '开机/关机/服务安装/网络连通/任务注册等'], ['附加信息', '事件原始字段（服务名、映像路径等）']],
    time: '事件时间（准确，含毫秒）。',
    tips: [
      '服务安装（7045）是恶意服务落地的高价值事件。',
      '开关机时间线用于框定入侵窗口：两次开机之间的间隔内不该有用户活动。']
  },
  '安全日志（Security）': {
    purpose: '登录/认证/进程创建/账户管理的权威时间线——应急的核心证据源。',
    source: 'Security 通道（需管理员；非提权自动降级说明），4624/4625/4648/4688/1102/4720 系列、4625 暴力破解聚合、R-030 爆破后成功序列',
    fields: [['登录类型', '2=交互 / 10=远程桌面 / 3=网络——类型比成败更重要'], ['源地址', '登录发起方（公网 IP 尤其关注）'], ['爆破聚合', '同一源的大量失败聚合为一条，显示次数与首末时间']],
    time: '事件时间（准确，含毫秒）。',
    tips: [
      '4688 进程创建需要审核策略开启——没有时进程审计用 Prefetch/Sysmon 补。',
      '4625 聚合后紧跟的成功登录（R-030 红色）= 爆破得手，最高优先级处置线索。',
      '1102 日志清空 = 攻击者擦痕迹的直接证据，把清空时间前的最后事件拉出来看。']
  },
  'PowerShell 日志（4104）': {
    purpose: 'PowerShell 脚本块日志——混淆命令、下载器、内联攻击脚本的原文。',
    source: 'Microsoft-Windows-PowerShell/Operational 4104 事件（需系统开启脚本块日志记录）',
    fields: [['描述', '脚本块原文片段'], ['附加信息', '路径/引擎信息']],
    time: '事件时间（准确）。',
    tips: [
      '未开启脚本块日志的机器此模块为空——属配置问题而非无活动。',
      '搜索 -enc / IEX / DownloadString / FromBase64String 快速定位混淆执行。']
  },
  'Sysmon 日志': {
    purpose: 'Sysmon 采集的进程创建（Event 1，含完整命令行/父进程/哈希）与网络连接（Event 3）。',
    source: 'Microsoft-Windows-Sysmon/Operational（需目标机事先安装 Sysmon——没装则 0 条属正常）',
    fields: [['命令行', '完整启动命令行'], ['父进程', '谁启动的它——进程链还原'], ['哈希', '样本哈希可直接比对威胁情报']],
    time: '事件时间（准确）。',
    tips: [
      '本工具自动检测是否安装 Sysmon，未装时如实报空。',
      '装有 Sysmon 的机器，这是命令行级攻击行为的最佳证据源。']
  },
  '自启动项': {
    purpose: '开机自启动程序清单（Run 家族/Winlogon/启动文件夹）。',
    source: 'HKLM/HKCU Run·RunOnce 家族、Winlogon 键、启动文件夹（含每用户）',
    fields: [['描述', '自启动项名称与执行命令'], ['（微软自带）', '系统/常见软件自带的豁免条目标灰降噪'], ['键最后写入时间', '该自启动项何时添加的线索']],
    time: '注册表键最后写入时间（添加时间线索，非执行时间）。',
    tips: [
      '重点看命令指向的路径：Temp/Public/AppData 下的自启动=高可疑。',
      '时间戳能回答"这个自启动项是上周才出现的吗"。']
  },
  '计划任务': {
    purpose: '全部计划任务及触发动作（时间线只列非微软任务，原表含全量）。',
    source: 'C:\\Windows\\System32\\Tasks\\*.xml 全量解析',
    fields: [['原表', '任务名/状态/触发器/动作/作者/创建时间——点击首列可看完整任务 XML'], ['时间线', '非微软任务（微软任务 160+ 条降噪进原表）']],
    time: '任务创建/注册时间；部分字段缺失显示"（无时间戳）"。',
    tips: [
      '任务计划是仅次于服务的持久化落点：动作指向脚本/可疑路径即重点。',
      '原表里点任务名可查看完整 XML（含触发条件与命令行全文）。']
  },
  '系统服务': {
    purpose: '系统服务清单 + svchost ServiceDll 劫持检查。',
    source: 'HKLM\\SYSTEM\\CurrentControlSet\\Services 全量 + 参数键',
    fields: [['描述', '服务名/显示名/描述'], ['路径', '服务映像或 ServiceDll——svchost 组内非标准 DLL 即劫持（R-011）'], ['启动类型', '自启/手动/禁用']],
    time: '服务键最后写入时间（创建/修改线索）。',
    tips: [
      '无描述 + 非常规路径 + 自启 = 恶意服务三特征。',
      'ServiceDll 劫持不动服务名只换 DLL，专查 svchost 宿主的参数键。']
  },
  '账号安全': {
    purpose: '本地账户安全检查：隐藏账户（$ 结尾）/ RID 克隆 / 已删账户的孤儿配置目录。',
    source: 'SAM 解析（需管理员）+ NetUserEnum + ProfileList 交叉',
    fields: [['描述', '账户名/异常类型'], ['RID', '500=内置管理员；与已知账户 RID 相同=克隆账户（R-013）'], ['孤儿目录', 'C:\\Users 下无同名账户的目录——账户可能已被删除（R-015）']],
    time: '账户相关键时间。',
    tips: [
      '克隆账户登录名不同但 RID 与管理员相同，拥有同等权限——重点排查。',
      '隐藏账户以 $ 结尾不出现在 net user 结果里，只在 SAM 里现形。']
  },
  'USB 设备历史': {
    purpose: '历史接入过的 USB 设备清单——数据外带与摆渡入侵的线索。',
    source: 'C:\\Windows\\inf\\setupapi.dev.log（含归档）解析 + 注册表 USBSTOR',
    fields: [['描述', '设备名/序列号'], ['首次/最后使用', '接入时间范围']],
    time: '驱动安装日志时间（准确）。',
    tips: [
      '把 USB 接入时间与文件外带时间对齐；序列号可对应到具体实体设备。',
      '事件时间窗内新出现的 USB 设备值得追查来源。']
  },
  'RDP 客户端历史': {
    purpose: '本机作为客户端远程连接过哪些机器——横向移动方向证据。',
    source: 'HKU\\<SID>\\Software\\Microsoft\\Terminal Server Client\\Servers',
    fields: [['描述', '连接过的目标主机名/IP'], ['用户名提示', '该目标保存的账户名（为推定信息）']],
    time: '连接键最后写入时间。',
    tips: [
      '这是"从这台机器出去"的方向；"谁连进来"看安全日志 4624 类型 10。',
      '失陷机器连过哪些内网主机 = 横向移动的下一步排查清单。']
  },
  '落盘文件扫描': {
    purpose: '常见可写目录近期新增的可执行文件——新落地的工具快速定位。',
    source: '下载/桌面/临时/Public/AppData 等目录近 N 天的可执行文件枚举',
    fields: [['描述', '文件完整路径'], ['修改时间', '落盘时间']],
    time: '文件系统时间。',
    tips: [
      '配合事件窗口过滤：入侵时间之后新出现的 exe/dll/ps1 优先看。',
      '与 ShimCache/AmCache 交叉：这里没有但那里有的 = 已被删除。']
  },
  '崩溃记录（WER/Minidump）': {
    purpose: '应用崩溃与蓝屏记录——攻击导致的不稳定、对抗杀软的崩溃、漏洞利用失败的重试都在这。',
    source: 'C:\\ProgramData\\...\\WER（系统级）+ 每用户 AppData WER + C:\\Windows\\Minidump + MEMORY.DMP',
    fields: [['描述', '崩溃程序名'], ['来源', '系统级（ProgramData）或用户级——系统级含服务/提权进程报告'], ['蓝屏', '内核转储文件名与时间']],
    time: '崩溃时间（准确）。',
    tips: [
      '同目录反复崩溃的同名程序 = 被反复利用/对抗的样本。',
      '蓝屏时间点常与内核驱动攻击（BYOVD）相关。']
  },
  '软件安装': {
    purpose: '已安装软件清单与安装时间——合规审计与可疑工具落地线索。',
    source: 'HKLM/HKCU 卸载表（Uninstall）',
    fields: [['描述', '软件名/版本/厂商'], ['安装时间', 'InstallDate（部分软件不写则无时间）']],
    time: '卸载表记录的安装日期（天级精度，部分缺失）。',
    tips: ['关注入侵窗口内新安装的远控/压缩/黑客工具类软件。']
  },
  '进程现场': {
    purpose: '扫描时刻的存活进程树快照（父子关系组织）——现场正在跑什么。',
    source: 'CreateToolhelp32Snapshot + 命令行/路径/创建时间（Win32 API 直调）',
    fields: [['进程树页', '当前存活进程按 PPID 组织，秒级刷新'], ['命令行/创建时间', '提权后全量可读']],
    time: '快照性质：只反映扫描时刻，历史进程看 4688/Sysmon。',
    tips: ['可疑进程名 + 异常父进程（如 explorer 下挂 svchost 变体）当场发现；配合网络现场看外联。']
  },
  '网络现场（连接/DNS/hosts）': {
    purpose: '当前网络连接（TCP/UDP+归属进程）、DNS 缓存、hosts 劫持——现场外联与劫持。',
    source: 'GetExtendedTcpTable/UdpTable + DNS 缓存 API + hosts 文件（Win32 直调零子进程）',
    fields: [['本地/远程', '连接两端地址端口'], ['状态/PID', 'TCP 状态与归属进程——ESTABLISHED 的远程地址是外联焦点'], ['DNS 缓存', '近期解析过的域名（出现可疑域名=近期真实解析过）'], ['hosts 劫持', '非默认条目标黄（R-009）']],
    time: '快照性质：扫描时刻的连接与缓存。',
    tips: ['远程地址拿去威胁情报比对；DNS 缓存条目说明近期访问过对应域名。']
  }
};

/* 通用帮助（未选中具体模块/总时间线时显示） */
const GENERAL_HELP = {
  purpose: '总时间线：全部模块事件按时间排序的统一视图——攻击链时序还原的主战场。',
  fields: [
    ['时间', '各证据源的时间（语义随模块而异——点开对应模块的 ❓ 帮助看时间语义，勿默认都是"发生时间"）'],
    ['动作类型', '事件类别（程序运行/文件删除/登录…）'],
    ['描述', '核心内容（路径/账户/威胁名…）'],
    ['附加信息', '上下文细节（次数/来源/哈希…）'],
    ['来源模块', '证据来自哪个模块'],
    ['可疑标记', '红=高度可疑 / 黄=需关注 / 灰=已知正常（判定规则见"可疑规则"页）']],
  tips: [
    '点击任意行展开完整内容与 ±10 秒关联事件——攻击链的时间邻近性在这里体现。',
    '（已不存在）= 路径已核验不存在的历史记录；（无时间戳）= 该证据源机制上不带时间。',
    '程序档案页按程序名聚合全部证据源的痕迹；可疑规则页看全部规则命中。',
    '证据链交叉原则：执行类证据（UserAssist/AmCache/Prefetch/4688）与存在类证据（ShimCache）互证才下结论。']
};

function helpToHtml(h){
  const rows = (h.fields||[]).map(f=>'<tr><td>'+esc(f[0])+'</td><td>'+esc(f[1])+'</td></tr>').join('');
  const tips = (h.tips||[]).map(t=>'<li>'+esc(t)+'</li>').join('');
  let out = '<h4>作用</h4><div>'+esc(h.purpose)+'</div>';
  if (h.source) out += '<h4>数据来源</h4><div class="mono" style="font-size:12px;word-break:break-all">'+esc(h.source)+'</div>';
  if (rows) out += '<h4>字段含义</h4><table><tbody>'+rows+'</tbody></table>';
  if (h.time) out += '<h4>时间语义</h4><div>'+esc(h.time)+'</div>';
  if (tips) out += '<h4>怎么解读</h4><ul>'+tips+'</ul>';
  return out;
}

function openHelp(){
  const key = (state.mod && state.mod !== 'all') ? state.mod : null;
  const h = (key && MODULE_HELP[key]) || GENERAL_HELP;
  document.getElementById('helpTitle').textContent = (key && MODULE_HELP[key]) ? key : '总时间线 · 使用帮助';
  document.getElementById('helpBody').innerHTML = helpToHtml(h);
  document.getElementById('helpOverlay').style.display = 'flex';
}
document.getElementById('btnHelp').addEventListener('click', openHelp);
document.getElementById('helpClose').addEventListener('click', ()=>{
  document.getElementById('helpOverlay').style.display = 'none';
});
document.getElementById('helpOverlay').addEventListener('click', e=>{
  if (e.target.id === 'helpOverlay') e.target.style.display = 'none';
});
document.addEventListener('keydown', e=>{
  if (e.key === 'Escape') document.getElementById('helpOverlay').style.display = 'none';
});

/* 关于页：聚合全部模块说明（可展开） */
(function buildAboutHelpIndex(){
  const box = document.getElementById('moduleHelpIndex');
  if (!box) return;
  const names = Object.keys(MODULE_HELP);
  box.innerHTML = '<p style="color:#5f6368;font-size:12.5px;margin:6px 0">共 ' + names.length + ' 个模块的解读说明。</p>'
    + names.map(n=>'<details><summary>'+esc(n)+'</summary><div>'+helpToHtml(MODULE_HELP[n])+'</div></details>').join('');
})();
