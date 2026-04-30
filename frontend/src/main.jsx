import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  Blocks,
  ChevronRight,
  Database,
  GitCompare,
  HardDrive,
  KeyRound,
  Play,
  RefreshCw,
  SearchCheck,
  Send,
  ShieldCheck,
  Trash2,
  Upload,
  UserRound,
} from 'lucide-react';
import './styles.css';

const API = '';

async function api(path, options = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await res.json();
  if (!res.ok || data.error) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

function short(value, size = 12) {
  if (value === undefined || value === null || value === '') return '-';
  const text = String(value);
  return text.length > size ? `${text.slice(0, size)}...` : text;
}

function bytesToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function Field({ label, value }) {
  return (
    <div className="field">
      <span>{label}</span>
      <strong title={String(value ?? '')}>{value ?? '-'}</strong>
    </div>
  );
}

function Panel({ title, icon: Icon, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      <header className="panelHeader">
        <Icon size={18} />
        <h2>{title}</h2>
      </header>
      {children}
    </section>
  );
}

function IconButton({ children, icon: Icon, onClick, disabled, title, variant = '' }) {
  return (
    <button className={`button ${variant}`} onClick={onClick} disabled={disabled} title={title || children}>
      {Icon ? <Icon size={16} /> : null}
      <span>{children}</span>
    </button>
  );
}

function Select({ value, onChange, children }) {
  return (
    <select value={value} onChange={(event) => onChange(event.target.value)}>
      {children}
    </select>
  );
}

function ClientPanel({ state, selectedFile }) {
  const uploads = state?.client?.uploads || [];
  const files = state?.client?.files || [];
  const active = uploads.find((item) => item.file_id === selectedFile) || uploads.at(-1);

  return (
    <Panel title="Client 文件库" icon={UserRound}>
      <div className="metricGrid">
        <Field label="data/client_files" value={files.length} />
        <Field label="上传记录" value={uploads.length} />
      </div>

      {active ? (
        <div className="detailBlock">
          <h3>当前上传</h3>
          <Field label="source" value={short(active.source_path, 32)} />
          <Field label="owner" value={short(active.owner_address, 18)} />
          <Field label="file hash" value={short(active.file_hash, 22)} />
          <Field label="t" value={short(active.t, 22)} />
          <Field label="root" value={short(active.root, 22)} />
          <Field label="blocks" value={active.block_count || active.block_ids?.length || 0} />
        </div>
      ) : (
        <Empty text="还没有上传记录" />
      )}

      <div className="splitTitle">
        <h3>待上传文件</h3>
        <span>{files.length}</span>
      </div>
      <div className="table compactTable">
        <div className="tableHead three">
          <span>name</span>
          <span>size</span>
          <span>sha256</span>
        </div>
        {files.slice(0, 12).map((item) => (
          <div className="tableRow three" key={item.name}>
            <span title={item.name}>{short(item.name, 24)}</span>
            <span>{item.size}</span>
            <span title={item.sha256}>{short(item.sha256, 14)}</span>
          </div>
        ))}
      </div>

      <div className="table">
        <div className="tableHead three">
          <span>file_id</span>
          <span>大小</span>
          <span>root</span>
        </div>
        {uploads.slice(-6).reverse().map((item) => (
          <div className="tableRow three" key={`${item.file_id}-${item.owner_address}`}>
            <span title={item.file_id}>{short(item.file_id, 18)}</span>
            <span>{item.file_size}</span>
            <span title={item.root}>{short(item.root, 16)}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function TreeNode({ node, expanded, onToggle, depth = 0 }) {
  if (!node) return <Empty text="该文件没有可展示的 HVT 树" />;
  const hasChildren = Boolean(node.children?.length);
  const isOpen = expanded.has(node.id);
  return (
    <div className="moduleTreeNode" data-depth={depth}>
      <div className={`moduleNode ${node.kind} ${node.id === 'root' ? 'rootNode' : ''}`} onClick={() => hasChildren && onToggle(node.id)}>
        <div className="moduleNodeTop">
          <button className={`twisty ${isOpen ? 'open' : ''}`} disabled={!hasChildren} onClick={(event) => { event.stopPropagation(); onToggle(node.id); }} title={isOpen ? '收起' : '展开'}>
            {hasChildren ? <ChevronRight size={14} /> : <span />}
          </button>
          <strong>{node.id === 'root' ? 'ROOT' : node.id}</strong>
          <span className="nodeKind">{node.kind}</span>
        </div>
        <div className="moduleNodeMeta">
          <span>p={node.p ?? '-'}</span>
          <span>lN={node.lN ?? '-'}</span>
        </div>
        <div className="monoLine" title={node.h}>h {short(node.h, 24)}</div>
        {node.tag ? <div className="monoLine" title={node.tag}>tag {short(node.tag, 24)}</div> : null}
      </div>
      {hasChildren && isOpen ? (
        <div className="moduleChildren">
          {node.children.map((child, index) => (
            <div className="moduleBranch" key={child.id}>
              <div className="moduleEdgeLabel">{index === 0 ? 'left' : 'right'}</div>
              <TreeNode node={child} expanded={expanded} onToggle={onToggle} depth={depth + 1} />
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function CspPanel({ state, selectedFile, hvt }) {
  const csp = state?.csp || {};
  const files = csp.files || [];
  const blocks = hvt?.blocks || [];
  const active = files.find((item) => item.file_id === selectedFile) || files.at(-1);
  const [expanded, setExpanded] = useState(new Set(['root', 'root.L', 'root.R']));

  useEffect(() => {
    setExpanded(new Set(['root', 'root.L', 'root.R']));
  }, [hvt?.file?.file_id]);

  function toggleNode(id) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function expandAll() {
    const ids = [];
    const walk = (node) => {
      if (!node) return;
      ids.push(node.id);
      node.children?.forEach(walk);
    };
    walk(hvt?.tree);
    setExpanded(new Set(ids));
  }

  function collapseAll() {
    setExpanded(new Set(['root']));
  }

  return (
    <Panel title="CSP 本地数据库" icon={Database}>
      <div className="metricGrid">
        <Field label="files" value={csp.counts?.files || 0} />
        <Field label="blocks" value={csp.counts?.blocks || 0} />
        <Field label="HVT" value={csp.counts?.authenticators || 0} />
        <Field label="key payload" value={csp.counts?.key_cipher_blocks || 0} />
      </div>

      {active ? (
        <div className="detailBlock">
          <h3>文件状态</h3>
          <Field label="file_id" value={active.file_id} />
          <Field label="owner" value={short(active.owner_address, 18)} />
          <Field label="root" value={short(active.mht_root, 28)} />
          <Field label="blocks" value={active.block_count} />
          <Field label="public" value={active.public_blocks?.join(',') || '-'} />
          <Field label="tree" value={`${active.tree_stats?.leaves || 0} leaves / ${active.tree_stats?.height || 0} levels`} />
        </div>
      ) : (
        <Empty text="CSP 暂无文件" />
      )}

      <div className="splitTitle">
        <h3>HVT/MHT 树结构</h3>
        <span>{hvt?.file?.block_count || active?.block_count || 0} blocks</span>
      </div>
      <div className="treeActions">
        <button onClick={expandAll} disabled={!hvt?.tree}>展开全部</button>
        <button onClick={collapseAll} disabled={!hvt?.tree}>只看根</button>
      </div>
      <div className="treeViewport">
        {hvt?.file?.block_count === 1 ? (
          <div className="treeNotice">当前文件只有 1 个块，因此 HVT 是单叶树。请选择 block_count 大于 1 的文件可看到完整二叉结构。</div>
        ) : null}
        <TreeNode node={hvt?.tree} expanded={expanded} onToggle={toggleNode} />
      </div>

      <div className="splitTitle">
        <h3>文件区块列表</h3>
        <span>block_id / tag / HVT</span>
      </div>
      <div className="blockList">
        {blocks.map((block) => (
          <div className="blockItem" key={`${block.index}-${block.block_id}`}>
            <div>
              <strong>#{block.index} {block.block_id}</strong>
              <span>{block.is_public ? 'public' : 'private'} / sectors {block.sector_count}</span>
            </div>
            <div className="monoLine">tag {short(block.tag, 20)}</div>
            <div className="monoLine">sigma {short(block.authenticator?.sigma, 20)}</div>
            <div className="monoLine">y {short(block.authenticator?.y, 20)}</div>
            <div className="monoLine">Y {short(block.authenticator?.Y, 20)}</div>
            <div className="monoLine">sector values {block.sector_values_preview?.map((item) => short(item, 8)).join(', ') || '-'}</div>
            <div className="monoLine">key payload {Object.entries(block.key_payload_sizes || {}).map(([owner, size]) => `${short(owner, 8)}:${size}`).join(', ') || '-'}</div>
            <div className="monoLine">owners {block.owners?.map((item) => short(item, 10)).join(', ') || '-'}</div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function ChainPanel({ state }) {
  const chain = state?.chain || {};
  const status = chain.status || {};
  const txs = chain.transactions || [];
  const blocks = chain.blocks || [];

  return (
    <Panel title="Ganache 区块链监控" icon={Blocks}>
      <div className="metricGrid">
        <Field label="连接" value={status.connected ? 'online' : 'offline'} />
        <Field label="chain id" value={status.chain_id} />
        <Field label="高度" value={status.latest_block ?? '-'} />
        <Field label="合约" value={short(status.contract_address, 16)} />
      </div>

      <div className="splitTitle">
        <h3>最近区块</h3>
        <span>{short(status.latest_hash, 18)}</span>
      </div>
      <div className="table">
        <div className="tableHead three">
          <span>block</span>
          <span>tx</span>
          <span>hash</span>
        </div>
        {blocks.slice().reverse().map((block) => (
          <div className="tableRow three" key={block.number}>
            <span>{block.number}</span>
            <span>{block.tx_count}</span>
            <span title={block.hash}>{short(block.hash, 14)}</span>
          </div>
        ))}
      </div>

      <div className="splitTitle">
        <h3>合约交易</h3>
        <span>{txs.length}</span>
      </div>
      <div className="txList">
        {txs.slice().reverse().map((tx) => (
          <div className="txItem" key={tx.hash}>
            <strong title={tx.hash}>{short(tx.hash, 22)}</strong>
            <span>block {tx.block_number} / gas {tx.gas_used} / status {tx.status}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function Timeline({ rows }) {
  function describe(row) {
    if (row.stage === 'upload:request') {
      return `文件 ${row.file_name || '-'}，${row.file_size || 0} bytes，blocks=${row.block_count || 0}，预测重复块=${row.duplicate_block_count || 0}，新块=${row.new_block_count || 0}`;
    }
    if (row.stage === 'upload:payload') {
      return `file=${row.file_id}，blocks=${row.block_count || row.preflight?.block_count || 0}，root=${short(row.mht_root, 18)}，tx=${short(row.chain_record?.tx_hash, 16)}`;
    }
    if (row.stage === 'csp:store') {
      return `file=${row.file_id}，CSP files=${row.counts?.files}，blocks=${row.counts?.blocks}，HVT=${row.counts?.authenticators}，keyPayload=${row.counts?.key_cipher_blocks}`;
    }
    if (row.stage === 'hvt') {
      return `file=${row.file_id}，root=${short(row.root, 18)}，leaves=${row.leaves}，height=${row.height}，nodes=${row.nodes}`;
    }
    if (row.stage === 'chain:upload') {
      return `file=${row.file_id}，block=${row.record?.block_number}，gas=${row.record?.gas_used}，tx=${short(row.record?.tx_hash, 18)}`;
    }
    if (row.stage === 'audit:verify') {
      return `file=${row.file_id}，challenge=${row.challenge_id}，z=${row.z}，indices=${row.indices?.join(',') || '-'}，verified=${row.verified}，gas=${row.chain_result?.gas_used}`;
    }
    if (row.stage === 'update:commit') {
      return `file=${row.file_id}，op=${row.op}，index=${row.index}，old=${short(row.old_root, 14)}，new=${short(row.new_root, 14)}，tx=${short(row.chain_update?.tx_hash, 16)}`;
    }
    if (row.stage?.startsWith('retrieve:')) {
      return `file=${row.file_id}，role=${row.role}，size=${row.size}，sha256=${short(row.sha256, 18)}，path=${row.saved_path || '-'}`;
    }
    if (row.stage === 'transfer:csp') {
      return `file=${row.file_id}，success=${row.success}，old=${short(row.old_owner, 12)}，new=${short(row.new_owner, 12)}，tx=${short(row.transfer_record?.tx_hash, 16)}`;
    }
    return [
      row.file_id ? `file=${row.file_id}` : '',
      row.challenge_id ? `challenge=${row.challenge_id}` : '',
      row.op ? `op=${row.op}` : '',
      row.verified !== undefined ? `verified=${row.verified}` : '',
      row.root ? `root=${short(row.root, 14)}` : '',
      row.new_root ? `newRoot=${short(row.new_root, 14)}` : '',
    ].filter(Boolean).join(' ');
  }

  return (
    <section className="timeline">
      <header>
        <Activity size={18} />
        <h2>流程详情</h2>
      </header>
      <div className="timelineRows">
        {(rows || []).slice().reverse().slice(0, 28).map((row, index) => (
          <div className="timelineRow" key={`${row.time}-${row.stage}-${index}`}>
            <span className="stage">{row.stage}</span>
            <span className="time">{row.time?.slice(11, 19)}</span>
            <span className="desc">{describe(row)}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function Empty({ text }) {
  return <div className="empty">{text}</div>;
}

function App() {
  const [state, setState] = useState(null);
  const [clientFiles, setClientFiles] = useState([]);
  const [selectedClientFile, setSelectedClientFile] = useState('');
  const [selectedFile, setSelectedFile] = useState('');
  const [hvt, setHvt] = useState(null);
  const [preflight, setPreflight] = useState(null);
  const [z, setZ] = useState(2);
  const [updateOp, setUpdateOp] = useState('insert');
  const [updateIndex, setUpdateIndex] = useState(0);
  const [updatePayload, setUpdatePayload] = useState('demo-update-block');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  const files = state?.csp?.files || [];
  const effectiveFile = selectedFile || files.at(-1)?.file_id || '';

  async function refresh() {
    const data = await api('/api/state');
    setState(data);
    const clientList = await api('/api/client-files');
    setClientFiles(clientList.files || []);
    if (!selectedFile && data?.csp?.files?.length) {
      setSelectedFile(data.csp.files.at(-1).file_id);
    }
  }

  async function run(label, task) {
    setBusy(true);
    setMessage(`${label}...`);
    try {
      const data = await task();
      if (data) {
        setState(data.state || data);
        if (data.operation?.file_id) setSelectedFile(data.operation.file_id);
      }
      setMessage(`${label}完成`);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    refresh().catch((error) => setMessage(error.message));
    const id = setInterval(() => refresh().catch(() => {}), 2500);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (!effectiveFile) {
      setHvt(null);
      return;
    }
    api(`/api/csp/files/${effectiveFile}/hvt`).then(setHvt).catch((error) => setMessage(error.message));
  }, [effectiveFile, state?.csp?.counts?.blocks]);

  const activeFile = useMemo(() => files.find((item) => item.file_id === effectiveFile), [files, effectiveFile]);

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <h1>DupMix 协议演示控制台</h1>
        </div>
        <div className="statusPill">
          <span className={state?.chain?.status?.connected ? 'dot online' : 'dot'} />
          {state?.chain?.status?.connected ? `block ${state.chain.status.latest_block}` : 'Ganache offline'}
        </div>
      </header>

      <section className="controls">
        <div className="controlGroup dbPicker">
          <HardDrive size={16} />
          <Select value={selectedClientFile} onChange={setSelectedClientFile}>
            <option value="">data/client_files</option>
            {clientFiles.map((item) => (
              <option key={item.name} value={item.name}>{item.name}</option>
            ))}
          </Select>
          <IconButton icon={SearchCheck} disabled={busy || !selectedClientFile} onClick={() => run('库中文件去重预检', async () => {
            const result = await api('/api/files/preflight-client-db', { method: 'POST', body: JSON.stringify({ file_name: selectedClientFile }) });
            setPreflight(result);
            return { state };
          })}>
            预检库文件
          </IconButton>
          <IconButton icon={Upload} disabled={busy || !selectedClientFile} onClick={() => run('上传 Client 文件库文件', async () => api('/api/files/upload-from-client-db', { method: 'POST', body: JSON.stringify({ file_name: selectedClientFile }) }))}>
            上传
          </IconButton>
        </div>
        <Select value={effectiveFile} onChange={setSelectedFile}>
          <option value="">选择文件</option>
          {files.map((item) => (
            <option key={item.file_id} value={item.file_id}>{item.file_id} / {item.block_count} blocks</option>
          ))}
        </Select>
        <input className="smallInput" type="number" min="1" value={z} onChange={(event) => setZ(event.target.value)} title="审计挑战块数" />
        <IconButton icon={ShieldCheck} disabled={busy || !effectiveFile} onClick={() => run('审计验证', async () => api(`/api/files/${effectiveFile}/audit`, { method: 'POST', body: JSON.stringify({ z }) }))}>
          审计
        </IconButton>
        <IconButton icon={Send} disabled={busy || !effectiveFile} onClick={() => run('取回 owner 数据', async () => api(`/api/files/${effectiveFile}/retrieve`, { method: 'POST', body: JSON.stringify({ role: 'owner' }) }))}>
          取回
        </IconButton>
        <IconButton icon={KeyRound} disabled={busy || !effectiveFile} onClick={() => run('权限转让', async () => api(`/api/files/${effectiveFile}/transfer`, { method: 'POST', body: JSON.stringify({}) }))}>
          转让
        </IconButton>
        <IconButton icon={RefreshCw} disabled={busy} onClick={() => run('刷新状态', refresh)}>
          刷新
        </IconButton>
        <IconButton icon={Trash2} variant="danger" disabled={busy} onClick={() => run('重置演示库', async () => api('/api/demo/reset', { method: 'POST', body: JSON.stringify({}) }))}>
          重置
        </IconButton>
      </section>

      <section className="updateBar">
        <GitCompare size={16} />
        <Select value={updateOp} onChange={setUpdateOp}>
          <option value="insert">insert</option>
          <option value="modify">modify</option>
          <option value="delete">delete</option>
        </Select>
        <input className="smallInput" type="number" min="0" value={updateIndex} onChange={(event) => setUpdateIndex(event.target.value)} />
        <input value={updatePayload} onChange={(event) => setUpdatePayload(event.target.value)} placeholder="更新块内容" />
        <IconButton icon={Play} disabled={busy || !effectiveFile} onClick={() => run('动态更新', async () => api(`/api/files/${effectiveFile}/update`, { method: 'POST', body: JSON.stringify({ op: updateOp, index: Number(updateIndex), payload: updatePayload }) }))}>
          提交更新
        </IconButton>
        <span className="message">{message}</span>
      </section>

      {preflight ? (
        <section className="preflight">
          <HardDrive size={16} />
          <strong>去重预检</strong>
          <span>{preflight.file_name}</span>
          <span>blocks {preflight.block_count}</span>
          <span>文件级重复 {String(preflight.duplicate_file)}</span>
          <span>重复块 {preflight.duplicate_block_count}</span>
          <span>新块 {preflight.new_block_count}</span>
          <span>hash {short(preflight.file_hash, 18)}</span>
          <span>t {short(preflight.t, 22)}</span>
          <button className="closeBtn" onClick={() => setPreflight(null)}>关闭</button>
        </section>
      ) : null}

      {activeFile ? (
        <section className="activeSummary">
          <Field label="当前 file_id" value={activeFile.file_id} />
          <Field label="MHT root" value={short(activeFile.mht_root, 34)} />
          <Field label="block count" value={activeFile.block_count} />
          <Field label="owner" value={short(activeFile.owner_address, 20)} />
        </section>
      ) : null}

      <main className="dashboard">
        <ClientPanel state={state} selectedFile={effectiveFile} />
        <CspPanel state={state} selectedFile={effectiveFile} hvt={hvt} />
        <ChainPanel state={state} />
      </main>

      <Timeline rows={state?.timeline || []} />
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
