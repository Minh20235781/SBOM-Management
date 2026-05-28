import React, { useMemo, useState } from 'react';
import { Search, ShieldAlert } from 'lucide-react';
import { type SbomGraphResponse, type SbomGraphNode } from '../types/sbom';

type Props = {
  graph: SbomGraphResponse | null;
  loading?: boolean;
  onSearchChange: (value: string) => void;
  onDepthChange: (value: number) => void;
  onOnlyVulnerableChange: (value: boolean) => void;
  search: string;
  depth: number;
  onlyVulnerable: boolean;
};

const riskClass: Record<SbomGraphNode['riskLevel'], string> = {
  LOW: 'fill-emerald-50 stroke-emerald-300 text-emerald-800',
  MEDIUM: 'fill-blue-50 stroke-blue-300 text-blue-800',
  HIGH: 'fill-amber-50 stroke-amber-300 text-amber-800',
  CRITICAL: 'fill-red-50 stroke-red-300 text-red-800',
};

const riskBadge: Record<SbomGraphNode['riskLevel'], string> = {
  LOW: 'bg-emerald-50 text-emerald-700 border-emerald-100',
  MEDIUM: 'bg-blue-50 text-blue-700 border-blue-100',
  HIGH: 'bg-amber-50 text-amber-700 border-amber-100',
  CRITICAL: 'bg-red-50 text-red-700 border-red-100',
};

const nodeWidth = 260;
const nodeHeight = 82;
const canvasPadding = 80;

const wrapLabel = (label: string, maxLineLength = 26, maxLines = 2) => {
  const tokens = label.split(/(?=[/@:_-])|\s+/).filter(Boolean);
  const lines: string[] = [];
  let current = '';

  for (const token of tokens) {
    const next = current ? `${current}${token}` : token;
    if (next.length > maxLineLength && current) {
      lines.push(current);
      current = token;
    } else if (next.length > maxLineLength) {
      lines.push(`${next.slice(0, maxLineLength - 3)}...`);
      current = '';
    } else {
      current = next;
    }
    if (lines.length === maxLines) break;
  }

  if (current && lines.length < maxLines) lines.push(current);
  if (lines.length === 0) lines.push(label.slice(0, maxLineLength));
  if (lines.length === maxLines && label.length > lines.join('').length) {
    lines[maxLines - 1] = `${lines[maxLines - 1].slice(0, maxLineLength - 3)}...`;
  }
  return lines;
};

const SbomDependencyGraph: React.FC<Props> = ({
  graph,
  loading,
  onSearchChange,
  onDepthChange,
  onOnlyVulnerableChange,
  search,
  depth,
  onlyVulnerable,
}) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const selectedNode = graph?.nodes.find(node => node.id === selectedNodeId) || null;

  const bounds = useMemo(() => {
    const nodes = graph?.nodes || [];
    const minX = Math.min(0, ...nodes.map(node => node.x));
    const maxX = Math.max(900, ...nodes.map(node => node.x + nodeWidth));
    const minY = Math.min(0, ...nodes.map(node => node.y));
    const maxY = Math.max(420, ...nodes.map(node => node.y + nodeHeight));
    return {
      width: Math.max(900, maxX - minX + canvasPadding * 2),
      height: Math.max(560, maxY - minY + canvasPadding * 2),
      offsetX: canvasPadding - minX,
      offsetY: canvasPadding - minY,
    };
  }, [graph]);

  const nodeMap = useMemo(() => new Map((graph?.nodes || []).map(node => [node.id, node])), [graph]);

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
        <div className="border-b border-slate-100 p-4 grid grid-cols-1 md:grid-cols-[1fr_120px_140px] gap-3">
          <label className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              value={search}
              onChange={event => onSearchChange(event.target.value)}
              placeholder="Tìm package..."
              className="w-full rounded-lg border border-slate-200 pl-9 pr-3 py-2 text-sm outline-none focus:border-blue-300 focus:ring-2 focus:ring-blue-100"
            />
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-600">
            Depth
            <input
              type="number"
              min={1}
              max={12}
              value={depth}
              onChange={event => onDepthChange(Number(event.target.value) || 1)}
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm"
            />
          </label>
          <label className="flex items-center gap-2 rounded-lg border border-slate-200 px-2 py-2 text-sm text-slate-600 whitespace-nowrap">
            <input
              type="checkbox"
              checked={onlyVulnerable}
              onChange={event => onOnlyVulnerableChange(event.target.checked)}
            />
            Only vulnerable
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-slate-100 text-xs">
          {(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).map(risk => (
            <span key={risk} className={`rounded-full border px-2.5 py-1 ${riskBadge[risk]}`}>{risk}</span>
          ))}
          {graph?.summary.cycleDetected && (
            <span className="inline-flex items-center gap-1 rounded-full border border-rose-100 bg-rose-50 px-2.5 py-1 text-rose-700">
              <ShieldAlert className="h-3.5 w-3.5" /> Cycle detected
            </span>
          )}
        </div>

        <div className="h-[680px] overflow-auto bg-slate-50">
          {loading ? (
            <div className="p-10 text-center text-slate-500">Đang tải graph...</div>
          ) : !graph || graph.nodes.length === 0 ? (
            <div className="p-10 text-center text-slate-500">Chưa có snapshot graph.</div>
          ) : (
            <svg width={bounds.width} height={bounds.height} className="block">
              <defs>
                <marker id="arrow" markerWidth="12" markerHeight="12" refX="10" refY="4" orient="auto" markerUnits="strokeWidth">
                  <path d="M0,0 L0,8 L11,4 z" fill="#64748b" />
                </marker>
              </defs>
              {graph.edges.map(edge => {
                const source = nodeMap.get(edge.source);
                const target = nodeMap.get(edge.target);
                if (!source || !target) return null;
                const x1 = source.x + bounds.offsetX + nodeWidth;
                const y1 = source.y + bounds.offsetY + nodeHeight / 2;
                const x2 = target.x + bounds.offsetX - 12;
                const y2 = target.y + bounds.offsetY + nodeHeight / 2;
                const gap = Math.max(90, x2 - x1);
                const mid1 = x1 + gap * 0.45;
                const mid2 = x2 - gap * 0.45;
                return (
                  <path
                    key={edge.id}
                    d={`M ${x1} ${y1} C ${mid1} ${y1}, ${mid2} ${y2}, ${x2} ${y2}`}
                    fill="none"
                    stroke={edge.hasCycle ? '#e11d48' : '#64748b'}
                    strokeWidth={edge.hasCycle ? 2.8 : 1.8}
                    strokeOpacity={edge.hasCycle ? 0.95 : 0.72}
                    markerEnd="url(#arrow)"
                  />
                );
              })}
              {graph.nodes.map(node => (
                <g key={node.id} transform={`translate(${node.x + bounds.offsetX}, ${node.y + bounds.offsetY})`} onClick={() => setSelectedNodeId(node.id)} className="cursor-pointer">
                  <rect
                    width={nodeWidth}
                    height={nodeHeight}
                    rx={8}
                    className={node.type === 'PROJECT' ? 'fill-slate-900 stroke-slate-900' : riskClass[node.riskLevel]}
                    strokeWidth={selectedNodeId === node.id ? 3 : 1.5}
                  />
                  <text x={16} y={24} className={node.type === 'PROJECT' ? 'fill-white text-sm font-semibold' : 'fill-slate-800 text-sm font-semibold'}>
                    {wrapLabel(node.label).map((line, index) => (
                      <tspan key={line + index} x={16} dy={index === 0 ? 0 : 17}>
                        {line}
                      </tspan>
                    ))}
                  </text>
                  <text x={16} y={67} className={node.type === 'PROJECT' ? 'fill-slate-300 text-xs' : 'fill-slate-500 text-xs'}>
                    {node.type} · depth {node.depth} · CVE {node.vulnerabilityCount}
                  </text>
                </g>
              ))}
            </svg>
          )}
        </div>
      </div>

      <aside className="rounded-xl border border-slate-200 bg-white p-5">
        <h3 className="font-bold text-slate-800 mb-4">Node detail</h3>
        {selectedNode ? (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-5 text-sm">
            <div>
              <p className="text-xs uppercase text-slate-400 font-bold">Name</p>
              <p className="font-semibold text-slate-800 break-all">{selectedNode.label}</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${riskBadge[selectedNode.riskLevel]}`}>{selectedNode.riskLevel}</span>
                <span className="rounded-md border border-slate-200 px-2 py-1 text-xs text-slate-600">{selectedNode.ecosystem}</span>
              </div>
            </div>
            <div className="space-y-2">
              <p><span className="font-semibold">Version:</span> {selectedNode.version || '-'}</p>
              <p><span className="font-semibold">License:</span> {selectedNode.license || '-'}</p>
              <p><span className="font-semibold">Supplier:</span> {selectedNode.supplier || '-'}</p>
              <p className="break-all"><span className="font-semibold">PURL:</span> {selectedNode.purl || '-'}</p>
              <p className="break-all"><span className="font-semibold">Hash:</span> {selectedNode.hash || '-'}</p>
            </div>
            <div>
              <p className="font-semibold mb-1">Direct dependencies</p>
              <ul className="space-y-1 text-xs text-slate-600 max-h-40 overflow-auto pr-1">
                {(graph?.edges.filter(edge => edge.source === selectedNode.id) || []).map(edge => (
                  <li key={edge.id} className="break-all">{nodeMap.get(edge.target)?.label || edge.target}</li>
                ))}
              </ul>
            </div>
            <div>
              <p className="font-semibold mb-1">Depended by</p>
              <ul className="space-y-1 text-xs text-slate-600 max-h-40 overflow-auto pr-1">
                {(graph?.edges.filter(edge => edge.target === selectedNode.id) || []).map(edge => (
                  <li key={edge.id} className="break-all">{nodeMap.get(edge.source)?.label || edge.source}</li>
                ))}
              </ul>
            </div>
          </div>
        ) : (
          <p className="text-sm text-slate-500">Chọn một node trên graph để xem chi tiết.</p>
        )}
      </aside>
    </div>
  );
};

export default SbomDependencyGraph;
