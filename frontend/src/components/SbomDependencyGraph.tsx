import React, { useMemo, useState } from 'react';
import { Search, ShieldAlert, X } from 'lucide-react';
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

const nodeWidth = 248;
const nodeHeight = 76;
const canvasPadding = 80;
const zoomMin = 0.55;
const zoomMax = 1.8;
const zoomStep = 0.15;

const wrapLabel = (label: string, maxLineLength = 25, maxLines = 2) => {
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

const listLabel = (node: SbomGraphNode | undefined, fallback: string) => node?.label || fallback;

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
  const [zoom, setZoom] = useState(1);
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

  const edgeMeta = useMemo(() => {
    const outgoing = new Map<string, string[]>();
    const incoming = new Map<string, string[]>();
    const relatedNodeIds = new Set<string>();
    const relatedEdgeIds = new Set<string>();

    for (const edge of graph?.edges || []) {
      outgoing.set(edge.source, [...(outgoing.get(edge.source) || []), edge.id]);
      incoming.set(edge.target, [...(incoming.get(edge.target) || []), edge.id]);
      if (selectedNodeId && (edge.source === selectedNodeId || edge.target === selectedNodeId)) {
        relatedEdgeIds.add(edge.id);
        relatedNodeIds.add(edge.source);
        relatedNodeIds.add(edge.target);
      }
    }

    if (selectedNodeId) relatedNodeIds.add(selectedNodeId);

    return {
      outgoing,
      incoming,
      relatedNodeIds,
      relatedEdgeIds,
    };
  }, [graph, selectedNodeId]);

  const selectedOutgoing = useMemo(
    () => graph?.edges.filter(edge => edge.source === selectedNodeId) || [],
    [graph, selectedNodeId]
  );

  const selectedIncoming = useMemo(
    () => graph?.edges.filter(edge => edge.target === selectedNodeId) || [],
    [graph, selectedNodeId]
  );

  const clampZoom = (value: number) => Math.min(zoomMax, Math.max(zoomMin, Number(value.toFixed(2))));

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
        <div className="border-b border-slate-100 p-4 grid grid-cols-1 md:grid-cols-[1fr_120px_140px] gap-3">
          <label className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              value={search}
              onChange={event => onSearchChange(event.target.value)}
              placeholder="Search package..."
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
          <span className="text-slate-500">Click a node to focus edges and view details.</span>
          <div className="ml-auto flex items-center gap-2 text-slate-600">
            <span className="font-semibold">Zoom</span>
            <button
              type="button"
              onClick={() => setZoom(current => clampZoom(current - zoomStep))}
              className="rounded-md border border-slate-200 bg-white px-2.5 py-1 text-sm font-semibold hover:bg-slate-50"
              aria-label="Zoom out"
            >
              -
            </button>
            <button
              type="button"
              onClick={() => setZoom(1)}
              className="rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-semibold hover:bg-slate-50"
              aria-label="Reset zoom"
            >
              {Math.round(zoom * 100)}%
            </button>
            <button
              type="button"
              onClick={() => setZoom(current => clampZoom(current + zoomStep))}
              className="rounded-md border border-slate-200 bg-white px-2.5 py-1 text-sm font-semibold hover:bg-slate-50"
              aria-label="Zoom in"
            >
              +
            </button>
          </div>
        </div>

        <div className="relative h-[680px] bg-slate-50">
          <div className="h-full overflow-auto">
            {loading ? (
              <div className="p-10 text-center text-slate-500">Loading graph...</div>
            ) : !graph || graph.nodes.length === 0 ? (
              <div className="p-10 text-center text-slate-500">No snapshot graph available.</div>
            ) : (
              <svg width={bounds.width} height={bounds.height} className="block">
                <defs>
                  <marker id="arrow-active" markerWidth="8" markerHeight="8" refX="7" refY="3.5" orient="auto" markerUnits="strokeWidth">
                    <path d="M0,0 L0,7 L7,3.5 z" fill="#2563eb" />
                  </marker>
                  <marker id="arrow-cycle" markerWidth="8" markerHeight="8" refX="7" refY="3.5" orient="auto" markerUnits="strokeWidth">
                    <path d="M0,0 L0,7 L7,3.5 z" fill="#e11d48" />
                  </marker>
                  <filter id="node-shadow" x="-20%" y="-20%" width="140%" height="140%">
                    <feDropShadow dx="0" dy="8" stdDeviation="6" floodColor="#0f172a" floodOpacity="0.18" />
                  </filter>
                </defs>
                <g transform={`scale(${zoom})`}>
                  {graph.edges.map(edge => {
                    const source = nodeMap.get(edge.source);
                    const target = nodeMap.get(edge.target);
                    if (!source || !target) return null;

                    const sourceEdges = edgeMeta.outgoing.get(edge.source) || [];
                    const targetEdges = edgeMeta.incoming.get(edge.target) || [];
                    const sourceIndex = Math.max(0, sourceEdges.indexOf(edge.id));
                    const targetIndex = Math.max(0, targetEdges.indexOf(edge.id));
                    const sourceFan = (sourceIndex - (sourceEdges.length - 1) / 2) * 10;
                    const targetFan = (targetIndex - (targetEdges.length - 1) / 2) * 10;
                    const x1 = source.x + bounds.offsetX + nodeWidth;
                    const y1 = source.y + bounds.offsetY + nodeHeight / 2 + sourceFan;
                    const x2 = target.x + bounds.offsetX - 14;
                    const y2 = target.y + bounds.offsetY + nodeHeight / 2 + targetFan;
                    const gap = Math.max(110, x2 - x1);
                    const bendX = x1 + gap * 0.52;
                    const emphasized = selectedNodeId ? edgeMeta.relatedEdgeIds.has(edge.id) : false;
                    const muted = selectedNodeId ? !emphasized : false;
                    const stroke = edge.hasCycle ? '#e11d48' : emphasized ? '#2563eb' : '#64748b';

                    return (
                      <path
                        key={edge.id}
                        d={`M ${x1} ${y1} C ${bendX} ${y1}, ${bendX} ${y2}, ${x2} ${y2}`}
                        fill="none"
                        stroke={stroke}
                        strokeWidth={emphasized ? 2.4 : edge.hasCycle ? 1.8 : 1.2}
                        strokeOpacity={muted ? 0.04 : emphasized ? 0.9 : edge.hasCycle ? 0.34 : 0.2}
                        strokeDasharray={edge.hasCycle ? '6 6' : undefined}
                        markerEnd={emphasized ? (edge.hasCycle ? 'url(#arrow-cycle)' : 'url(#arrow-active)') : undefined}
                      />
                    );
                  })}

                  {graph.nodes.map(node => {
                    const selected = selectedNodeId === node.id;
                    const related = !selectedNodeId || edgeMeta.relatedNodeIds.has(node.id);
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${node.x + bounds.offsetX}, ${node.y + bounds.offsetY})`}
                        onClick={() => setSelectedNodeId(node.id)}
                        className="cursor-pointer"
                        opacity={related ? 1 : 0.24}
                        filter={selected ? 'url(#node-shadow)' : undefined}
                      >
                        <rect
                          width={nodeWidth}
                          height={nodeHeight}
                          rx={8}
                          className={node.type === 'PROJECT' ? 'fill-slate-900 stroke-slate-900' : riskClass[node.riskLevel]}
                          strokeWidth={selected ? 3 : related ? 1.4 : 1}
                          stroke={selected ? '#2563eb' : undefined}
                        />
                        <text x={14} y={23} className={node.type === 'PROJECT' ? 'fill-white text-sm font-semibold' : 'fill-slate-800 text-sm font-semibold'}>
                          {wrapLabel(node.label).map((line, index) => (
                            <tspan key={line + index} x={14} dy={index === 0 ? 0 : 16}>
                              {line}
                            </tspan>
                          ))}
                        </text>
                        <text x={14} y={62} className={node.type === 'PROJECT' ? 'fill-slate-300 text-xs' : 'fill-slate-500 text-xs'}>
                          {node.type} - depth {node.depth} - CVE {node.vulnerabilityCount}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>
            )}
          </div>

          {selectedNode && (
            <aside className="absolute right-4 top-4 z-10 w-[min(380px,calc(100%-2rem))] max-h-[calc(100%-2rem)] overflow-auto rounded-lg border border-slate-200 bg-white/95 p-4 shadow-xl backdrop-blur">
              <div className="mb-3 flex items-start justify-between gap-3">
                <div>
                  <p className="text-xs font-bold uppercase tracking-wide text-slate-400">Node detail</p>
                  <h3 className="mt-1 break-all text-sm font-bold text-slate-900">{selectedNode.label}</h3>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedNodeId(null)}
                  className="rounded-md border border-slate-200 p-1.5 text-slate-500 hover:bg-slate-50 hover:text-slate-800"
                  aria-label="Close node detail"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="mb-3 flex flex-wrap gap-2">
                <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${riskBadge[selectedNode.riskLevel]}`}>
                  {selectedNode.riskLevel}
                </span>
                <span className="rounded-md border border-slate-200 px-2 py-1 text-xs text-slate-600">{selectedNode.ecosystem}</span>
                <span className="rounded-md border border-slate-200 px-2 py-1 text-xs text-slate-600">CVE {selectedNode.vulnerabilityCount}</span>
              </div>

              <dl className="grid grid-cols-[84px_1fr] gap-x-3 gap-y-2 text-xs text-slate-600">
                <dt className="font-semibold text-slate-500">Version</dt>
                <dd className="break-all">{selectedNode.version || '-'}</dd>
                <dt className="font-semibold text-slate-500">License</dt>
                <dd className="break-all">{selectedNode.license || '-'}</dd>
                <dt className="font-semibold text-slate-500">Supplier</dt>
                <dd className="break-all">{selectedNode.supplier || '-'}</dd>
                <dt className="font-semibold text-slate-500">PURL</dt>
                <dd className="break-all">{selectedNode.purl || '-'}</dd>
              </dl>

              {selectedNode.vulnerabilities && selectedNode.vulnerabilities.length > 0 && (
                <div className="mt-4">
                  <p className="mb-2 text-xs font-bold uppercase tracking-wide text-slate-400">Vulnerabilities</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedNode.vulnerabilities.slice(0, 8).map((vuln, index) => (
                      <span key={`${vuln.id}-${index}`} className="rounded-md border border-rose-100 bg-rose-50 px-2 py-1 text-xs text-rose-700">
                        {vuln.id || 'UNKNOWN'} {vuln.severity ? `- ${vuln.severity}` : ''}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="mt-4 grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
                <div>
                  <p className="mb-1 font-semibold text-slate-700">Depends on</p>
                  <ul className="max-h-32 space-y-1 overflow-auto rounded-md border border-slate-100 bg-slate-50 p-2 text-slate-600">
                    {selectedOutgoing.length === 0 ? (
                      <li className="text-slate-400">None</li>
                    ) : selectedOutgoing.map(edge => (
                      <li key={edge.id} className="break-all">{listLabel(nodeMap.get(edge.target), edge.target)}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <p className="mb-1 font-semibold text-slate-700">Depended by</p>
                  <ul className="max-h-32 space-y-1 overflow-auto rounded-md border border-slate-100 bg-slate-50 p-2 text-slate-600">
                    {selectedIncoming.length === 0 ? (
                      <li className="text-slate-400">None</li>
                    ) : selectedIncoming.map(edge => (
                      <li key={edge.id} className="break-all">{listLabel(nodeMap.get(edge.source), edge.source)}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </aside>
          )}
        </div>
      </div>
    </div>
  );
};

export default SbomDependencyGraph;
