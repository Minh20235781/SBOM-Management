import React from 'react';
import { type SBOMComponent } from '../types/sbom';

interface Props {
  components: SBOMComponent[];
}

const ComponentTable: React.FC<Props> = ({ components }) => {
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
      <table className="w-full text-left text-sm text-slate-700">
        <thead className="bg-slate-50 text-xs uppercase text-slate-500">
          <tr>
            <th className="px-6 py-4 font-semibold">STT</th>
            <th className="px-6 py-4 font-semibold">Tên thành phần</th>
            <th className="px-6 py-4 font-semibold">Phiên bản</th>
            <th className="px-6 py-4 font-semibold">Giấy phép</th>
            <th className="px-6 py-4 font-semibold">PURL</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {components.map((c, idx) => (
            <tr key={c.component_id} className="hover:bg-slate-50/50 transition-colors">
              <td className="px-6 py-4 font-mono text-slate-700">{idx + 1}</td>
              <td className="px-6 py-4 font-medium text-slate-800">{c.name}</td>
              <td className="px-6 py-4">{c.version || 'N/A'}</td>
              <td className="px-6 py-4">
                <span className="px-2.5 py-1 bg-slate-100 text-slate-600 rounded-md text-xs font-medium border border-slate-200">
                  {c.licenses || 'Unknown'}
                </span>
              </td>
              <td className="px-6 py-4 truncate max-w-[200px] text-slate-400 font-mono text-xs" title={c.purl}>
                {c.purl || '-'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ComponentTable;