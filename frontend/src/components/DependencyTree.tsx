import React from 'react';
import { type Dependency, type SBOMComponent } from '../types/sbom';
import { Network, Box, CornerDownRight } from 'lucide-react';

interface Props {
  dependencies: Dependency[];
  components: SBOMComponent[];
}

const DependencyTree: React.FC<Props> = ({ dependencies, components }) => {
  // Build a map of components by purl or component_id for quick lookup
  const componentMap = new Map<string, SBOMComponent>();
  components.forEach(c => {
    if (c.purl) componentMap.set(c.purl, c);
    componentMap.set(c.component_id, c);
  });

  const getComponentName = (ref: string) => {
    const comp = componentMap.get(ref);
    return comp ? `${comp.name} 
      ${comp.version ? `(v${comp.version})` : ''}` : ref;
  };

  // Group dependencies
  const structure = new Map<string, string[]>();
  dependencies.forEach(d => {
    const arr = structure.get(d.component_ref) || [];
    arr.push(d.depends_on_ref);
    structure.set(d.component_ref, arr);
  });

  const topLevelDeps = Array.from(structure.keys());

  return (
    <div className="p-5">
      {topLevelDeps.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-10 text-slate-400">
          <Network className="w-10 h-10 mb-3 opacity-20 text-slate-500" />
          <p className="text-sm font-medium">Không tìm thấy thông tin phụ thuộc.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {topLevelDeps.map(ref => (
            <div key={ref} className="bg-slate-50/50 rounded-md border border-slate-200 p-4">
              <div className="flex items-center gap-2 font-semibold text-slate-800 mb-3">
                <Box className="w-4 h-4 text-blue-500" />
                <span className="break-all">{getComponentName(ref)}</span>
              </div>
              <div className="pl-6 space-y-2">
                {structure.get(ref)?.map(target => (
                  <div key={target} className="flex items-start gap-2 text-sm text-slate-600">
                    <CornerDownRight className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                    <span className="break-all">{getComponentName(target)}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default DependencyTree;
