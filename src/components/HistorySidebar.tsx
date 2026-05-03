import { HistoryRecord } from "../types";
import { format } from "date-fns";
import { GlassCard, VerdictBadge } from "./ui/Primitives";
import { Clock, Search } from "lucide-react";

interface HistorySidebarProps {
  history: HistoryRecord[];
  onSelect: (record: HistoryRecord) => void;
}

export function HistorySidebar({ history, onSelect }: HistorySidebarProps) {
  return (
    <GlassCard className="h-full flex flex-col gap-4 overflow-hidden" id="history-sidebar">
      <div className="flex items-center gap-2 mb-2">
        <Clock className="w-4 h-4 text-electric" />
        <h2 className="text-sm font-bold tracking-tighter uppercase text-white/60">Case Records</h2>
      </div>

      <div className="flex-1 overflow-y-auto space-y-2 pr-2 scrollbar-thin scrollbar-thumb-white/10">
        {history.length === 0 ? (
          <div className="text-[10px] text-white/30 italic p-4 text-center border border-dashed border-white/10 rounded">
            No records found in database.
          </div>
        ) : (
          history.map((record) => (
            <button
              key={record.id}
              onClick={() => onSelect(record)}
              className="w-full text-left p-3 border border-white/10 hover:border-electric/50 transition-colors group relative overflow-hidden bg-white/5"
            >
              <div className="flex justify-between items-start mb-1">
                <span className="text-[10px] font-bold text-electric opacity-70 uppercase">{record.type}</span>
                <span className="text-[9px] text-white/40">{format(record.createdAt, "HH:mm:ss")}</span>
              </div>
              <div className="text-[11px] truncate mb-2 text-white/90 font-medium">{record.input}</div>
              <div className="flex justify-between items-center">
                <VerdictBadge verdict={record.verdict} />
                <span className="text-[10px] text-white/40 font-mono">{record.legitimacyPercentage}%</span>
              </div>
              <div className="absolute inset-0 bg-electric/5 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
            </button>
          ))
        )}
      </div>
    </GlassCard>
  );
}
