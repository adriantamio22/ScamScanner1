import React, { useState } from "react";
import { HistoryRecord } from "../types";
import { format } from "date-fns";
import { GlassCard, VerdictBadge } from "./ui/Primitives";
import { Clock, Search as SearchIcon, X } from "lucide-react";

interface HistorySidebarProps {
  history: HistoryRecord[];
  onSelect: (record: HistoryRecord) => void;
  onClear: () => void;
  onDelete: (id: string) => void;
}

export function HistorySidebar({ history, onSelect, onClear, onDelete }: HistorySidebarProps) {
  const [searchQuery, setSearchQuery] = useState("");

  const filteredHistory = history.filter((record) => {
    const query = searchQuery.toLowerCase();
    return (
      record.input.toLowerCase().includes(query) ||
      record.type.toLowerCase().includes(query) ||
      record.verdict.toLowerCase().includes(query)
    );
  });

  return (
    <GlassCard className="h-full flex flex-col gap-0 overflow-hidden" id="history-sidebar">
      {/* Header */}
      <div className="p-4 border-b border-white/5 bg-white/5">
        <div className="flex items-center justify-between gap-2 mb-4">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-electric" />
            <h2 className="text-sm font-bold tracking-tighter uppercase text-white/60">Case Records</h2>
          </div>
          {history.length > 0 && (
            <button 
              onClick={onClear}
              className="text-[9px] font-bold text-malicious/60 hover:text-malicious transition-colors uppercase tracking-widest px-2 py-1 border border-malicious/20 hover:border-malicious/40 rounded"
            >
              Clear
            </button>
          )}
        </div>

        {/* Search Bar */}
        <div className="relative group">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <SearchIcon className="h-3.5 w-3.5 text-white/20 group-focus-within:text-electric transition-colors" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="FILTER RECORDS..."
            className="w-full pl-9 pr-9 py-2 bg-black/40 border border-white/10 text-[10px] text-white focus:outline-none focus:border-electric/50 transition-all font-mono placeholder:text-white/10 uppercase tracking-wider"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-white/20 hover:text-white transition-colors"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Records Scrollable List */}
      <div className="flex-1 overflow-y-auto min-h-0 divide-y divide-white/5">
        {filteredHistory.length === 0 ? (
          <div className="text-[10px] text-white/20 italic p-8 text-center uppercase tracking-widest">
            {searchQuery ? "No matching records" : "No records found"}
          </div>
        ) : (
          filteredHistory.map((record) => (
            <div key={record.id} className="group relative border-b border-white/5 last:border-0">
              <button
                onClick={() => onSelect(record)}
                className="w-full text-left p-4 hover:bg-white/5 transition-colors relative overflow-hidden pr-12"
              >
                <div className="flex justify-between items-start mb-2">
                  <span className="text-[9px] px-1.5 py-0.5 bg-electric/10 border border-electric/20 font-bold text-electric uppercase tracking-tighter">{record.type}</span>
                  <span className="text-[9px] text-white/30 font-mono italic">{format(record.createdAt, "MMM dd HH:mm")}</span>
                </div>
                <div className="text-[11px] truncate mb-3 text-white/80 font-medium group-hover:text-white transition-colors">
                  {record.input}
                </div>
                <div className="flex justify-between items-center">
                  <VerdictBadge verdict={record.verdict} />
                  <div className="flex items-center gap-1.5">
                    <div className="w-12 h-1 bg-white/5 rounded-full overflow-hidden">
                      <div 
                        className={`h-full transition-all duration-1000 ${record.legitimacyPercentage > 70 ? 'bg-legit' : record.legitimacyPercentage > 30 ? 'bg-suspicious' : 'bg-malicious'}`}
                        style={{ width: `${record.legitimacyPercentage}%` }}
                      />
                    </div>
                    <span className="text-[9px] text-white/40 font-mono tracking-tighter">{record.legitimacyPercentage}%</span>
                  </div>
                </div>
                <div className="absolute inset-y-0 left-0 w-[2px] bg-electric opacity-0 group-hover:opacity-100 transition-opacity" />
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete(record.id);
                }}
                className="absolute top-1/2 -translate-y-1/2 right-3 p-2 text-white/10 hover:text-malicious hover:bg-malicious/10 rounded transition-all opacity-0 group-hover:opacity-100"
                title="Delete Record"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          ))
        )}
      </div>
      
      {/* Footer Info */}
      <div className="p-3 bg-black/40 border-t border-white/5 flex justify-between items-center">
        <span className="text-[8px] text-white/20 uppercase tracking-[0.2em] font-bold">
          {filteredHistory.length} Entry Found
        </span>
        <div className="flex gap-1">
           <div className="w-1 h-1 bg-electric/40 rounded-full animate-pulse" />
           <div className="w-1 h-1 bg-electric/20 rounded-full animate-pulse delay-75" />
           <div className="w-1 h-1 bg-electric/10 rounded-full animate-pulse delay-150" />
        </div>
      </div>
    </GlassCard>
  );
}
