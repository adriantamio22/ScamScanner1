import { ScanResult } from "../types";
import { GlassCard, VerdictBadge, PulseIndicator } from "./ui/Primitives";
import { Radar, AlertTriangle, CheckCircle, Info, ChevronRight, Activity, Search } from "lucide-react";
import { motion } from "motion/react";

interface ResultsDisplayProps {
  result: ScanResult | null;
  loading: boolean;
  error?: string | null;
}

export function ResultsDisplay({ result, loading, error }: ResultsDisplayProps) {
  if (loading) {
    return (
      <GlassCard className="h-full flex items-center justify-center min-h-[300px]">
        <div className="flex flex-col items-center gap-4">
          <div className="relative">
            <Activity className="w-12 h-12 text-electric animate-pulse" />
            <div className="absolute inset-0 bg-electric/20 blur-xl animate-pulse" />
          </div>
          <div className="text-electric text-xs font-bold tracking-[0.2em] animate-pulse">ANALYZING SIGNALS...</div>
        </div>
      </GlassCard>
    );
  }

  if (error) {
    return (
      <GlassCard className="h-full flex items-center justify-center border-malicious/30 bg-malicious/5 min-h-[300px]">
        <div className="text-center space-y-4 p-8">
          <div className="relative inline-block">
            <AlertTriangle className="w-12 h-12 mx-auto text-malicious" />
            <div className="absolute inset-0 bg-malicious/20 blur-xl" />
          </div>
          <div className="space-y-2">
            <p className="text-[10px] uppercase font-bold tracking-widest text-malicious">Diagnostic Failure</p>
            <p className="text-xs text-white/70 max-w-md mx-auto font-mono bg-black/40 p-4 border border-malicious/20 rounded">
              {error}
            </p>
            <p className="text-[9px] text-white/30 uppercase mt-4">
              Check API status and environmental authentication tokens.
            </p>
          </div>
        </div>
      </GlassCard>
    );
  }

  if (!result) {
    return (
      <GlassCard className="h-full flex items-center justify-center border-dashed min-h-[300px]">
        <div className="text-center space-y-2 opacity-30">
          <Radar className="w-12 h-12 mx-auto mb-4 animate-pulse" />
          <p className="text-[10px] uppercase font-bold tracking-widest">Awaiting Forensic Input</p>
          <p className="text-[9px] max-w-[200px] mx-auto">Select a diagnostic tool and provide parameters to initialize scan protocol.</p>
        </div>
      </GlassCard>
    );
  }

  return (
    <GlassCard className="h-full" id="results-display">
      <div className="flex flex-col h-full">
        {/* Header Section */}
        <div className="flex justify-between items-start mb-6 border-b border-white/5 pb-6">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold text-electric bg-electric/20 border border-electric/30 px-2 py-0.5 rounded-sm">CASE_ID_{result.id.slice(0, 8).toUpperCase()}</span>
              <VerdictBadge verdict={result.verdict} />
              {result.classification && (
                 <div className="flex items-center gap-1.5 px-2 py-0.5 bg-white/5 border border-white/10 rounded-sm">
                   <div className="w-1 h-1 bg-white/30 rounded-full" />
                   <span className="text-[9px] font-mono uppercase tracking-tighter text-white/50">
                     TARGET: <span className="text-electric/80 font-bold">{result.classification}</span>
                   </span>
                 </div>
              )}
            </div>
            <h2 className="text-2xl font-black tracking-tighter text-white truncate max-w-2xl">
              {result.input}
            </h2>
          </div>
          <div className="text-right">
            <div className="text-[10px] text-white/40 uppercase mb-1">Legitimacy Score</div>
            <div 
              className={`text-4xl font-black tracking-tighter ${
                result.legitimacyPercentage > 70 ? 'text-emerald-400' : 
                result.legitimacyPercentage > 30 ? 'text-amber-400' : 
                'text-red-400'
              }`}
            >
              {result.legitimacyPercentage}<span className="text-sm opacity-50">%</span>
            </div>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-3">
            <PulseIndicator active={true} />
            <h3 className="text-xs font-bold uppercase tracking-widest text-white/60">Executive Summary</h3>
          </div>
          <p className="text-sm leading-relaxed text-white/80 border-l-2 border-electric/30 pl-4 py-1 italic bg-white/5 rounded-r">
            {result.executiveSummary}
          </p>
        </div>

        {/* Forensic Signals */}
        <div className="flex-1 overflow-y-auto pr-2">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-electric" />
            <h3 className="text-xs font-bold uppercase tracking-widest text-white/60">Forensic Signals</h3>
          </div>
          
          <div className="grid gap-3">
            {result.forensicSignals.map((signal, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.1 }}
                className="p-3 border border-white/5 bg-white/5 rounded flex gap-3 group hover:border-white/20 transition-colors"
              >
                <div className="mt-0.5">
                  {signal.severity === 'CRITICAL' ? (
                    <AlertTriangle className="w-4 h-4 text-malicious" />
                  ) : signal.severity === 'WARNING' ? (
                    <AlertTriangle className="w-4 h-4 text-suspicious" />
                  ) : (
                    <Info className="w-4 h-4 text-legit" />
                  )}
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[11px] font-bold text-white/90">{signal.name}</span>
                    <span className={`text-[8px] px-1 py-0 border rounded leading-none ${
                      signal.severity === 'CRITICAL' ? 'border-malicious/50 text-malicious' :
                      signal.severity === 'WARNING' ? 'border-suspicious/50 text-suspicious' :
                      'border-legit/50 text-legit'
                    }`}>
                      {signal.severity}
                    </span>
                  </div>
                  <p className="text-[10px] text-white/50 leading-normal">{signal.description}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </GlassCard>
  );
}
