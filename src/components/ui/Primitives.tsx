import { motion } from "motion/react";
import { ReactNode } from "react";
import { Verdict } from "@/src/types";

interface GlassCardProps {
  children: ReactNode;
  className?: string;
  id?: string;
}

export function GlassCard({ children, className = "", id }: GlassCardProps) {
  return (
    <motion.div
      id={id}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`glass-card relative group ${className}`}
    >
      <div className="scanline pointer-events-none" />
      <div className="absolute inset-0 bg-gradient-to-br from-electric/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
      <div className="relative z-10 p-6 h-full flex flex-col">
        {children}
      </div>
    </motion.div>
  );
}

interface BadgeProps {
  verdict: Verdict;
}

export function VerdictBadge({ verdict }: BadgeProps) {
  const normalizedVerdict = (verdict || "NOT_FOUND") as keyof typeof labels;

  const styles = {
    MALICIOUS_THREAT: "bg-red-500/20 text-red-400 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.3)]",
    SUSPICIOUS_ACTIVITY: "bg-amber-500/20 text-amber-400 border-amber-500/50 shadow-[0_0_15px_rgba(245,158,11,0.3)]",
    LEGIT_SIGNAL: "bg-emerald-500/20 text-emerald-400 border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.3)]",
    NOT_FOUND: "bg-slate-500/10 text-slate-400 border-slate-500/30",
  };

  const labels = {
    MALICIOUS_THREAT: "MALICIOUS",
    SUSPICIOUS_ACTIVITY: "SUSPICIOUS",
    LEGIT_SIGNAL: "CLEAN",
    NOT_FOUND: "NO DATA",
  };

  const dotColors = {
    MALICIOUS_THREAT: "bg-red-500",
    SUSPICIOUS_ACTIVITY: "bg-amber-500",
    LEGIT_SIGNAL: "bg-emerald-500",
    NOT_FOUND: "bg-slate-500",
  };

  const label = labels[normalizedVerdict] || String(verdict).replace(/_/g, ' ').toUpperCase();
  const style = styles[normalizedVerdict] || styles.NOT_FOUND;
  const dotColor = dotColors[normalizedVerdict] || dotColors.NOT_FOUND;

  return (
    <div className={`inline-flex items-center gap-2 px-2.5 py-1 border rounded-md text-[10px] font-black tracking-widest transition-all duration-300 ${style}`}>
      <div className={`w-2 h-2 rounded-full animate-pulse shrink-0 ${dotColor} shadow-[0_0_8px_currentColor]`} />
      <span className="leading-none">{label}</span>
    </div>
  );
}

export function PulseIndicator({ active = true, color = "bg-electric" }: { active?: boolean; color?: string }) {
  return (
    <div className="relative flex h-3 w-3">
      {active && (
        <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${color} opacity-75`}></span>
      )}
      <span className={`relative inline-flex rounded-full h-3 w-3 ${active ? color : 'bg-white/20'}`}></span>
    </div>
  );
}
