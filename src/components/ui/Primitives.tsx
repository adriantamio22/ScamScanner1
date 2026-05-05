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
  const styles = {
    MALICIOUS_THREAT: "bg-malicious/20 text-malicious border-malicious/30",
    SUSPICIOUS_ACTIVITY: "bg-suspicious/20 text-suspicious border-suspicious/30",
    LEGIT_SIGNAL: "bg-legit/20 text-legit border-legit/30",
    NOT_FOUND: "bg-white/10 text-white/40 border-white/20",
  };

  const labels = {
    MALICIOUS_THREAT: "MALICIOUS THREAT",
    SUSPICIOUS_ACTIVITY: "SUSPICIOUS ACTIVITY",
    LEGIT_SIGNAL: "LEGIT SIGNAL",
    NOT_FOUND: "NOT FOUND",
  };

  return (
    <span className={`px-2 py-1 border text-[10px] font-bold tracking-widest ${styles[verdict]}`}>
      {labels[verdict]}
    </span>
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
