export type ToolType = 'MAILBOX' | 'EMAIL' | 'IP' | 'WEBSITE' | 'EML';

export type Verdict = 'MALICIOUS_THREAT' | 'SUSPICIOUS_ACTIVITY' | 'LEGIT_SIGNAL';

export interface ForensicSignal {
  name: string;
  severity: 'CRITICAL' | 'WARNING' | 'INFO';
  description: string;
}

export interface ScanResult {
  userId: string;
  type: ToolType;
  input: string;
  legitimacyPercentage: number;
  verdict: Verdict;
  executiveSummary: string;
  forensicSignals: ForensicSignal[];
  createdAt: number;
  id: string;
}

export interface HistoryRecord {
  id: string;
  type: ToolType;
  input: string;
  verdict: Verdict;
  legitimacyPercentage: number;
  createdAt: number;
}
