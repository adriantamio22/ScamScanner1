export type ToolType = 'LOOKUP' | 'EMAIL' | 'IP' | 'WEBSITE' | 'EML' | 'MAILBOX';

export type Verdict = 'MALICIOUS_THREAT' | 'SUSPICIOUS_ACTIVITY' | 'LEGIT_SIGNAL' | 'NOT_FOUND';

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
  classification?: string;
  executiveSummary: string;
  forensicSignals: ForensicSignal[];
  sourcesChecked?: string[];
  limitations?: string[];
  createdAt: number;
  id: string;
}

export interface HistoryRecord {
  id: string;
  type: ToolType;
  input: string;
  verdict: Verdict;
  classification?: string;
  legitimacyPercentage: number;
  executiveSummary: string;
  forensicSignals: ForensicSignal[];
  sourcesChecked?: string[];
  limitations?: string[];
  createdAt: number;
}
