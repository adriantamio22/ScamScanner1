import React, { useState, useRef } from "react";
import { ToolType } from "../types";
import { Mail, Radar, Globe, Search, ArrowRight, MousePointer2, FileSearch, Upload, FileText } from "lucide-react";
import { GlassCard } from "./ui/Primitives";

interface ToolSelectorProps {
  onScan: (type: ToolType, input: string) => void;
  loading: boolean;
}

const TOOLS = [
  {
    type: 'LOOKUP' as ToolType,
    label: 'Threat & Hash Lookup',
    icon: Search,
    description: 'Comprehensive malware & entity intelligence. Analyzes hashes (SHA256/SHA1/MD5), domains, and URLs using VirusTotal and Microsoft Malware Intelligence.',
    placeholder: 'Enter Hash, Domain, URL, or IP...'
  },
  {
    type: 'EMAIL' as ToolType,
    label: 'Email Verifier',
    icon: Radar,
    description: 'Email forensics using Disify and VirusTotal. Checks delivery status, disposable status, and known malicious sender reputation.',
    placeholder: 'Enter email address to verify...'
  },
  {
    type: 'IP' as ToolType,
    label: 'IP Analysis',
    icon: Globe,
    description: 'Advanced IP reputation analysis using AbuseIPDB and VirusTotal. Detects malicious exit nodes, SOC alerts, and geolocation.',
    placeholder: 'Enter IP address or CIDR...'
  },
  {
    type: 'WEBSITE' as ToolType,
    label: 'Web Scanner',
    icon: MousePointer2,
    description: 'URL safety and WHOIS analysis. Scans for phishing templates, SSL validity, and domain age using VirusTotal.',
    placeholder: 'Enter URL or domain to scan (e.g. example.com)...'
  },
  {
    type: 'EML' as ToolType,
    label: 'EML Forensic',
    icon: FileSearch,
    description: 'Header forensics and MXToolbox analysis. Detects identity deception, spoofed hops, and malicious routing patterns.',
    placeholder: 'Drag EML file here or enter raw source...'
  }
];

export function ToolSelector({ onScan, loading }: ToolSelectorProps) {
  const [activeTool, setActiveTool] = useState<ToolType>('LOOKUP');
  const [inputValue, setInputValue] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const currentTool = TOOLS.find(t => t.type === activeTool)!;

  const handleInputChange = (val: string) => {
    setInputValue(val);
    const trimmed = val.trim();
    if (trimmed.length < 3) return;

    // Auto-routing logic
    // Email
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
      setActiveTool('EMAIL');
    }
    // IP (IPv4 or IPv6 basic)
    else if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/\d+)?$/.test(trimmed) || /^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$/.test(trimmed)) {
      setActiveTool('IP');
    }
    // Hash (MD5: 32, SHA1: 40, SHA256: 64)
    else if (/^[a-fA-F0-9]{32}$/.test(trimmed) || /^[a-fA-F0-9]{40}$/.test(trimmed) || /^[a-fA-F0-9]{64}$/.test(trimmed)) {
      setActiveTool('LOOKUP');
    }
    // URL (Starting with http or having a clear domain structure)
    else if (/^https?:\/\//.test(trimmed) || (/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(trimmed) && !trimmed.includes('@'))) {
      if (trimmed.includes('/') || trimmed.startsWith('http')) {
        setActiveTool('WEBSITE');
      } else {
        setActiveTool('LOOKUP'); // Naked domains often go to threat lookup
      }
    }
    // EML Detection
    else if (trimmed.length > 100 && (trimmed.toLowerCase().includes('received:') || trimmed.toLowerCase().includes('return-path:'))) {
      setActiveTool('EML');
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputValue.trim() && !loading) {
      onScan(activeTool, inputValue.trim());
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const processFile = (file: File) => {
    if (!file.name.endsWith('.eml') && !file.name.endsWith('.txt')) {
      alert("Please upload a .eml or .txt file containing email source.");
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (content) {
        setInputValue(`[FILE_NAME: ${file.name}]\n${content.substring(0, 5000)}`);
      }
    };
    reader.readAsText(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (activeTool === 'EML') setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (activeTool === 'EML') {
      const file = e.dataTransfer.files[0];
      if (file) processFile(file);
    }
  };

  return (
    <div className="space-y-4">
      {/* Tool Selector Buttons */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {TOOLS.map((tool) => (
          <button
            key={tool.type}
            onClick={() => {
              setActiveTool(tool.type);
              setInputValue("");
            }}
            className={`flex flex-col items-center gap-3 p-4 border transition-all relative overflow-hidden group ${
              activeTool === tool.type 
                ? 'border-electric bg-electric/10 text-white' 
                : 'border-white/10 bg-white/5 text-white/40 hover:border-white/30 hover:bg-white/[0.07]'
            }`}
          >
            <tool.icon className={`w-6 h-6 ${activeTool === tool.type ? 'text-electric' : 'group-hover:text-white/60'}`} />
            <span className="text-[10px] font-bold uppercase tracking-wider text-center">{tool.label}</span>
            {activeTool === tool.type && (
              <div className="absolute top-0 right-0 p-1">
                <div className="w-1 h-1 rounded-full bg-electric animate-pulse" />
              </div>
            )}
          </button>
        ))}
      </div>

      {/* Input Field */}
      <GlassCard 
        className={`border-electric/30 transition-shadow duration-300 ${isDragging ? 'ring-2 ring-electric shadow-[0_0_20px_rgba(0,242,255,0.2)]' : ''}`}
        id="input-card"
      >
        <form 
          onSubmit={handleSubmit} 
          className="space-y-4"
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-bold uppercase tracking-widest text-electric">{activeTool} ANALYZER</h3>
              {activeTool === 'EML' && (
                <span className="text-[8px] bg-electric/20 text-electric px-1 py-0.5 rounded border border-electric/30 font-bold">DRAG & DROP SUPPORTED</span>
              )}
            </div>
            <span className="text-[9px] text-white/30 font-mono">STATUS: OPERATIONAL</span>
          </div>
          
          <p className="text-[10px] text-white/50 mb-4">{currentTool.description}</p>

          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 pt-3 flex items-start pointer-events-none">
              {activeTool === 'EML' ? <FileText className="h-4 w-4 text-white/20" /> : <Search className="h-4 w-4 text-white/20" />}
            </div>
            
            {activeTool === 'EML' ? (
              <div className="flex flex-col gap-3">
                <textarea
                  value={inputValue}
                  onChange={(e) => handleInputChange(e.target.value)}
                  placeholder={currentTool.placeholder}
                  className="block w-full pl-10 pr-12 py-4 bg-black/50 border border-white/10 text-white text-sm focus:outline-none focus:border-electric transition-colors font-mono placeholder:text-white/10 min-h-[120px] resize-none"
                  disabled={loading}
                />
                <div className="flex justify-between items-center bg-white/5 p-3 border border-dashed border-white/10">
                  <div className="text-[9px] text-white/40 uppercase font-bold flex items-center gap-2">
                    <Upload className="w-3 h-3" />
                    Drop .eml or .txt case file here
                  </div>
                  <button 
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="text-[9px] font-bold text-electric hover:text-white transition-colors uppercase border-b border-electric/30 pb-0.5"
                  >
                    Select Local File
                  </button>
                  <input 
                    type="file" 
                    ref={fileInputRef} 
                    className="hidden" 
                    accept=".eml,.txt" 
                    onChange={handleFileChange} 
                  />
                </div>
              </div>
            ) : (
              <input
                type="text"
                value={inputValue}
                onChange={(e) => handleInputChange(e.target.value)}
                placeholder={currentTool.placeholder}
                className="block w-full pl-10 pr-12 py-4 bg-black/50 border border-white/10 text-white text-sm focus:outline-none focus:border-electric transition-colors font-mono placeholder:text-white/10"
                disabled={loading}
              />
            )}
            
            <button
              type="submit"
              disabled={!inputValue.trim() || loading}
              className={`absolute right-1.5 px-4 bg-electric text-black hover:bg-electric/80 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-2 group font-bold text-[10px] uppercase tracking-tighter ${activeTool === 'EML' ? 'bottom-16 py-3' : 'inset-y-1.5'}`}
            >
              Initialize {loading && <div className="w-3 h-3 border-2 border-black/30 border-t-black animate-spin rounded-full" />}
              <ArrowRight className="w-3 h-3 group-hover:translate-x-1 transition-transform" />
            </button>
          </div>
        </form>
      </GlassCard>
    </div>
  );
}
