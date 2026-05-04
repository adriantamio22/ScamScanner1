import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { GlassCard } from './Primitives';
import { AlertTriangle, X } from 'lucide-react';

interface ConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  type?: 'warning' | 'danger' | 'info';
}

export const ConfirmModal: React.FC<ConfirmModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  type = "warning"
}) => {
  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
          />

          {/* Modal Content */}
          <motion.div
            initial={{ scale: 0.9, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.9, opacity: 0, y: 20 }}
            transition={{ type: "spring", damping: 25, stiffness: 300 }}
            className="relative w-full max-w-md z-10"
          >
            <GlassCard className="border-electric/30 shadow-[0_0_50px_rgba(0,242,255,0.15)]">
              <div className="p-6 space-y-6">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-malicious/10 rounded-lg border border-malicious/20">
                      <AlertTriangle className="w-6 h-6 text-malicious" />
                    </div>
                    <h3 className="text-xl font-black tracking-tighter text-white uppercase italic">{title}</h3>
                  </div>
                  <button 
                    onClick={onClose}
                    className="p-1 hover:bg-white/10 rounded-full transition-colors"
                  >
                    <X className="w-5 h-5 text-white/50" />
                  </button>
                </div>

                <div className="space-y-4">
                  <div className="p-4 bg-black/40 border border-white/5 rounded-xl">
                    <p className="text-sm text-white/70 leading-relaxed font-medium">
                      {message}
                    </p>
                  </div>

                  <div className="flex gap-3 pt-2">
                    <button
                      onClick={onClose}
                      className="flex-1 px-4 py-3 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl text-[10px] font-black uppercase tracking-widest text-white transition-all active:scale-95"
                    >
                      {cancelLabel}
                    </button>
                    <button
                      onClick={() => {
                        onConfirm();
                        onClose();
                      }}
                      className="flex-1 px-4 py-3 bg-malicious/20 hover:bg-malicious/30 border border-malicious/40 rounded-xl text-[10px] font-black uppercase tracking-widest text-malicious shadow-[0_0_20px_rgba(255,59,48,0.2)] transition-all active:scale-95"
                    >
                      {confirmLabel}
                    </button>
                  </div>
                </div>

                {/* Aesthetic status line */}
                <div className="flex justify-between items-center pt-4 border-t border-white/5 font-mono">
                  <span className="text-[7px] text-white/20 uppercase tracking-widest">Auth_Protocol_Interrupt</span>
                  <div className="h-[1px] flex-1 mx-4 bg-white/5" />
                  <span className="text-[7px] text-malicious/50 font-bold uppercase tracking-widest">Status: Waiting_User_Input</span>
                </div>
              </div>
            </GlassCard>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};
