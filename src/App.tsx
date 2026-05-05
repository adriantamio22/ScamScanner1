/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from "react";
import { ToolType, ScanResult, HistoryRecord } from "./types";
import { performForensicAnalysis, checkApiStatus } from "./services/geminiService";
import { HistorySidebar } from "./components/HistorySidebar";
import { ResultsDisplay } from "./components/ResultsDisplay";
import { ToolSelector } from "./components/ForensicTool";
import { motion, AnimatePresence } from "motion/react";
import { Shield, Lock, Cpu, Mail, Key, Radar, Search, Fingerprint, Activity } from "lucide-react";
import { PulseIndicator } from "./components/ui/Primitives";
import { ConfirmModal } from "./components/ui/ConfirmModal";
import { auth, db, googleProvider } from "@/src/lib/firebase";
import { 
  onAuthStateChanged, 
  signInWithEmailAndPassword, 
  createUserWithEmailAndPassword, 
  signInWithPopup,
  signOut,
  User
} from "firebase/auth";
import { 
  collection, 
  query, 
  orderBy, 
  onSnapshot, 
  doc, 
  setDoc,
  deleteDoc,
  getDocs,
  serverTimestamp,
  getDocFromServer
} from "firebase/firestore";
import { handleFirestoreError, OperationType } from "@/src/lib/firestoreUtils";
import { sendPasswordResetEmail } from "firebase/auth";

// Helper to map Firebase Auth errors to theme-friendly messages
const formatAuthError = (error: any) => {
  const code = error.code || "";
  switch (code) {
    case 'auth/user-not-found':
      return "IDENT_FAILURE: Investigator profile not found in forensic database.";
    case 'auth/wrong-password':
      return "ACCESS_DENIED: Invalid authorization key provided.";
    case 'auth/invalid-email':
      return "IDENT_PROTOCOL_ERROR: Malformed mailbox address.";
    case 'auth/email-already-in-use':
      return "IDENT_CONFLICT: Identity already registered in database.";
    case 'auth/user-disabled':
      return "SECURITY_BREACH: Access revoked. Profile decommissioned.";
    case 'auth/too-many-requests':
      return "PROTECTION_LOCK: Brute-force protection active. Try later.";
    case 'auth/invalid-credential':
      return "ACCESS_DENIED: Invalid investigator credentials or profile mismatch.";
    case 'auth/operation-not-allowed':
      return "PROTOCOL_DISABLED: Email auth protocol not enabled in lab console.";
    case 'auth/weak-password':
      return "SECURITY_WARNING: Password strength below forensic standard.";
    case 'auth/account-exists-with-different-credential':
      return "IDENT_CONFLICT: Account linked to another auth provider (Google).";
    case 'auth/user-mismatch':
      return "PROTOCOL_ERROR: Credential mismatch detected.";
    default:
      // Remove the prefix "Firebase: Error (auth/..." from the default message if possible
      const cleanMsg = error.message?.replace(/Firebase: Error \(auth\//g, '').replace(/\)\./g, '') || "Unknown auth error.";
      return `SYSTEM_ERROR: ${cleanMsg}`;
  }
};

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
  const [isSignUp, setIsSignUp] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [authError, setAuthError] = useState("");
  const [authSuccess, setAuthSuccess] = useState("");
  const [portalStatus, setPortalStatus] = useState({ ok: true, status: "OPERATIONAL" });
  const [isLogoutConfirmOpen, setIsLogoutConfirmOpen] = useState(false);
  const [isClearHistoryConfirmOpen, setIsClearHistoryConfirmOpen] = useState(false);
  const [isDeleteCaseConfirmOpen, setIsDeleteCaseConfirmOpen] = useState(false);
  const [caseToDelete, setCaseToDelete] = useState<string | null>(null);

  // Listen for auth state changes
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (firebaseUser) => {
      // Clear results and history preview when user changes to prevent data leak
      setCurrentResult(null);
      setUser(firebaseUser);
    });

    // Test Firestore connection on boot
    const testConnection = async () => {
      try {
        await getDocFromServer(doc(db, 'test', 'connection'));
      } catch (error: any) {
        if(error?.message?.includes('the client is offline')) {
          console.error("Please check your Firebase configuration.");
        }
      }
    };
    testConnection();

    // Check Gemini API Status
    const updateApiStatus = async () => {
      const status = await checkApiStatus();
      setPortalStatus(status);
    };
    updateApiStatus();
    const statusInterval = setInterval(updateApiStatus, 120000); // Check every 2 mins

    return () => {
      unsubscribe();
      clearInterval(statusInterval);
    };
  }, []);

  // Sync history with Firestore
  useEffect(() => {
    if (!user) {
      setHistory([]);
      return;
    }

    const path = `users/${user.uid}/cases`;
    const q = query(collection(db, path), orderBy("createdAt", "desc"));
    
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const records: HistoryRecord[] = snapshot.docs.map(doc => {
        const data = doc.data();
        return {
          ...data as HistoryRecord,
          id: doc.id,
          // Handle Firestore Timestamp to number conversion
          createdAt: data.createdAt?.toMillis?.() || Date.now()
        };
      });
      setHistory(records);
    }, (error) => {
      handleFirestoreError(error, OperationType.LIST, path);
    });

    return () => unsubscribe();
  }, [user]);

  const saveToHistory = async (result: ScanResult) => {
    if (!user) return;
    
    const path = `users/${user.uid}/cases`;
    const docRef = doc(db, path, result.id);
    
    try {
      await setDoc(docRef, {
        userId: user.uid,
        type: result.type,
        input: result.input,
        verdict: result.verdict,
        legitimacyPercentage: result.legitimacyPercentage,
        executiveSummary: result.executiveSummary || "Analysis summary unavailable.",
        forensicSignals: result.forensicSignals || [],
        createdAt: serverTimestamp(),
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, `${path}/${result.id}`);
    }
  };

  const clearHistory = async () => {
    if (!user) return;
    setIsClearHistoryConfirmOpen(true);
  };

  const handleDeleteCase = (id: string) => {
    setCaseToDelete(id);
    setIsDeleteCaseConfirmOpen(true);
  };

  const confirmDeleteCase = async () => {
    if (!user || !caseToDelete) return;
    setLoading(true);
    const path = `users/${user.uid}/cases`;
    try {
      await deleteDoc(doc(db, path, caseToDelete));
      if (currentResult?.id === caseToDelete) {
        setCurrentResult(null);
      }
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, `${path}/${caseToDelete}`);
    } finally {
      setLoading(false);
      setCaseToDelete(null);
      setIsDeleteCaseConfirmOpen(false);
    }
  };

  const confirmClearHistory = async () => {
    if (!user) return;
    setLoading(true);
    const path = `users/${user.uid}/cases`;
    try {
      const q = query(collection(db, path));
      const querySnapshot = await getDocs(q);
      
      const deletePromises = querySnapshot.docs.map(document => 
        deleteDoc(doc(db, path, document.id))
      );
      
      await Promise.all(deletePromises);
      setCurrentResult(null);
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, path);
    } finally {
      setLoading(false);
    }
  };

  const handleScan = async (type: ToolType, input: string) => {
    setLoading(true);
    setError(null);
    try {
      const result = await performForensicAnalysis(type, input);
      setCurrentResult(result);
      if (user) {
        await saveToHistory(result);
      }
    } catch (err: any) {
      console.error("Scan failed", err);
      setError(err.message || "An unknown error occurred during forensic scan.");
    } finally {
      setLoading(false);
    }
  };

  const handleSelectHistory = (record: HistoryRecord) => {
    // Instant display from history
    setCurrentResult({
      ...record,
      userId: user?.uid || "anonymous"
    });
    // Scroll to top or ensure visible
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    setLoading(true);
    try {
      if (isSignUp) {
        await createUserWithEmailAndPassword(auth, email, password);
      } else {
        await signInWithEmailAndPassword(auth, email, password);
      }
      setIsLoginModalOpen(false);
      setEmail("");
      setPassword("");
      setAuthSuccess("");
    } catch (error: any) {
      setAuthError(formatAuthError(error));
      setAuthSuccess("");
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = async () => {
    if (!email) {
      setAuthError("Email address required for key recovery.");
      return;
    }
    setAuthError("");
    setAuthSuccess("");
    setLoading(true);
    try {
      // NOTE: Firebase sendPasswordResetEmail succeeds even if email doesn't exist 
      // due to 'Email Enumeration Protection' being enabled in the console.
      await sendPasswordResetEmail(auth, email);
      setAuthSuccess("Recovery protocol sent. If this identity exists in our records, a link will arrive shortly.");
    } catch (error: any) {
      setAuthError(formatAuthError(error));
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setAuthError("");
    setLoading(true);
    try {
      await signInWithPopup(auth, googleProvider);
      setIsLoginModalOpen(false);
    } catch (error: any) {
      setAuthError(formatAuthError(error));
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setIsLogoutConfirmOpen(true);
  };

  const confirmLogout = async () => {
    try {
      await signOut(auth);
    } catch (error) {
      console.error("Logout failed", error);
    }
  };

  return (
    <div className="min-h-screen p-4 md:p-8 flex flex-col gap-6 max-w-7xl mx-auto">
      {/* Header Bar */}
      <motion.header 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col md:flex-row justify-between items-center gap-4 border-b border-white/10 pb-6"
      >
        <div className="flex items-center gap-4 group cursor-pointer relative" onClick={() => window.location.reload()}>
          {/* Global Scanline Animation */}
          <div className="absolute inset-0 overflow-hidden rounded-2xl pointer-events-none z-30">
            <motion.div 
              animate={{ y: ["-100%", "200%"] }}
              transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
              className="absolute left-0 right-0 h-[2px] bg-electric/30 shadow-[0_0_15px_#00f2ff] opacity-0 group-hover:opacity-100 transition-opacity"
            />
            <motion.div 
              animate={{ y: ["-100%", "200%"] }}
              transition={{ duration: 4.5, repeat: Infinity, ease: "linear", delay: 0.5 }}
              className="absolute left-0 right-0 h-[1px] bg-electric/10 shadow-[0_0_10px_#00f2ff] opacity-40 group-hover:opacity-70 transition-opacity"
            />
          </div>

          <div className="relative">
            <div className="absolute -inset-4 bg-electric/20 blur-2xl rounded-full group-hover:bg-electric/40 transition-all duration-700 animate-pulse"></div>
            <div className="relative p-4 bg-black/80 backdrop-blur-xl border-2 border-electric/40 rounded-2xl group-hover:border-electric group-hover:scale-105 transition-all shadow-[0_0_25px_rgba(0,242,255,0.2)] group-hover:shadow-[0_0_40px_rgba(0,242,255,0.4)] overflow-hidden">
              <div className="absolute inset-0 opacity-20 group-hover:opacity-40 transition-opacity">
                <Radar className="w-full h-full text-electric animate-[spin_10s_linear_infinite]" />
              </div>
              <div className="absolute inset-0 flex items-center justify-center">
                 <motion.div 
                   animate={{ scale: [1, 1.5, 1], opacity: [0.3, 0.7, 0.3] }}
                   transition={{ duration: 3, repeat: Infinity }}
                   className="w-12 h-12 bg-electric/10 rounded-full"
                 />
              </div>
              <Radar className="w-10 h-10 text-electric relative z-10 drop-shadow-[0_0_10px_#00f2ff] animate-pulse" />
            </div>
          </div>
          <div className="relative z-10">
            <h1 className="text-4xl font-black tracking-tighter text-white flex items-baseline gap-2 group-hover:text-electric transition-colors">
              SCAM<span className="text-electric">SCANNER</span>
              <div className="flex flex-col">
                <div className="flex items-center gap-1">
                  <span className="text-[10px] px-1.5 py-0.5 bg-electric/10 border border-electric/30 text-electric rounded uppercase tracking-[0.2em] font-mono group-hover:border-electric transition-colors leading-none">CORE_v4</span>
                  <Activity className="w-3 h-3 text-electric animate-pulse" />
                </div>
                <span className="text-[7px] text-malicious/80 font-mono animate-pulse tracking-[0.1em] mt-1">THREAT_DETECTION: GLOBAL_ACTIVE</span>
              </div>
            </h1>
            <p className="text-[11px] text-white/40 uppercase tracking-[0.55em] font-black pl-1 mt-1">Advanced Email and Web Analyzer</p>
          </div>
        </div>

        <div className="flex items-center gap-6">
          {user ? (
            <div className="flex items-center gap-4 bg-white/5 border border-white/10 p-2 pl-4 rounded-lg">
              <div className="text-right">
                <div className="text-[9px] text-white/30 uppercase font-bold">Investigator Id</div>
                <div className="text-[10px] font-mono text-electric uppercase truncate max-w-[100px]">{user.email?.split('@')[0]}</div>
              </div>
              <button 
                onClick={logout}
                className="p-2 hover:bg-white/10 rounded-md transition-colors text-white/40 hover:text-malicious"
                title="Deauthorize Session"
              >
                <Lock className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <button 
              onClick={() => {
                setIsLoginModalOpen(true);
                setAuthError("");
              }}
              className="px-4 py-2 bg-electric text-black font-bold text-[10px] uppercase tracking-widest hover:bg-white transition-colors"
            >
              Initialize Identity
            </button>
          )}

          <div className="hidden lg:flex items-center gap-3 border-l border-white/10 pl-6">
            <div className="text-right mr-3">
              <div className="text-[9px] text-white/30 uppercase font-bold">Portal Status</div>
              <div className={`text-[10px] font-mono uppercase ${portalStatus.ok ? 'text-legit' : 'text-malicious'}`}>
                {portalStatus.status}
              </div>
            </div>
            <PulseIndicator active={true} color={portalStatus.ok ? "bg-legit" : "bg-malicious"} />
          </div>
        </div>
      </motion.header>

      {/* Main Bento Grid */}
      <main className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 pb-8">
        {/* Left Span: History (3 cols) */}
        <div className="lg:col-span-3 h-[600px] lg:max-h-[85vh] lg:sticky lg:top-8 order-2 lg:order-1 relative group">
          {!user && (
            <div className="absolute inset-0 bg-black/80 backdrop-blur-sm z-20 flex flex-col items-center justify-center p-6 text-center gap-4 rounded-xl border border-white/5">
              <Lock className="w-8 h-8 text-white/20" />
              <div className="space-y-1">
                <p className="text-[10px] font-bold uppercase tracking-widest text-white/40">History Locked</p>
                <p className="text-[9px] text-white/20">Authorization required to access legacy case files.</p>
              </div>
              <button 
                onClick={() => setIsLoginModalOpen(true)}
                className="text-[10px] font-bold text-electric hover:text-white underline underline-offset-4"
              >
                Sign In
              </button>
            </div>
          )}
          <HistorySidebar 
            history={history} 
            onSelect={handleSelectHistory} 
            onClear={clearHistory} 
            onDelete={handleDeleteCase}
          />
        </div>

        {/* Right Span: Tools & Results (9 cols) */}
        <div className="lg:col-span-9 flex flex-col gap-6 order-1 lg:order-2">
          <ToolSelector onScan={handleScan} loading={loading} />

          <div className="flex-1 min-h-[400px]">
            <AnimatePresence mode="wait">
              <motion.div
                key={currentResult?.id || error || 'idle'}
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                transition={{ duration: 0.2 }}
                className="h-full"
              >
                <ResultsDisplay result={currentResult} loading={loading} error={error} />
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </main>

      {/* Login Modal */}
      <AnimatePresence>
        {isLoginModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsLoginModalOpen(false)}
              className="absolute inset-0 bg-black/95 backdrop-blur-3xl" 
            />
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="relative w-full max-w-md bg-black border border-white/10 p-8 rounded-2xl overflow-hidden glass-card shadow-2xl shadow-electric/5"
            >
              <div className="scanline" />
              <div className="space-y-6">
                <div className="flex flex-col items-center gap-4">
                  <div className="relative p-4 bg-electric/10 rounded-2xl border border-electric/30">
                    <Radar className="w-8 h-8 text-electric" />
                    <motion.div 
                      animate={{ y: [-15, 15, -15] }}
                      transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                      className="absolute left-1 right-1 h-[1px] bg-electric/50"
                    />
                  </div>
                  <div className="text-center">
                    <h2 className="text-xl font-bold tracking-tight uppercase flex items-center justify-center gap-2">
                       SCAM<span className="text-electric">SCANNER</span> ACCESS
                    </h2>
                    <p className="text-[10px] text-white/40 uppercase tracking-widest mt-1">
                      {isSignUp ? "Register new investigator profile" : "Verify active session credentials"}
                    </p>
                  </div>
                </div>
                
                <form onSubmit={handleAuth} className="space-y-4">
                  <div className="space-y-4">
                    <div className="relative group">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Mail className="h-4 w-4 text-white/20 group-focus-within:text-electric transition-colors" />
                      </div>
                      <input
                        type="email"
                        required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="EMAIL_ADDRESS"
                        className="block w-full pl-10 pr-4 py-3 bg-white/5 border border-white/10 text-white text-sm focus:outline-none focus:border-electric transition-all font-mono placeholder:text-white/10"
                      />
                    </div>
                    <div className="relative group">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Key className="h-4 w-4 text-white/20 group-focus-within:text-electric transition-colors" />
                      </div>
                      <input
                        type={showPassword ? "text" : "password"}
                        required
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="ACCESS_KEY"
                        className="block w-full pl-10 pr-12 py-3 bg-white/5 border border-white/10 text-white text-sm focus:outline-none focus:border-electric transition-all font-mono placeholder:text-white/10"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute inset-y-0 right-0 pr-3 flex items-center text-white/20 hover:text-white/40 transition-colors"
                      >
                        {showPassword ? (
                          <div className="text-[8px] font-bold uppercase tracking-tighter">Hide</div>
                        ) : (
                          <div className="text-[8px] font-bold uppercase tracking-tighter">Show</div>
                        )}
                      </button>
                    </div>
                  </div>

                  {authError && (
                    <p className="text-[9px] text-malicious font-mono bg-malicious/10 p-2 border border-malicious/20 uppercase break-words">
                      ERR_AUTH: {authError.toUpperCase()}
                    </p>
                  )}

                  <button 
                    type="submit"
                    disabled={loading}
                    className="w-full py-4 bg-electric text-black font-bold text-xs uppercase tracking-[0.2em] hover:bg-white transition-all disabled:opacity-50 flex items-center justify-center gap-2"
                  >
                    {loading ? "PROCESSING..." : isSignUp ? "CREATE IDENTITY" : "AUTHORIZE SESSION"}
                  </button>
                  
                  {!isSignUp && (
                    <div className="flex justify-center">
                      <button 
                        type="button"
                        onClick={handleForgotPassword}
                        className="text-[9px] font-bold text-white/20 hover:text-white/60 transition-colors uppercase tracking-widest"
                      >
                        FORGOT YOUR PASSWORD? RESET IT HERE
                      </button>
                    </div>
                  )}
                </form>

                {authSuccess && (
                  <p className="text-[9px] text-legit font-mono bg-legit/10 p-2 border border-legit/20 uppercase">
                    SYSTEM_MSG: {authSuccess.toUpperCase()}
                  </p>
                )}

                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-white/10"></div>
                  </div>
                  <div className="relative flex justify-center text-[8px] uppercase tracking-[0.2em]">
                    <span className="bg-black px-2 text-white/20">OR CONTINGENCY</span>
                  </div>
                </div>

                <button 
                  onClick={handleGoogleSignIn}
                  disabled={loading}
                  className="w-full py-3 bg-white/5 border border-white/10 text-white font-bold text-[10px] uppercase tracking-widest hover:bg-white/10 transition-all flex items-center justify-center gap-3 group"
                >
                  <svg className="w-4 h-4 group-hover:scale-110 transition-transform" viewBox="0 0 24 24">
                    <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                    <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                    <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" />
                    <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                  </svg>
                  Authorize with Google
                </button>

                <div className="text-center">
                  <button 
                    onClick={() => {
                      setIsSignUp(!isSignUp);
                      setAuthError("");
                    }}
                    className="text-[10px] font-bold text-white/40 hover:text-electric transition-colors uppercase tracking-widest"
                  >
                    {isSignUp ? "Already registered? Login" : "New profile? Register here"}
                  </button>
                </div>

                <div className="pt-4 flex justify-center gap-4 text-[8px] text-white/10 font-mono">
                  <span>SECURE_LAYER_X1</span>
                  <span>IP_LOGGING_ACTIVE</span>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Footer Meta */}
      <footer className="text-[9px] text-white/20 uppercase tracking-widest flex justify-between items-center border-t border-white/5 pt-4">
        <div className="flex items-center gap-4">
          <span>© 2026 MALICIOUS INTELLIGENCE PORTAL // SCAMSCANNER-ENGINE</span>
          <span className="opacity-30 hover:opacity-100 transition-opacity cursor-default">DEV_UID: ADRIAN_TAMIO</span>
        </div>
        <div className="flex gap-4">
          <span>FOR INTERNAL FORENSIC USE ONLY</span>
          <span className="text-white/40">SYSTEM_UPTIME: 99.98%</span>
        </div>
      </footer>

      {/* Confirmation Modals */}
      <ConfirmModal
        isOpen={isLogoutConfirmOpen}
        onClose={() => setIsLogoutConfirmOpen(false)}
        onConfirm={confirmLogout}
        title="Session Deauth"
        message="Are you sure you want to deauthorize this investigator session? You will need to re-verify your identity to access restricted forensic data."
        confirmLabel="Deauthorize"
        cancelLabel="Stay Active"
      />

      <ConfirmModal
        isOpen={isClearHistoryConfirmOpen}
        onClose={() => setIsClearHistoryConfirmOpen(false)}
        onConfirm={confirmClearHistory}
        title="DATA PURGE"
        message="ARE YOU SURE YOU WANT TO PURGE ALL CASE RECORDS? THIS ACTION IS IRREVERSIBLE AND ALL FORENSIC HISTORY WILL BE PERMANENTLY DELETED FROM THE SERVER."
        confirmLabel="PURGE RECORDS"
        cancelLabel="ABORT"
      />

      <ConfirmModal
        isOpen={isDeleteCaseConfirmOpen}
        onClose={() => setIsDeleteCaseConfirmOpen(false)}
        onConfirm={confirmDeleteCase}
        title="RECORD REMOVAL"
        message="ARE YOU SURE YOU WANT TO REMOVE THIS SPECIFIC CASE RECORD? THIS WILL PERMANENTLY DELETE THE EVIDENCE FROM THE SECURE CLOUD DATABASE."
        confirmLabel="DELETE RECORD"
        cancelLabel="CANCEL"
      />
    </div>
  );
}

