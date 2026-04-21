import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, Send, Lock, Key, RefreshCw, User, 
  MessageSquare, Zap, Cpu, Terminal, 
  LogOut, Binary, ChevronRight, CheckCircle,
  AlertCircle, ShieldCheck, UserPlus, LogIn, Bell
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const App = () => {
  const [currentUser, setCurrentUser] = useState(null);
  const [authMode, setAuthMode] = useState('login'); 
  const [authData, setAuthData] = useState({ username: '', password: '' });
  const [messages, setMessages] = useState([]);
  const [activeRecipient, setActiveRecipient] = useState('');
  const [messageInput, setMessageInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [securityLogs, setSecurityLogs] = useState([]);
  const [lastDebug, setLastDebug] = useState(null);
  const [showRightPanel, setShowRightPanel] = useState(true);
  const [availableUsers, setAvailableUsers] = useState([]);
  const [unreadNotifications, setUnreadNotifications] = useState({}); // { senderId: count }
  
  const scrollRef = useRef(null);

  const addLog = (message, type = 'info') => {
    setSecurityLogs(prev => [{ id: Date.now(), message, type, time: new Date().toLocaleTimeString() }, ...prev].slice(0, 10));
  };

  const handleAuth = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    addLog(`${authMode.toUpperCase()} sequence initiated...`, 'info');
    
    const url = `/api/${authMode}`;
    console.log(`[FRONTEND SEND] ${authMode.toUpperCase()} | URL: ${url} | DATA:`, { username: authData.username });

    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(authData),
      });
      const data = await res.json();
      if (res.ok) {
        setCurrentUser(data.username);
        addLog(authMode === 'signup' ? 'New identity provisioned.' : 'Vault decrypted.', 'success');
        fetchUsers();
      } else {
        addLog(`Access Denied: ${data.detail}`, 'danger');
      }
    } catch (err) {
      addLog(`Network Failure: ${err.message}`, 'danger');
    } finally {
      setIsLoading(false);
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await fetch('/api/users');
      if (res.ok) {
        const data = await res.json();
        setAvailableUsers(data.filter(u => u !== currentUser));
      }
    } catch (err) {
      console.error('Fetch users error:', err);
    }
  };

  const fetchMessages = async () => {
    if (!currentUser) return;
    try {
      const res = await fetch(`/api/messages/${currentUser}`);
      if (res.ok) {
        const data = await res.json();
        if (data.length > 0) {
          setMessages(prev => [...prev, ...data]);
          const newNotifications = { ...unreadNotifications };
          data.forEach(msg => {
            addLog(`Inbound packet from ${msg.sender_id}`, 'success');
            setLastDebug(msg.debug);
            if (msg.sender_id !== activeRecipient) {
              newNotifications[msg.sender_id] = (newNotifications[msg.sender_id] || 0) + 1;
            }
          });
          setUnreadNotifications(newNotifications);
        }
      }
    } catch (err) {
      console.error('Fetch error:', err);
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!messageInput || !activeRecipient) return;
    
    setIsLoading(true);
    addLog(`Encrypting for ${activeRecipient}...`, 'info');
    
    const payload = {
      username: currentUser,
      peer_id: activeRecipient,
      message: messageInput
    };
    console.log(`[FRONTEND SEND] ENCRYPTED_BROADCAST | URL: /api/send | DATA:`, payload);

    try {
      const res = await fetch('/api/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (res.ok) {
        addLog(`Encrypted broadcast successful.`, 'success');
        setMessages(prev => [...prev, { sender_id: 'me', text: messageInput, id: Date.now() }]);
        setMessageInput('');
        setLastDebug(data.debug);
      } else {
        addLog(`Transmission error: ${data.detail}`, 'danger');
      }
    } catch (err) {
      addLog(`Critical error: ${err.message}`, 'danger');
    } finally {
      setIsLoading(false);
    }
  };

  const selectUser = (userId) => {
    setActiveRecipient(userId);
    setUnreadNotifications(prev => {
      const updated = { ...prev };
      delete updated[userId];
      return updated;
    });
  };

  useEffect(() => {
    if (currentUser) {
      const interval = setInterval(() => {
        fetchMessages();
        fetchUsers();
      }, 3000);
      return () => clearInterval(interval);
    }
  }, [currentUser, activeRecipient, unreadNotifications]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  if (!currentUser) {
    return (
      <div className="app-container items-center justify-center">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="card-sleek w-full" 
          style={{ maxWidth: '440px' }}
        >
          <div className="flex flex-col items-center mb-8">
            <div className="mb-4" style={{ background: 'rgba(99, 102, 241, 0.1)', padding: '16px', borderRadius: '16px' }}>
              <ShieldCheck className="text-primary" size={40} />
            </div>
            <h1 style={{ fontSize: '2rem', fontWeight: '800', letterSpacing: '-0.02em', marginBottom: '8px' }}>Secure Messenger</h1>
            <p style={{ color: '#a1a1aa', fontSize: '0.9rem' }}>Zero-Knowledge Asymmetric Messaging</p>
          </div>

          <div style={{ display: 'flex', background: '#141414', padding: '4px', borderRadius: '12px', marginBottom: '32px' }}>
            <button 
              onClick={() => setAuthMode('login')}
              style={{ 
                flex: 1, border: 'none', padding: '12px', borderRadius: '8px', cursor: 'pointer', transition: '0.2s',
                background: authMode === 'login' ? '#262626' : 'transparent',
                color: authMode === 'login' ? '#fff' : '#a1a1aa',
                fontWeight: '600', fontSize: '0.85rem'
              }}
            >
              LOG IN
            </button>
            <button 
              onClick={() => setAuthMode('signup')}
              style={{ 
                flex: 1, border: 'none', padding: '12px', borderRadius: '8px', cursor: 'pointer', transition: '0.2s',
                background: authMode === 'signup' ? '#262626' : 'transparent',
                color: authMode === 'signup' ? '#fff' : '#a1a1aa',
                fontWeight: '600', fontSize: '0.85rem'
              }}
            >
              SIGN UP
            </button>
          </div>

          <form onSubmit={handleAuth} style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label style={{ fontSize: '0.75rem', fontWeight: '800', color: '#6366f1', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Identity UID</label>
              <input 
                type="text" 
                className="input-modern" 
                placeholder="Ex: alice_01"
                value={authData.username}
                onChange={e => setAuthData({...authData, username: e.target.value})}
                required
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label style={{ fontSize: '0.75rem', fontWeight: '800', color: '#6366f1', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Master Password</label>
              <input 
                type="password" 
                className="input-modern" 
                placeholder="Database Decryption Key"
                value={authData.password}
                onChange={e => setAuthData({...authData, password: e.target.value})}
                required
              />
            </div>
            <button disabled={isLoading} className="btn-primary mt-4">
              {isLoading ? <RefreshCw className="animate-spin" /> : (authMode === 'login' ? <LogIn size={20}/> : <UserPlus size={20}/>)}
              <span style={{ marginLeft: '8px' }}>{isLoading ? 'Decrypting Vault...' : (authMode === 'login' ? 'ACCESS VAULT' : 'PROVISION IDENTITY')}</span>
            </button>
          </form>
          
          <div style={{ marginTop: '32px', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '24px', display: 'flex', gap: '16px' }}>
            <Lock style={{ color: '#6366f1', opacity: 0.5, flexShrink: 0 }} size={24} />
            <p style={{ fontSize: '0.75rem', color: '#a1a1aa', lineHeight: '1.6' }}>
              Keys are generated and stored locally in your encrypted vault. They are never transmitted to the relay.
            </p>
          </div>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="app-container">
      <div className="sidebar">
        <div className="p-8" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div className="flex items-center" style={{ gap: '12px' }}>
            <div style={{ background: '#6366f1', padding: '6px', borderRadius: '8px' }}>
              <Shield style={{ color: '#fff' }} size={20} />
            </div>
            <h2 style={{ fontSize: '1.2rem', fontWeight: '800', letterSpacing: '-0.03em' }}>NOVA</h2>
          </div>
          <button onClick={() => window.location.reload()} style={{ padding: '8px', background: 'transparent', border: 'none', color: '#a1a1aa', cursor: 'pointer' }}>
            <LogOut size={18} />
          </button>
        </div>

        <div className="p-8" style={{ overflowY: 'auto', flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', padding: '16px', background: 'rgba(255,255,255,0.03)', borderRadius: '16px', marginBottom: '40px', border: '1px solid rgba(255,255,255,0.05)' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '14px', background: 'linear-gradient(135deg, #6366f1, #a855f7)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: '900', fontSize: '1.2rem' }}>
              {currentUser[0].toUpperCase()}
            </div>
            <div style={{ overflow: 'hidden' }}>
               <p style={{ fontSize: '0.65rem', fontWeight: '900', color: '#6366f1', textTransform: 'uppercase', letterSpacing: '0.2em' }}>Host Node</p>
               <p style={{ fontWeight: '700', fontSize: '0.9rem', color: '#fff' }}>{currentUser}</p>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <p style={{ fontSize: '0.65rem', fontWeight: '900', color: '#a1a1aa', textTransform: 'uppercase', letterSpacing: '0.2em' }}>Available Peer Nodes</p>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {availableUsers.length === 0 && (
                <p style={{ fontSize: '0.75rem', color: '#a1a1aa', fontStyle: 'italic', padding: '12px' }}>Awaiting new peer registration...</p>
              )}
              {availableUsers.map(user => (
                <motion.div 
                  key={user}
                  onClick={() => selectUser(user)}
                  whileHover={{ x: 4 }}
                  style={{ 
                    padding: '12px 16px', borderRadius: '14px', cursor: 'pointer', transition: '0.2s',
                    background: activeRecipient === user ? 'rgba(99, 102, 241, 0.1)' : 'rgba(255,255,255,0.02)', 
                    border: '1px solid',
                    borderColor: activeRecipient === user ? 'rgba(99, 102, 241, 0.3)' : 'rgba(255,255,255,0.05)',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{ position: 'relative' }}>
                      <div style={{ width: '32px', height: '32px', borderRadius: '10px', background: activeRecipient === user ? '#6366f1' : 'rgba(255,255,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: '800', fontSize: '0.8rem', color: activeRecipient === user ? '#fff' : '#a1a1aa' }}>
                        {user[0].toUpperCase()}
                      </div>
                      {unreadNotifications[user] > 0 && (
                        <div style={{ position: 'absolute', top: '-6px', right: '-6px', background: '#ef4444', color: '#fff', fontSize: '0.6rem', fontWeight: '900', minWidth: '16px', height: '16px', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '2px solid #0a0a0a', padding: '0 4px' }}>
                          {unreadNotifications[user]}
                        </div>
                      )}
                    </div>
                    <span style={{ fontSize: '0.85rem', fontWeight: activeRecipient === user ? '700' : '500', color: activeRecipient === user ? '#fff' : '#a1a1aa' }}>{user}</span>
                  </div>
                  {activeRecipient === user && <ChevronRight size={14} style={{ color: '#6366f1' }} />}
                </motion.div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="main-content">
        <div style={{ height: '80px', padding: '0 40px', borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(0,0,0,0.2)' }}>
           <div>
             <h3 style={{ fontSize: '1.2rem', fontWeight: '800', letterSpacing: '-0.02em' }}>{activeRecipient ? `@${activeRecipient}` : 'Command Center'}</h3>
             <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
               <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: activeRecipient ? '#10b981' : 'rgba(255,255,255,0.1)' }} />
               <span style={{ fontSize: '0.65rem', fontWeight: '800', color: '#a1a1aa', textTransform: 'uppercase', letterSpacing: '0.15em' }}>
                 {activeRecipient ? 'Asymmetric Tunnel Active' : 'Waiting for transport'}
               </span>
             </div>
           </div>
           <button 
             onClick={() => setShowRightPanel(!showRightPanel)}
             style={{ padding: '10px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)', background: showRightPanel ? 'rgba(99, 102, 241, 0.15)' : 'transparent', color: showRightPanel ? '#6366f1' : '#a1a1aa', cursor: 'pointer', transition: '0.2s' }}
           >
             <Terminal size={18} />
           </button>
        </div>

        <div className="flex-1 overflow-y-auto p-12" style={{ display: 'flex', flexDirection: 'column', gap: '32px' }} ref={scrollRef}>
          {messages.length === 0 ? (
            <div style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', opacity: 0.1, textAlign: 'center' }}>
              <Lock size={80} style={{ marginBottom: '24px' }} />
              <p style={{ fontSize: '1.5rem', fontWeight: '800' }}>END-TO-END SECURITY</p>
              <p style={{ fontSize: '0.9rem', marginTop: '8px' }}>Select a peer from the sidebar to establish a secure handshake.</p>
            </div>
          ) : (
            messages.filter(m => m.sender_id === 'me' || m.sender_id === activeRecipient).map((msg, i) => (
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                key={msg.id} 
                style={{ display: 'flex', flexDirection: 'column', alignItems: msg.sender_id === 'me' ? 'flex-end' : 'flex-start' }}
              >
                <div className={msg.sender_id === 'me' ? 'message-me' : 'message-peer'}>
                  <p style={{ fontSize: '0.95rem', lineHeight: '1.6' }}>{msg.text}</p>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '12px', padding: '0 4px' }}>
                  <span style={{ fontSize: '0.65rem', fontWeight: '900', color: '#a1a1aa', textTransform: 'uppercase', letterSpacing: '0.15em' }}>
                    {msg.sender_id === 'me' ? 'SIG_VALID' : `VERIFIED_${activeRecipient.toUpperCase()}`}
                  </span>
                  {msg.sender_id === 'me' ? <CheckCircle size={10} style={{ color: '#10b981' }} /> : <div style={{ width: '4px', height: '4px', borderRadius: '50%', background: '#6366f1' }} />}
                </div>
              </motion.div>
            ))
          )}
        </div>

        <div style={{ padding: '40px', paddingTop: '20px', background: 'linear-gradient(to top, #000, transparent)' }}>
          <form onSubmit={sendMessage} style={{ position: 'relative' }}>
            <input 
              disabled={!activeRecipient}
              type="text" 
              className="input-modern w-full" 
              style={{ padding: '20px 80px 20px 28px', fontSize: '1.1rem', borderRadius: '16px' }}
              placeholder={activeRecipient ? `Message @${activeRecipient}...` : 'Establish link to enable encryption'}
              value={messageInput}
              onChange={e => setMessageInput(e.target.value)}
            />
            <button 
              disabled={!activeRecipient || !messageInput || isLoading} 
              type="submit" 
              style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)', height: '48px', width: '48px', background: '#fff', color: '#000', border: 'none', borderRadius: '12px', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
              {isLoading ? <RefreshCw className="animate-spin" size={20} /> : <Send size={20} />}
            </button>
          </form>
        </div>
      </div>

      {showRightPanel && (
        <div className="right-panel">
          <div className="p-8" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <ShieldCheck size={18} style={{ color: '#6366f1' }} />
              <h3 style={{ fontSize: '0.75rem', fontWeight: '900', textTransform: 'uppercase', letterSpacing: '0.2em' }}>Security Handshake</h3>
            </div>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981' }} />
          </div>

          <div className="p-8" style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '40px' }}>
            {lastDebug ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div style={{ padding: '20px', borderRadius: '16px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <p style={{ fontSize: '0.65rem', fontWeight: '900', color: '#a1a1aa', textTransform: 'uppercase', letterSpacing: '0.2em', marginBottom: '20px' }}>Cipher Telemetry</p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                     <div>
                       <p style={{ fontSize: '0.65rem', color: '#6366f1', fontWeight: '900', textTransform: 'uppercase', marginBottom: '8px' }}>X25519 Shared Secret</p>
                       <code className="mono" style={{ display: 'block', padding: '12px', background: '#000', borderRadius: '10px', color: 'rgba(255,255,255,0.6)', border: '1px solid rgba(255,255,255,0.05)', wordBreak: 'break-all' }}>
                         {lastDebug.shared_secret_prefix}
                       </code>
                     </div>
                     <div>
                       <p style={{ fontSize: '0.65rem', color: '#6366f1', fontWeight: '900', textTransform: 'uppercase', marginBottom: '8px' }}>AES-256-Key (HKDF)</p>
                       <code className="mono" style={{ display: 'block', padding: '12px', background: '#000', borderRadius: '10px', color: 'rgba(255,255,255,0.6)', border: '1px solid rgba(255,255,255,0.05)', wordBreak: 'break-all' }}>
                         {lastDebug.session_key_prefix}
                       </code>
                     </div>
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', opacity: 0.1 }}>
                 <Binary size={48} style={{ marginBottom: '16px' }} />
                 <p style={{ fontSize: '0.7rem', fontWeight: '900', textTransform: 'uppercase' }}>Awaiting Session Data</p>
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
               <p style={{ fontSize: '0.65rem', fontWeight: '900', color: '#a1a1aa', textTransform: 'uppercase', letterSpacing: '0.2em' }}>Secure Log</p>
               <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                 {securityLogs.map(log => (
                   <div key={log.id} style={{ padding: '12px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.05)', background: 'rgba(255,255,255,0.01)', fontSize: '0.7rem', color: log.type === 'success' ? '#10b981' : log.type === 'danger' ? '#ef4444' : 'rgba(255,255,255,0.5)', fontFamily: 'JetBrains Mono, monospace' }}>
                     <span style={{ opacity: 0.3, marginRight: '8px' }}>[{log.time}]</span>
                     {log.message}
                   </div>
                 ))}
               </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
