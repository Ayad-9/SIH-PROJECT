import { useState, useEffect } from 'react';
import { Server, Activity, Terminal, ShieldCheck, ExternalLink, Zap, CheckCircle2, AlertCircle } from 'lucide-react';
import './App.css';

function App() {
  const [backendStatus, setBackendStatus] = useState('checking');
  const [demoData, setDemoData] = useState(null);
  const [loadingDemo, setLoadingDemo] = useState(false);

  const checkHealth = async () => {
    setBackendStatus('checking');
    try {
      const res = await fetch('http://localhost:8000/api/health');
      if (res.ok) {
        setBackendStatus('connected');
      } else {
        setBackendStatus('error');
      }
    } catch {
      setBackendStatus('offline');
    }
  };

  const fetchDemoData = async () => {
    setLoadingDemo(true);
    try {
      const res = await fetch('http://localhost:8000/api/demo-data');
      if (res.ok) {
        const data = await res.json();
        setDemoData(data);
      }
    } catch (err) {
      console.error('Failed to fetch demo data', err);
    } finally {
      setLoadingDemo(false);
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '40px 20px' }}>
      <header style={{ textAlign: 'center', marginBottom: '40px' }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '8px',
          padding: '6px 16px',
          borderRadius: '9999px',
          backgroundColor: '#eff6ff',
          color: '#2563eb',
          fontSize: '14px',
          fontWeight: 600,
          marginBottom: '16px'
        }}>
          <Zap size={16} /> Smart India Hackathon Starter
        </div>
        <h1 style={{ fontSize: '36px', fontWeight: 800, color: '#0f172a', marginBottom: '8px' }}>
          SIH Project Workspace
        </h1>
        <p style={{ color: '#64748b', fontSize: '16px' }}>
          FastAPI Backend + React (Vite) Frontend Monorepo
        </p>
      </header>

      {/* Status Bar */}
      <div style={{
        background: '#ffffff',
        border: '1px solid #e2e8f0',
        borderRadius: '16px',
        padding: '20px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05)',
        marginBottom: '32px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{
            width: '44px',
            height: '44px',
            borderRadius: '12px',
            backgroundColor: backendStatus === 'connected' ? '#dcfce7' : '#fee2e2',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: backendStatus === 'connected' ? '#16a34a' : '#ef4444'
          }}>
            <Server size={24} />
          </div>
          <div>
            <div style={{ fontWeight: 700, color: '#0f172a', fontSize: '16px' }}>
              FastAPI Backend Status
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '14px', color: '#64748b' }}>
              {backendStatus === 'connected' && (
                <><CheckCircle2 size={15} color="#16a34a" /> <span style={{ color: '#16a34a', fontWeight: 600 }}>Connected</span> (http://localhost:8000)</>
              )}
              {backendStatus === 'checking' && <span>Checking connection...</span>}
              {(backendStatus === 'offline' || backendStatus === 'error') && (
                <><AlertCircle size={15} color="#ef4444" /> <span style={{ color: '#ef4444', fontWeight: 600 }}>Not running</span> (Run `uvicorn main:app --reload` in `backend/`)</>
              )}
            </div>
          </div>
        </div>

        <button
          onClick={checkHealth}
          style={{
            padding: '10px 18px',
            borderRadius: '10px',
            border: '1px solid #cbd5e1',
            background: '#ffffff',
            cursor: 'pointer',
            fontSize: '14px',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
          <Activity size={16} /> Recheck Status
        </button>
      </div>

      {/* Feature Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', marginBottom: '32px' }}>
        <div style={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '16px', padding: '24px' }}>
          <div style={{ color: '#2563eb', marginBottom: '12px' }}><Terminal size={28} /></div>
          <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '8px', color: '#0f172a' }}>FastAPI Backend</h3>
          <p style={{ color: '#64748b', fontSize: '14px', marginBottom: '16px' }}>
            High-performance asynchronous Python REST API with auto-generated documentation.
          </p>
          <a
            href="http://localhost:8000/docs"
            target="_blank"
            rel="noreferrer"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#2563eb', fontSize: '14px', fontWeight: 600, textDecoration: 'none' }}>
            Open Swagger Docs <ExternalLink size={14} />
          </a>
        </div>

        <div style={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: '16px', padding: '24px' }}>
          <div style={{ color: '#16a34a', marginBottom: '12px' }}><ShieldCheck size={28} /></div>
          <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '8px', color: '#0f172a' }}>React + Vite Frontend</h3>
          <p style={{ color: '#64748b', fontSize: '14px', marginBottom: '16px' }}>
            Fast development environment with instant HMR and modern UI starter components.
          </p>
          <button
            onClick={fetchDemoData}
            disabled={loadingDemo || backendStatus !== 'connected'}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '8px',
              background: backendStatus === 'connected' ? '#2563eb' : '#94a3b8',
              color: '#ffffff',
              border: 'none',
              cursor: backendStatus === 'connected' ? 'pointer' : 'not-allowed',
              fontSize: '13px',
              fontWeight: 600
            }}>
            {loadingDemo ? 'Fetching...' : 'Test Backend API'}
          </button>
        </div>
      </div>

      {demoData && (
        <div style={{ background: '#0f172a', color: '#e2e8f0', borderRadius: '16px', padding: '20px', fontSize: '14px' }}>
          <div style={{ fontWeight: 700, marginBottom: '8px', color: '#38bdf8' }}>Backend Response (/api/demo-data):</div>
          <pre style={{ margin: 0, overflowX: 'auto' }}>{JSON.stringify(demoData, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

export default App;