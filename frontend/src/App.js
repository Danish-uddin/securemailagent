import React, { useState } from 'react'

const MAILHOG_URL = 'http://localhost:8025'
const API_URL = 'http://localhost:8000'

function App() {
  const [testResult, setTestResult] = useState(null)

  const sendTestEmail = async () => {
    try {
      const res = await fetch(`${API_URL}/send-test-email`, {
        method: 'POST'
      })
      const data = await res.json()
      setTestResult(data.status)
    } catch (e) {
      setTestResult('error')
    }
  }

  return (
    <div style={styles.page}>

      {/* HEADER */}
      <div style={styles.header}>
        <span>🔐 SECUREMAILAGENT SOC</span>
        <span style={styles.live}>● LIVE</span>
      </div>

      {/* STATS BAR */}
      <div style={styles.statsBar}>
        <span>Analyzed: 0</span>
        <span>Human Threats: 0</span>
        <span>AI Threats: 0</span>
        <span>Blocked: 0</span>
      </div>

      {/* AGENT PIPELINE — placeholder */}
      <div style={styles.panel}>
        <div style={styles.panelTitle}>AGENT PIPELINE (LIVE)</div>
        <div style={styles.placeholder}>
          [Intent] ──► [AI Threat] ──► [Behavioral] ──► [Orchestration] ──► [Audit]
        </div>
      </div>

      {/* LIVE INBOX — Mailhog iframe */}
      <div style={styles.panel}>
        <div style={styles.panelTitle}>LIVE INBOX</div>
        <iframe
          src={MAILHOG_URL}
          style={styles.iframe}
          title="Mailhog Inbox"
        />
      </div>

      {/* TWO COLUMN ROW */}
      <div style={styles.row}>

        {/* EMAIL ATTACK LAUNCHER */}
        <div style={styles.halfPanel}>
          <div style={styles.panelTitle}>EMAIL ATTACK LAUNCHER</div>
          <div style={styles.placeholder}>Attack buttons coming in Layer 2</div>
          <hr style={styles.divider} />
          <button style={styles.button} onClick={sendTestEmail}>
            ✉️ Send Test Email
          </button>
          {testResult && (
            <div style={styles.result}>
              Result: {testResult}
            </div>
          )}
        </div>

        {/* AGENT ATTACK CONSOLE */}
        <div style={styles.halfPanel}>
          <div style={styles.panelTitle}>AGENT ATTACK CONSOLE</div>
          <div style={styles.placeholder}>Agent attack buttons coming in Layer 2</div>
        </div>

      </div>

      {/* SECOND TWO COLUMN ROW */}
      <div style={styles.row}>

        {/* DEFENSE LOG */}
        <div style={styles.halfPanel}>
          <div style={styles.panelTitle}>DEFENSE LOG</div>
          <div style={styles.placeholder}>Defense log coming in Layer 2</div>
        </div>

        {/* AGENT DEFENSE STATUS */}
        <div style={styles.halfPanel}>
          <div style={styles.panelTitle}>AGENT DEFENSE STATUS</div>
          <div style={styles.placeholder}>Agent defense status coming in Layer 2</div>
        </div>

      </div>

      {/* INCIDENT BOARD */}
      <div style={styles.panel}>
        <div style={styles.panelTitle}>INCIDENT BOARD</div>
        <div style={styles.placeholder}>Incidents coming in Layer 2</div>
      </div>

      {/* BOTTOM THREE COLUMN ROW */}
      <div style={styles.row}>

        <div style={styles.thirdPanel}>
          <div style={styles.panelTitle}>THREAT INTEL</div>
          <div style={styles.placeholder}>Threat intel coming in Layer 5</div>
        </div>

        <div style={styles.thirdPanel}>
          <div style={styles.panelTitle}>THREAT TRENDS</div>
          <div style={styles.placeholder}>Chart coming in Layer 7</div>
        </div>

        <div style={styles.thirdPanel}>
          <div style={styles.panelTitle}>API USAGE MONITOR</div>
          <div style={styles.placeholder}>API counters coming in Layer 5</div>
        </div>

      </div>

    </div>
  )
}

const styles = {
  page: {
    backgroundColor: '#0f172a',
    minHeight: '100vh',
    padding: '16px',
    fontFamily: 'monospace',
    color: '#e2e8f0',
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '18px',
    fontWeight: 'bold',
    color: '#38bdf8',
    padding: '8px 0',
  },
  live: {
    color: '#4ade80',
    fontSize: '14px',
  },
  statsBar: {
    display: 'flex',
    gap: '32px',
    backgroundColor: '#1e293b',
    padding: '10px 16px',
    borderRadius: '6px',
    fontSize: '13px',
    color: '#94a3b8',
  },
  panel: {
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '8px',
    padding: '12px',
  },
  halfPanel: {
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '8px',
    padding: '12px',
    flex: 1,
  },
  thirdPanel: {
    backgroundColor: '#1e293b',
    border: '1px solid #334155',
    borderRadius: '8px',
    padding: '12px',
    flex: 1,
  },
  panelTitle: {
    fontSize: '11px',
    fontWeight: 'bold',
    color: '#38bdf8',
    letterSpacing: '0.1em',
    marginBottom: '10px',
    textTransform: 'uppercase',
  },
  placeholder: {
    color: '#475569',
    fontSize: '12px',
    padding: '12px 0',
  },
  iframe: {
    width: '100%',
    height: '400px',
    border: 'none',
    borderRadius: '4px',
  },
  row: {
    display: 'flex',
    gap: '12px',
  },
  divider: {
    border: 'none',
    borderTop: '1px solid #334155',
    margin: '12px 0',
  },
  button: {
    backgroundColor: '#1d4ed8',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    padding: '8px 16px',
    cursor: 'pointer',
    fontSize: '13px',
    fontFamily: 'monospace',
  },
  result: {
    marginTop: '8px',
    fontSize: '12px',
    color: '#4ade80',
  },
}

export default App