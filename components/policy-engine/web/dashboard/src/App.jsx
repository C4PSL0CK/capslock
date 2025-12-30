import { useState, useEffect } from 'react'
import axios from 'axios'
import { 
  Activity, Shield, AlertTriangle, CheckCircle, Server, 
  FileText, Settings, BarChart3, Bell, Home, Lock,
  Network, Layers, GitBranch, ExternalLink
} from 'lucide-react'
import './App.css'

const API_URL = 'http://localhost:8000/api'

function App() {
  const [stats, setStats] = useState(null)
  const [namespaces, setNamespaces] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedView, setSelectedView] = useState('overview')
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 10000)
    return () => clearInterval(interval)
  }, [])

  const fetchData = async () => {
    try {
      const [statsRes, namespacesRes] = await Promise.all([
        axios.get(`${API_URL}/dashboard/stats`),
        axios.get(`${API_URL}/namespaces`)
      ])
      
      setStats(statsRes.data)
      setNamespaces(namespacesRes.data)
      setLoading(false)
    } catch (error) {
      console.error('Error fetching data:', error)
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="loading-container">
        <Activity size={48} className="loading-spinner" />
        <p>Loading EAPE Control Panel...</p>
      </div>
    )
  }

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div className="logo">
            <Shield size={36} />
            <div>
              <h1>EAPE Control Panel</h1>
              <p className="subtitle">Environment-Aware Policy Engine</p>
            </div>
          </div>
          <div className="header-info">
            <div className="status-indicator">
              <CheckCircle size={18} />
              <span>System Online</span>
            </div>
          </div>
        </div>
      </header>

      <div className="main-container">
        {/* Sidebar */}
        <aside className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
          <div className="sidebar-section">
            <div className="section-title">EAPE MODULES</div>
            <nav className="sidebar-nav">
              <button 
                className={selectedView === 'overview' ? 'active' : ''}
                onClick={() => setSelectedView('overview')}
              >
                <Home size={20} />
                <span>Overview</span>
              </button>
              <button 
                className={selectedView === 'detection' ? 'active' : ''}
                onClick={() => setSelectedView('detection')}
              >
                <Activity size={20} />
                <span>Environment Detection</span>
              </button>
              <button 
                className={selectedView === 'policies' ? 'active' : ''}
                onClick={() => setSelectedView('policies')}
              >
                <FileText size={20} />
                <span>Policy Management</span>
              </button>
              <button 
                className={selectedView === 'compliance' ? 'active' : ''}
                onClick={() => setSelectedView('compliance')}
              >
                <Lock size={20} />
                <span>Compliance Monitor</span>
              </button>
              <button 
                className={selectedView === 'audit' ? 'active' : ''}
                onClick={() => setSelectedView('audit')}
              >
                <BarChart3 size={20} />
                <span>Audit Logs</span>
              </button>
            </nav>
          </div>

          <div className="sidebar-section">
            <div className="section-title">TEAM COMPONENTS</div>
            <nav className="sidebar-nav">
              <a href="#" className="external-link">
                <Server size={20} />
                <span>ICAP Operator</span>
                <ExternalLink size={14} />
              </a>
              <a href="#" className="external-link">
                <Network size={20} />
                <span>Service Discovery</span>
                <ExternalLink size={14} />
              </a>
              <a href="#" className="external-link">
                <GitBranch size={20} />
                <span>MEDS System</span>
                <ExternalLink size={14} />
              </a>
            </nav>
          </div>
        </aside>

        {/* Main Content */}
        <main className="content">
          {selectedView === 'overview' && <OverviewView stats={stats} namespaces={namespaces} />}
          {selectedView === 'detection' && <DetectionView namespaces={namespaces} />}
          {selectedView === 'policies' && <PoliciesView />}
          {selectedView === 'compliance' && <ComplianceView />}
          {selectedView === 'audit' && <AuditView />}
        </main>
      </div>
    </div>
  )
}

// Overview Component
function OverviewView({ stats, namespaces }) {
  return (
    <div className="view">
      <h2>Overview</h2>
      
      {/* Top Stats */}
      <div className="metrics-row">
        <div className="metric-card">
          <div className="metric-icon">
            <Server size={24} />
          </div>
          <div className="metric-content">
            <div className="metric-value">{stats?.totalNamespaces || 0}</div>
            <div className="metric-label">Deployments</div>
          </div>
        </div>

        <div className="metric-card success">
          <div className="metric-icon">
            <CheckCircle size={24} />
          </div>
          <div className="metric-content">
            <div className="metric-value">100%</div>
            <div className="metric-label">Security Score</div>
          </div>
        </div>

        <div className="metric-card warning">
          <div className="metric-icon">
            <AlertTriangle size={24} />
          </div>
          <div className="metric-content">
            <div className="metric-value">0</div>
            <div className="metric-label">Avg Risk</div>
          </div>
        </div>

        <div className="metric-card error">
          <div className="metric-icon">
            <Bell size={24} />
          </div>
          <div className="metric-content">
            <div className="metric-value">0</div>
            <div className="metric-label">Violations</div>
          </div>
        </div>
      </div>

      {/* Environments Section */}
      <div className="section">
        <h3>Environments</h3>
        <div className="env-grid">
          <div className="env-card dev">
            <div className="env-header">
              <Activity size={24} />
              <h4>Dev</h4>
            </div>
            <div className="env-content">
              <div className="env-stat">
                <span className="stat-label">Namespaces:</span>
                <span className="stat-value">{stats?.devNamespaces || 0}</span>
              </div>
              <div className="env-stat">
                <span className="stat-label">Risk Score:</span>
                <span className="stat-value">Low</span>
              </div>
            </div>
          </div>

          <div className="env-card staging">
            <div className="env-header">
              <Settings size={24} />
              <h4>Staging</h4>
            </div>
            <div className="env-content">
              <div className="env-stat">
                <span className="stat-label">Namespaces:</span>
                <span className="stat-value">{stats?.stagingNamespaces || 0}</span>
              </div>
              <div className="env-stat">
                <span className="stat-label">Risk Score:</span>
                <span className="stat-value">Medium</span>
              </div>
            </div>
          </div>

          <div className="env-card prod">
            <div className="env-header">
              <Shield size={24} />
              <h4>Prod</h4>
            </div>
            <div className="env-content">
              <div className="env-stat">
                <span className="stat-label">Namespaces:</span>
                <span className="stat-value">{stats?.prodNamespaces || 0}</span>
              </div>
              <div className="env-stat">
                <span className="stat-label">Risk Score:</span>
                <span className="stat-value">High</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// Detection View
function DetectionView({ namespaces }) {
  return (
    <div className="view">
      <h2>Environment Detection</h2>
      <div className="table-card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Namespace</th>
              <th>Environment</th>
              <th>Security Level</th>
              <th>Compliance</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {namespaces.map(ns => (
              <tr key={ns.name}>
                <td><strong>{ns.name}</strong></td>
                <td><span className={`badge badge-${ns.environment}`}>{ns.environment}</span></td>
                <td>{ns.securityLevel}</td>
                <td>{ns.compliance.join(', ') || 'None'}</td>
                <td>{(ns.confidence * 100).toFixed(0)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// Policies View
function PoliciesView() {
  return (
    <div className="view">
      <h2>Policy Management</h2>
      <div className="placeholder">
        <FileText size={64} />
        <h3>Policy Templates</h3>
        <p>Configure security policies for different environments</p>
        <p className="coming-soon">Coming in Task 2.6-2.9</p>
      </div>
    </div>
  )
}

// Compliance View
function ComplianceView() {
  return (
    <div className="view">
      <h2>Compliance Monitor</h2>
      <div className="compliance-grid">
        <div className="compliance-card">
          <Lock size={32} />
          <h4>ISO 27001</h4>
          <p>93 Controls</p>
          <span className="status-badge active">Active</span>
        </div>
        <div className="compliance-card">
          <Lock size={32} />
          <h4>SOC 2</h4>
          <p>64 Controls</p>
          <span className="status-badge active">Active</span>
        </div>
        <div className="compliance-card">
          <Lock size={32} />
          <h4>CIS Benchmarks</h4>
          <p>18 Controls</p>
          <span className="status-badge pending">Pending</span>
        </div>
        <div className="compliance-card">
          <Lock size={32} />
          <h4>PCI-DSS</h4>
          <p>12 Requirements</p>
          <span className="status-badge active">Active</span>
        </div>
      </div>
    </div>
  )
}

// Audit View
function AuditView() {
  return (
    <div className="view">
      <h2>Audit Logs</h2>
      <div className="placeholder">
        <BarChart3 size={64} />
        <h3>Audit Trail</h3>
        <p>View policy enforcement and detection events</p>
        <p className="coming-soon">Coming in Task 3.x</p>
      </div>
    </div>
  )
}

export default App