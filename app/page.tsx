"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardHeader, CardContent, CardTitle, CardDescription } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { Switch } from "@/components/ui/switch"
import { Checkbox } from "@/components/ui/checkbox"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Separator } from "@/components/ui/separator"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

interface Agent {
  id: string
  name: string
  location: string
  status: 'online' | 'offline' | 'scanning'
  lastSeen: string
  capabilities: string[]
  os: string
  version: string
  cpuUsage: number
  memoryUsage: number
}

interface ComplianceFramework {
  id: string
  name: string
  description: string
  controls: number
  categories: string[]
  severity: 'low' | 'medium' | 'high' | 'critical'
}

interface ScanResult {
  id: string
  timestamp: string
  framework: string
  target: string
  status: 'completed' | 'failed' | 'running'
  score: number
  findings: Finding[]
  recommendations: string[]
  agentData?: AgentScanResult[]
  executionTime: number
  vulnerabilities: Vulnerability[]
}

interface Finding {
  id: string
  control: string
  status: 'pass' | 'fail' | 'warning'
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  evidence: string
  remediation: string
}

interface Vulnerability {
  id: string
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  impact: string
  solution: string
  cvss: number
}

interface AgentScanResult {
  agentId: string
  agentName: string
  status: 'success' | 'error'
  data: any
  executionTime: number
}

const COMPLIANCE_FRAMEWORKS: ComplianceFramework[] = [
  {
    id: 'hipaa',
    name: 'HIPAA',
    description: 'Health Insurance Portability and Accountability Act',
    controls: 18,
    categories: ['Administrative', 'Physical', 'Technical'],
    severity: 'critical'
  },
  {
    id: 'iso27001',
    name: 'ISO 27001',
    description: 'Information Security Management System',
    controls: 114,
    categories: ['Security Policy', 'Organization', 'Asset Management', 'Access Control'],
    severity: 'high'
  },
  {
    id: 'soc2',
    name: 'SOC 2',
    description: 'Service Organization Control 2',
    controls: 64,
    categories: ['Security', 'Availability', 'Processing Integrity', 'Confidentiality', 'Privacy'],
    severity: 'high'
  },
  {
    id: 'pci',
    name: 'PCI DSS',
    description: 'Payment Card Industry Data Security Standard',
    controls: 12,
    categories: ['Network Security', 'Data Protection', 'Vulnerability Management'],
    severity: 'critical'
  },
  {
    id: 'gdpr',
    name: 'GDPR',
    description: 'General Data Protection Regulation',
    controls: 99,
    categories: ['Lawfulness', 'Data Subject Rights', 'Privacy by Design'],
    severity: 'critical'
  },
  {
    id: 'nist',
    name: 'NIST CSF',
    description: 'NIST Cybersecurity Framework',
    controls: 108,
    categories: ['Identify', 'Protect', 'Detect', 'Respond', 'Recover'],
    severity: 'high'
  },
  {
    id: 'cis',
    name: 'CIS Controls',
    description: 'Center for Internet Security Controls',
    controls: 18,
    categories: ['Basic', 'Foundational', 'Organizational'],
    severity: 'high'
  },
  {
    id: 'cobit',
    name: 'COBIT 2019',
    description: 'Control Objectives for Information Technologies',
    controls: 40,
    categories: ['Governance', 'Management', 'Design Factors'],
    severity: 'medium'
  }
]

export default function ComplianceAuditPlatform() {
  // State Management
  const [activeTab, setActiveTab] = useState("dashboard")
  const [agents, setAgents] = useState<Agent[]>([])
  const [scanResults, setScanResults] = useState<ScanResult[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  // Local Scan State
  const [localTarget, setLocalTarget] = useState("")
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([])
  const [scanDepth, setScanDepth] = useState("standard")
  const [includeVulnScan, setIncludeVulnScan] = useState(false)
  const [includePenetrationTest, setIncludePenetrationTest] = useState(false)

  // Remote Audit State
  const [selectedAgents, setSelectedAgents] = useState<string[]>([])
  const [customScript, setCustomScript] = useState("")
  const [scheduledScan, setScheduledScan] = useState(false)
  const [scanInterval, setScanInterval] = useState("daily")

  // Advanced Features State
  const [realTimeMonitoring, setRealTimeMonitoring] = useState(false)
  const [autoRemediation, setAutoRemediation] = useState(false)
  const [alertThreshold, setAlertThreshold] = useState(70)
  const [aiAnalysis, setAiAnalysis] = useState(false)
  const [threatIntelligence, setThreatIntelligence] = useState(false)

  // Initialize mock data
  useEffect(() => {
    initializeMockData()
    if (realTimeMonitoring) {
      const interval = setInterval(updateAgentStatus, 5000)
      return () => clearInterval(interval)
    }
  }, [realTimeMonitoring])

  const initializeMockData = () => {
    const mockAgents: Agent[] = [
      {
        id: 'agent-001',
        name: 'Web Server - Production',
        location: 'US-East-1',
        status: 'online',
        lastSeen: new Date().toISOString(),
        capabilities: ['web-scan', 'ssl-check', 'header-analysis', 'vuln-scan'],
        os: 'Ubuntu 20.04',
        version: '2.1.0',
        cpuUsage: 45,
        memoryUsage: 62
      },
      {
        id: 'agent-002',
        name: 'Database Server - Primary',
        location: 'US-West-2',
        status: 'online',
        lastSeen: new Date().toISOString(),
        capabilities: ['db-audit', 'access-control', 'encryption-check', 'compliance-scan'],
        os: 'CentOS 8',
        version: '2.1.0',
        cpuUsage: 23,
        memoryUsage: 78
      },
      {
        id: 'agent-003',
        name: 'API Gateway',
        location: 'EU-Central-1',
        status: 'scanning',
        lastSeen: new Date().toISOString(),
        capabilities: ['api-security', 'rate-limiting', 'auth-check', 'traffic-analysis'],
        os: 'Alpine Linux',
        version: '2.0.8',
        cpuUsage: 89,
        memoryUsage: 34
      },
      {
        id: 'agent-004',
        name: 'Mobile Backend',
        location: 'Asia-Pacific-1',
        status: 'offline',
        lastSeen: new Date(Date.now() - 300000).toISOString(),
        capabilities: ['mobile-security', 'data-encryption', 'privacy-scan'],
        os: 'Ubuntu 22.04',
        version: '2.1.0',
        cpuUsage: 0,
        memoryUsage: 0
      },
      {
        id: 'agent-005',
        name: 'Cloud Infrastructure',
        location: 'Multi-Region',
        status: 'online',
        lastSeen: new Date().toISOString(),
        capabilities: ['cloud-security', 'iam-audit', 'network-scan', 'container-scan'],
        os: 'Container Linux',
        version: '2.1.1',
        cpuUsage: 67,
        memoryUsage: 45
      },
      {
        id: 'agent-006',
        name: 'IoT Device Monitor',
        location: 'Edge-Network',
        status: 'online',
        lastSeen: new Date().toISOString(),
        capabilities: ['iot-security', 'device-audit', 'firmware-check'],
        os: 'Embedded Linux',
        version: '1.9.2',
        cpuUsage: 12,
        memoryUsage: 28
      }
    ]
    setAgents(mockAgents)
  }

  const updateAgentStatus = () => {
    setAgents(prev => prev.map(agent => ({
      ...agent,
      lastSeen: Math.random() > 0.7 ? new Date().toISOString() : agent.lastSeen,
      status: Math.random() > 0.9 ? 'offline' : agent.status,
      cpuUsage: Math.floor(Math.random() * 100),
      memoryUsage: Math.floor(Math.random() * 100)
    })))
  }

  const handleLocalScan = async () => {
    if (!localTarget.trim() || selectedFrameworks.length === 0) {
      setError("Please enter a target URL and select at least one compliance framework")
      return
    }

    setLoading(true)
    setError("")

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: localTarget,
          frameworks: selectedFrameworks,
          depth: scanDepth,
          includeVulnScan,
          includePenetrationTest,
          options: {
            realTimeMonitoring,
            autoRemediation,
            alertThreshold,
            aiAnalysis,
            threatIntelligence
          }
        })
      })

      const result = await response.json()
      if (!response.ok) throw new Error(result.message)

      setScanResults(prev => [result, ...prev])
      setLocalTarget("")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed")
    } finally {
      setLoading(false)
    }
  }

  const handleRemoteAudit = async () => {
    if (selectedAgents.length === 0 || selectedFrameworks.length === 0) {
      setError("Please select agents and compliance frameworks")
      return
    }

    setLoading(true)
    setError("")

    try {
      const response = await fetch("/api/remote-audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agentIds: selectedAgents,
          frameworks: selectedFrameworks,
          customScript,
          scheduled: scheduledScan,
          interval: scanInterval,
          options: {
            realTimeMonitoring,
            autoRemediation,
            alertThreshold,
            aiAnalysis,
            threatIntelligence
          }
        })
      })

      const result = await response.json()
      if (!response.ok) throw new Error(result.message)

      setScanResults(prev => [result, ...prev])
      setSelectedAgents([])
      setCustomScript("")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Remote audit failed")
    } finally {
      setLoading(false)
    }
  }

  const handleFrameworkToggle = (frameworkId: string) => {
    setSelectedFrameworks(prev => 
      prev.includes(frameworkId) 
        ? prev.filter(id => id !== frameworkId)
        : [...prev, frameworkId]
    )
  }

  const handleAgentToggle = (agentId: string) => {
    setSelectedAgents(prev => 
      prev.includes(agentId) 
        ? prev.filter(id => id !== agentId)
        : [...prev, agentId]
    )
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'bg-green-500'
      case 'scanning': return 'bg-yellow-500'
      case 'offline': return 'bg-red-500'
      default: return 'bg-gray-500'
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-green-600'
    if (score >= 70) return 'text-yellow-600'
    return 'text-red-600'
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200'
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8 max-w-7xl">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold mb-4">Enterprise Compliance Audit Platform</h1>
          <p className="text-muted-foreground text-lg">
            Advanced multi-framework compliance auditing with distributed agent network and AI-powered analysis
          </p>
        </div>

        {/* Main Navigation */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-6">
            <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
            <TabsTrigger value="local-scan">Local Scan</TabsTrigger>
            <TabsTrigger value="remote-audit">Remote Audit</TabsTrigger>
            <TabsTrigger value="agents">Agent Network</TabsTrigger>
            <TabsTrigger value="reports">Reports</TabsTrigger>
            <TabsTrigger value="settings">Settings</TabsTrigger>
          </TabsList>

          {/* Dashboard Tab */}
          <TabsContent value="dashboard" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Active Agents</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold text-green-600">
                    {agents.filter(a => a.status === 'online').length}
                  </div>
                  <p className="text-sm text-muted-foreground">of {agents.length} total</p>
                  <Progress value={(agents.filter(a => a.status === 'online').length / agents.length) * 100} className="mt-2" />
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader>
                  <CardTitle>Recent Scans</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold">{scanResults.length}</div>
                  <p className="text-sm text-muted-foreground">completed today</p>
                  <div className="text-xs text-muted-foreground mt-1">
                    {scanResults.filter(r => r.status === 'running').length} running
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader>
                  <CardTitle>Avg Compliance Score</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className={`text-3xl font-bold ${getScoreColor(scanResults.length > 0 ? Math.round(scanResults.reduce((acc, r) => acc + r.score, 0) / scanResults.length) : 0)}`}>
                    {scanResults.length > 0 ? Math.round(scanResults.reduce((acc, r) => acc + r.score, 0) / scanResults.length) : 0}%
                  </div>
                  <p className="text-sm text-muted-foreground">across all frameworks</p>
                  <Progress value={scanResults.length > 0 ? Math.round(scanResults.reduce((acc, r) => acc + r.score, 0) / scanResults.length) : 0} className="mt-2" />
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Critical Issues</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold text-red-600">
                    {scanResults.reduce((acc, r) => acc + r.findings.filter(f => f.severity === 'critical').length, 0)}
                  </div>
                  <p className="text-sm text-muted-foreground">require immediate attention</p>
                  <div className="text-xs text-red-600 mt-1">
                    {scanResults.reduce((acc, r) => acc + r.findings.filter(f => f.severity === 'high').length, 0)} high priority
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Real-time Monitoring */}
            {realTimeMonitoring && (
              <Card>
                <CardHeader>
                  <CardTitle>Real-time Monitoring</CardTitle>
                  <CardDescription>Live agent status and system health</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {agents.filter(a => a.status === 'online').slice(0, 3).map(agent => (
                      <div key={agent.id} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium">{agent.name}</h4>
                          <div className={`w-2 h-2 rounded-full ${getStatusColor(agent.status)}`} />
                        </div>
                        <div className="space-y-2">
                          <div>
                            <div className="flex justify-between text-sm">
                              <span>CPU</span>
                              <span>{agent.cpuUsage}%</span>
                            </div>
                            <Progress value={agent.cpuUsage} className="h-1" />
                          </div>
                          <div>
                            <div className="flex justify-between text-sm">
                              <span>Memory</span>
                              <span>{agent.memoryUsage}%</span>
                            </div>
                            <Progress value={agent.memoryUsage} className="h-1" />
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Compliance Frameworks Overview */}
            <Card>
              <CardHeader>
                <CardTitle>Supported Compliance Frameworks</CardTitle>
                <CardDescription>Enterprise-grade compliance standards with AI-powered analysis</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  {COMPLIANCE_FRAMEWORKS.map(framework => (
                    <div key={framework.id} className="border rounded-lg p-4 hover:shadow-md transition-shadow">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="font-semibold">{framework.name}</h3>
                        <Badge className={getSeverityColor(framework.severity)}>
                          {framework.severity}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground mb-2">{framework.description}</p>
                      <div className="flex justify-between text-xs text-muted-foreground">
                        <span>{framework.controls} controls</span>
                        <span>{framework.categories.length} categories</span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Recent Scan Results */}
            {scanResults.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Recent Scan Results</CardTitle>
                  <CardDescription>Latest compliance audit results</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {scanResults.slice(0, 5).map(result => (
                      <div key={result.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <p className="font-medium">{result.target}</p>
                            <Badge variant="outline">{result.framework}</Badge>
                          </div>
                          <p className="text-sm text-muted-foreground">
                            {result.timestamp} • {result.executionTime}ms • {result.findings.length} findings
                          </p>
                        </div>
                        <div className="text-right">
                          <div className={`text-2xl font-bold ${getScoreColor(result.score)}`}>
                            {result.score}%
                          </div>
                          <Badge variant={result.status === 'completed' ? 'default' : result.status === 'running' ? 'secondary' : 'destructive'}>
                            {result.status}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Local Scan Tab */}
          <TabsContent value="local-scan" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Local Security Scan</CardTitle>
                <CardDescription>Comprehensive compliance scanning for individual targets</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="target">Target URL or IP Address</Label>
                      <Input
                        id="target"
                        placeholder="https://example.com or 192.168.1.1"
                        value={localTarget}
                        onChange={(e) => setLocalTarget(e.target.value)}
                        disabled={loading}
                      />
                    </div>

                    <div>
                      <Label>Scan Depth</Label>
                      <Select value={scanDepth} onValueChange={setScanDepth}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="basic">Basic Scan</SelectItem>
                          <SelectItem value="standard">Standard Scan</SelectItem>
                          <SelectItem value="comprehensive">Comprehensive Scan</SelectItem>
                          <SelectItem value="deep">Deep Scan</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-3">
                      <div className="flex items-center space-x-2">
                            <Checkbox
                              id="vuln-scan"
                              checked={includeVulnScan}
                              onCheckedChange={(checked) => setIncludeVulnScan(checked === true)}
                            />
                        <Label htmlFor="vuln-scan">Include Vulnerability Scanning</Label>
                      </div>
                      <div className="flex items-center space-x-2">
                            <Checkbox
                              id="pen-test"
                              checked={includePenetrationTest}
                              onCheckedChange={(checked) => setIncludePenetrationTest(checked === true)}
                            />
                        <Label htmlFor="pen-test">Include Penetration Testing</Label>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <Label>Compliance Frameworks</Label>
                      <div className="grid grid-cols-2 gap-2 mt-2 max-h-48 overflow-y-auto">
                        {COMPLIANCE_FRAMEWORKS.map(framework => (
                          <div key={framework.id} className="flex items-center space-x-2">
                            <Checkbox
                              id={framework.id}
                              checked={selectedFrameworks.includes(framework.id)}
                              onCheckedChange={() => handleFrameworkToggle(framework.id)}
                            />
                            <Label htmlFor={framework.id} className="text-sm">
                              {framework.name}
                            </Label>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedFrameworks(COMPLIANCE_FRAMEWORKS.map(f => f.id))}
                      >
                        Select All
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedFrameworks([])}
                      >
                        Clear All
                      </Button>
                    </div>
                  </div>
                </div>

                {error && (
                  <Alert>
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}

                <Button onClick={handleLocalScan} disabled={loading} className="w-full">
                  {loading ? "Scanning..." : "Start Compliance Scan"}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Remote Audit Tab */}
          <TabsContent value="remote-audit" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Distributed Remote Audit</CardTitle>
                <CardDescription>Execute compliance audits across multiple agents simultaneously</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div>
                      <Label>Select Audit Agents</Label>
                      <div className="space-y-2 mt-2 max-h-48 overflow-y-auto border rounded-lg p-3">
                        {agents.map(agent => (
                          <div key={agent.id} className="flex items-center justify-between p-2 hover:bg-muted rounded">
                            <div className="flex items-center space-x-3">
                              <Checkbox
                                id={agent.id}
                                checked={selectedAgents.includes(agent.id)}
                                onCheckedChange={() => handleAgentToggle(agent.id)}
                                disabled={agent.status === 'offline'}
                              />
                              <div>
                                <Label htmlFor={agent.id} className="font-medium">
                                  {agent.name}
                                </Label>
                                <p className="text-xs text-muted-foreground">
                                  {agent.location} • {agent.os}
                                </p>
                              </div>
                            </div>
                            <div className={`w-2 h-2 rounded-full ${getStatusColor(agent.status)}`} />
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <Label>Compliance Frameworks</Label>
                      <div className="grid grid-cols-2 gap-2 mt-2">
                        {COMPLIANCE_FRAMEWORKS.slice(0, 6).map(framework => (
                          <div key={framework.id} className="flex items-center space-x-2">
                            <Checkbox
                              id={`remote-${framework.id}`}
                              checked={selectedFrameworks.includes(framework.id)}
                              onCheckedChange={() => handleFrameworkToggle(framework.id)}
                            />
                            <Label htmlFor={`remote-${framework.id}`} className="text-sm">
                              {framework.name}
                            </Label>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="custom-script">Custom Audit Script</Label>
                      <Textarea
                        id="custom-script"
                        placeholder="#!/bin/bash&#10;# Custom audit commands&#10;echo 'Running custom compliance check...'&#10;# Add your audit logic here"
                        value={customScript}
                        onChange={(e) => setCustomScript(e.target.value)}
                        rows={6}
                      />
                    </div>

                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <Label htmlFor="scheduled">Scheduled Scanning</Label>
                        <Switch
                          id="scheduled"
                          checked={scheduledScan}
                          onCheckedChange={setScheduledScan}
                        />
                      </div>

                      {scheduledScan && (
                        <div>
                          <Label>Scan Interval</Label>
                          <Select value={scanInterval} onValueChange={setScanInterval}>
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="hourly">Hourly</SelectItem>
                              <SelectItem value="daily">Daily</SelectItem>
                              <SelectItem value="weekly">Weekly</SelectItem>
                              <SelectItem value="monthly">Monthly</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {error && (
                  <Alert>
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}

                <Button onClick={handleRemoteAudit} disabled={loading} className="w-full">
                  {loading ? "Executing Remote Audit..." : "Start Remote Audit"}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Agent Network Tab */}
          <TabsContent value="agents" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Agent Network Management</CardTitle>
                <CardDescription>Monitor and manage distributed audit agents</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Agent</TableHead>
                      <TableHead>Location</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Capabilities</TableHead>
                      <TableHead>System</TableHead>
                      <TableHead>Performance</TableHead>
                      <TableHead>Last Seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {agents.map(agent => (
                      <TableRow key={agent.id}>
                        <TableCell>
                          <div>
                            <div className="font-medium">{agent.name}</div>
                            <div className="text-sm text-muted-foreground">{agent.id}</div>
                          </div>
                        </TableCell>
                        <TableCell>{agent.location}</TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <div className={`w-2 h-2 rounded-full ${getStatusColor(agent.status)}`} />
                            <span className="capitalize">{agent.status}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {agent.capabilities.slice(0, 2).map(cap => (
                              <Badge key={cap} variant="outline" className="text-xs">
                                {cap}
                              </Badge>
                            ))}
                            {agent.capabilities.length > 2 && (
                              <Badge variant="outline" className="text-xs">
                                +{agent.capabilities.length - 2}
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div>
                            <div className="text-sm">{agent.os}</div>
                            <div className="text-xs text-muted-foreground">v{agent.version}</div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="space-y-1">
                            <div className="flex items-center gap-2 text-xs">
                              <span>CPU:</span>
                              <div className="w-16 bg-muted rounded-full h-1">
                                <div 
                                  className="bg-primary h-1 rounded-full" 
                                  style={{ width: `${agent.cpuUsage}%` }}
                                />
                              </div>
                              <span>{agent.cpuUsage}%</span>
                            </div>
                            <div className="flex items-center gap-2 text-xs">
                              <span>MEM:</span>
                              <div className="w-16 bg-muted rounded-full h-1">
                                <div 
                                  className="bg-primary h-1 rounded-full" 
                                  style={{ width: `${agent.memoryUsage}%` }}
                                />
                              </div>
                              <span>{agent.memoryUsage}%</span>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="text-sm">
                            {new Date(agent.lastSeen).toLocaleString()}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Reports Tab */}
          <TabsContent value="reports" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Compliance Reports</CardTitle>
                <CardDescription>Generate and export detailed compliance reports</CardDescription>
              </CardHeader>
              <CardContent>
                {scanResults.length === 0 ? (
                  <div className="text-center py-8">
                    <p className="text-muted-foreground">No scan results available. Run a scan to generate reports.</p>
                  </div>
                ) : (
                  <div className="space-y-6">
                    {scanResults.map(result => (
                      <Card key={result.id}>
                        <CardHeader>
                          <div className="flex items-center justify-between">
                            <div>
                              <CardTitle className="text-lg">{result.target}</CardTitle>
                              <CardDescription>
                                {result.framework} • {result.timestamp}
                              </CardDescription>
                            </div>
                            <div className="text-right">
                              <div className={`text-2xl font-bold ${getScoreColor(result.score)}`}>
                                {result.score}%
                              </div>
                              <Badge variant={result.status === 'completed' ? 'default' : 'destructive'}>
                                {result.status}
                              </Badge>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                            <div className="text-center">
                              <div className="text-lg font-semibold text-green-600">
                                {result.findings.filter(f => f.status === 'pass').length}
                              </div>
                              <div className="text-sm text-muted-foreground">Passed</div>
                            </div>
                            <div className="text-center">
                              <div className="text-lg font-semibold text-red-600">
                                {result.findings.filter(f => f.status === 'fail').length}
                              </div>
                              <div className="text-sm text-muted-foreground">Failed</div>
                            </div>
                            <div className="text-center">
                              <div className="text-lg font-semibold text-yellow-600">
                                {result.findings.filter(f => f.status === 'warning').length}
                              </div>
                              <div className="text-sm text-muted-foreground">Warnings</div>
                            </div>
                          </div>

                          <Separator className="my-4" />

                          <div className="space-y-3">
                            <h4 className="font-semibold">Key Findings</h4>
                            {result.findings.slice(0, 3).map(finding => (
                              <div key={finding.id} className="flex items-start gap-3 p-3 border rounded">
                                <Badge className={getSeverityColor(finding.severity)}>
                                  {finding.severity}
                                </Badge>
                                <div className="flex-1">
                                  <p className="font-medium">{finding.control}</p>
                                  <p className="text-sm text-muted-foreground">{finding.description}</p>
                                </div>
                                <Badge variant={finding.status === 'pass' ? 'default' : finding.status === 'fail' ? 'destructive' : 'secondary'}>
                                  {finding.status}
                                </Badge>
                              </div>
                            ))}
                          </div>

                          <div className="flex gap-2 mt-4">
                            <Button variant="outline" size="sm">
                              Export PDF
                            </Button>
                            <Button variant="outline" size="sm">
                              Export CSV
                            </Button>
                            <Button variant="outline" size="sm">
                              View Details
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Settings Tab */}
          <TabsContent value="settings" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Advanced Settings</CardTitle>
                <CardDescription>Configure advanced audit features and AI capabilities</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <h3 className="font-semibold">Monitoring & Automation</h3>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="real-time">Real-time Monitoring</Label>
                        <p className="text-sm text-muted-foreground">
                          Continuously monitor agent status and system health
                        </p>
                      </div>
                      <Switch
                        id="real-time"
                        checked={realTimeMonitoring}
                        onCheckedChange={setRealTimeMonitoring}
                      />
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="auto-remediation">Auto Remediation</Label>
                        <p className="text-sm text-muted-foreground">
                          Automatically fix common compliance issues
                        </p>
                      </div>
                      <Switch
                        id="auto-remediation"
                        checked={autoRemediation}
                        onCheckedChange={setAutoRemediation}
                      />
                    </div>

                    <div>
                      <Label htmlFor="alert-threshold">Alert Threshold</Label>
                      <div className="flex items-center gap-4 mt-2">
                        <input
                          type="range"
                          id="alert-threshold"
                          min="0"
                          max="100"
                          value={alertThreshold}
                          onChange={(e) => setAlertThreshold(Number(e.target.value))}
                          className="flex-1"
                        />
                        <span className="text-sm font-medium w-12">{alertThreshold}%</span>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        Trigger alerts when compliance score falls below this threshold
                      </p>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h3 className="font-semibold">AI & Intelligence</h3>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="ai-analysis">AI-Powered Analysis</Label>
                        <p className="text-sm text-muted-foreground">
                          Use machine learning for advanced threat detection
                        </p>
                      </div>
                      <Switch
                        id="ai-analysis"
                        checked={aiAnalysis}
                        onCheckedChange={setAiAnalysis}
                      />
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <Label htmlFor="threat-intel">Threat Intelligence</Label>
                        <p className="text-sm text-muted-foreground">
                          Integrate with threat intelligence feeds
                        </p>
                      </div>
                      <Switch
                        id="threat-intel"
                        checked={threatIntelligence}
                        onCheckedChange={setThreatIntelligence}
                      />
                    </div>

                    <div className="p-4 border rounded-lg bg-muted/50">
                      <h4 className="font-medium mb-2">Enterprise Features</h4>
                      <ul className="text-sm text-muted-foreground space-y-1">
                        <li>• Custom compliance frameworks</li>
                        <li>• Advanced reporting & analytics</li>
                        <li>• SIEM integration</li>
                        <li>• Multi-tenant support</li>
                        <li>• API access & webhooks</li>
                      </ul>
                    </div>
                  </div>
                </div>

                <Separator />

                <div className="flex gap-4">
                  <Button>Save Settings</Button>
                  <Button variant="outline">Reset to Defaults</Button>
                  <Button variant="outline">Export Configuration</Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
