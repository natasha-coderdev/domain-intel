'use client';
import { useState, useEffect } from 'react';
import { Search, Globe, Server, Shield, MapPin, Copy, Check, Loader2, AlertCircle, Lock, Mail, Clock, Download, ChevronDown, ChevronUp, AlertTriangle, CheckCircle, XCircle, Info, History, Trash2, Users, ArrowRight, Wrench } from 'lucide-react';

export default function Home() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('whois');
  const [results, setResults] = useState<any>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState('');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [expandedFixes, setExpandedFixes] = useState<Record<number, boolean>>({});
  const [history, setHistory] = useState<{query:string,timestamp:number}[]>([]);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem('lookupHistory');
    if (saved) setHistory(JSON.parse(saved));
  }, []);

  const toggle = (id: string) => setExpanded(p => ({ ...p, [id]: !p[id] }));
  const toggleFix = (idx: number) => setExpandedFixes(p => ({ ...p, [idx]: !p[idx] }));
  const copy = (text: string, key: string) => { navigator.clipboard.writeText(text); setCopied(key); setTimeout(() => setCopied(''), 2000); };
  const exportJSON = () => { if (!results) return; const b = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' }); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href = u; a.download = `${results.query}-${Date.now()}.json`; a.click(); };
  const clearHistory = () => { localStorage.removeItem('lookupHistory'); setHistory([]); };

  const lookup = async (q?: string) => {
    const search = q || query;
    if (!search.trim()) return;
    setLoading(true); setError(''); setResults(null); setShowHistory(false);
    try {
      const res = await fetch(`/api/lookup?q=${encodeURIComponent(search.trim())}`);
      const data = await res.json();
      if (data.error) { setError(data.error); }
      else {
        setResults(data);
        setActiveTab(data.isIP ? 'ip' : 'whois');
        const newHist = [{ query: data.query, timestamp: Date.now() }, ...history.filter(h => h.query !== data.query).slice(0, 19)];
        setHistory(newHist);
        localStorage.setItem('lookupHistory', JSON.stringify(newHist));
      }
    } catch { setError('Lookup failed. Please try again.'); }
    setLoading(false);
  };

  const fmtDate = (d: string) => { if (!d || d === 'N/A') return 'N/A'; try { const dt = new Date(d); return isNaN(dt.getTime()) ? d : dt.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); } catch { return d; } };

  const Badge = ({ status, text }: { status: 'good'|'warning'|'bad'|'info'; text: string }) => {
    const s = { good: 'bg-green-100 text-green-700', warning: 'bg-yellow-100 text-yellow-700', bad: 'bg-red-100 text-red-700', info: 'bg-blue-100 text-blue-700' };
    const i = { good: <CheckCircle size={12}/>, warning: <AlertTriangle size={12}/>, bad: <XCircle size={12}/>, info: <Info size={12}/> };
    return <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${s[status]}`}>{i[status]} {text}</span>;
  };

  const CopyBtn = ({ text, k }: { text: string; k: string }) => (
    <button onClick={() => copy(text, k)} className="p-1 hover:bg-gray-200 rounded">{copied === k ? <Check size={14} className="text-green-600"/> : <Copy size={14} className="text-gray-400"/>}</button>
  );

  const Row = ({ label, value, k, badge }: { label: string; value?: string|null; k: string; badge?: React.ReactNode }) => {
    const v = value || 'N/A';
    return <div className="flex justify-between items-start py-2 border-b border-gray-100 last:border-0"><span className="text-gray-500 text-sm">{label}</span><div className="flex items-center gap-2">{badge}<span className="text-gray-900 text-sm font-medium text-right max-w-xs truncate">{v}</span>{v !== 'N/A' && <CopyBtn text={v} k={k}/>}</div></div>;
  };

  const Section = ({ id, title, icon: Icon, children, open = true, color = 'text-blue-500' }: any) => {
    const isOpen = expanded[id] ?? open;
    return <div className="bg-gray-50 rounded-xl overflow-hidden"><button onClick={() => toggle(id)} className="w-full flex items-center justify-between p-4 hover:bg-gray-100"><h3 className="font-semibold text-gray-900 flex items-center gap-2"><Icon size={16} className={color}/> {title}</h3>{isOpen ? <ChevronUp size={16} className="text-gray-400"/> : <ChevronDown size={16} className="text-gray-400"/>}</button>{isOpen && <div className="px-4 pb-4">{children}</div>}</div>;
  };

  // Count various entries
  const blacklistCount = results?.blacklists?.filter((b: any) => b.listed).length || 0;
  const subdomainCount = results?.subdomains?.length || 0;
  const sharedHostingCount = results?.sharedHosting?.length || 0;
  const recommendationCount = results?.recommendations?.length || 0;

  const tabs = results?.isIP 
    ? [
        { id: 'ip', label: 'IP Info', icon: MapPin }, 
        { id: 'blacklist', label: `Blacklist${blacklistCount > 0 ? ` (${blacklistCount})` : ''}`, icon: Shield },
        { id: 'network', label: 'Network WHOIS', icon: Server },
        { id: 'shared', label: `Shared Hosting${sharedHostingCount > 0 ? ` (${sharedHostingCount})` : ''}`, icon: Users },
        { id: 'security', label: 'Security', icon: Shield },
        { id: 'fixes', label: `Fixes${recommendationCount > 0 ? ` (${recommendationCount})` : ''}`, icon: Wrench }
      ] 
    : [
        { id: 'whois', label: 'WHOIS', icon: Globe }, 
        { id: 'dns', label: 'DNS', icon: Server }, 
        { id: 'ssl', label: 'SSL', icon: Lock }, 
        { id: 'security', label: 'Security', icon: Shield }, 
        { id: 'email', label: 'Email', icon: Mail }, 
        { id: 'ip', label: 'Hosting', icon: MapPin },
        { id: 'subdomains', label: `Subdomains${subdomainCount > 0 ? ` (${subdomainCount})` : ''}`, icon: Globe },
        { id: 'fixes', label: `Fixes${recommendationCount > 0 ? ` (${recommendationCount})` : ''}`, icon: Wrench }
      ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-4 md:p-8">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 mb-4"><Globe className="text-white" size={32}/></div>
          <h1 className="text-3xl font-bold text-white mb-2">Domain Intelligence</h1>
          <p className="text-slate-400">Comprehensive WHOIS, DNS, SSL, and security analysis</p>
        </div>

        <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-2 mb-6 relative">
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={20}/>
              <input type="text" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && !loading && lookup()} onFocus={() => history.length > 0 && setShowHistory(true)} placeholder="Enter domain or IP (e.g., github.com, 8.8.8.8)" className="w-full pl-12 pr-12 py-4 bg-white rounded-xl text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500" disabled={loading}/>
              {history.length > 0 && <button onClick={() => setShowHistory(!showHistory)} className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"><History size={20}/></button>}
            </div>
            <button onClick={() => lookup()} disabled={loading || !query.trim()} className="px-6 py-4 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-semibold rounded-xl hover:opacity-90 disabled:opacity-50 flex items-center gap-2">{loading ? <Loader2 className="animate-spin" size={20}/> : <Search size={20}/>}<span className="hidden sm:inline">Analyze</span></button>
          </div>
          {showHistory && history.length > 0 && (
            <div className="absolute top-full left-0 right-0 mt-2 bg-white rounded-xl shadow-xl z-50 overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 bg-gray-50 border-b"><span className="text-sm font-medium text-gray-700">Recent</span><button onClick={clearHistory} className="text-gray-400 hover:text-red-500"><Trash2 size={16}/></button></div>
              <div className="max-h-64 overflow-y-auto">{history.map((h, i) => <button key={i} onClick={() => { setQuery(h.query); lookup(h.query); }} className="w-full px-4 py-3 text-left hover:bg-gray-50 flex justify-between border-b border-gray-100 last:border-0"><span className="text-gray-900">{h.query}</span><span className="text-xs text-gray-400">{new Date(h.timestamp).toLocaleDateString()}</span></button>)}</div>
            </div>
          )}
        </div>

        {error && <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 mb-6 flex items-center gap-3"><AlertCircle className="text-red-400" size={20}/><span className="text-red-300">{error}</span></div>}
        {loading && <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4 mb-6 flex items-center gap-3"><Loader2 className="text-blue-400 animate-spin" size={20}/><span className="text-blue-300">Analyzing... This may take a few seconds.</span></div>}

        {results && (
          <div className="bg-white rounded-2xl shadow-xl overflow-hidden">
            <div className="bg-gray-50 px-4 py-3 border-b flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-gray-900 font-semibold">{results.query}</span>
                {results.resolvedIP && <span className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded-full">→ {results.resolvedIP}</span>}
                {results.meta?.domainAge && <span className="text-xs bg-purple-100 text-purple-700 px-2 py-1 rounded-full"><Clock size={10} className="inline mr-1"/>{results.meta.domainAge}</span>}
              </div>
              <div className="flex items-center gap-2">
                <button onClick={exportJSON} className="text-xs bg-gray-200 hover:bg-gray-300 text-gray-700 px-3 py-1.5 rounded-full flex items-center gap-1"><Download size={12}/> Export</button>
                <span className={`text-xs px-2 py-1 rounded-full ${results.isIP ? 'bg-purple-100 text-purple-700' : 'bg-green-100 text-green-700'}`}>{results.isIP ? 'IP' : 'Domain'}</span>
              </div>
            </div>

            <div className="flex border-b overflow-x-auto">{tabs.map(t => <button key={t.id} onClick={() => setActiveTab(t.id)} className={`flex items-center gap-2 px-4 py-3 text-sm font-medium whitespace-nowrap ${activeTab === t.id ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50/50' : 'text-gray-500 hover:bg-gray-50'}`}><t.icon size={16}/>{t.label}</button>)}</div>

            <div className="p-4 space-y-4">
              {activeTab === 'whois' && results.whois && (
                <div className="grid md:grid-cols-2 gap-4">
                  <Section id="reg" title="Registration" icon={Shield}><Row label="Domain" value={results.whois.domain} k="domain"/><Row label="Registrar" value={results.whois.registrar} k="registrar"/><Row label="Registrant" value={results.whois.registrant} k="registrant"/><Row label="Created" value={fmtDate(results.whois.created)} k="created"/><Row label="Expires" value={fmtDate(results.whois.expires)} k="expires"/><Row label="Updated" value={fmtDate(results.whois.updated)} k="updated"/>{results.whois.abuseContact && <Row label="Abuse" value={results.whois.abuseContact} k="abuse"/>}</Section>
                  <Section id="ns" title="Nameservers" icon={Server} color="text-green-500">{results.whois.nameservers?.length > 0 ? results.whois.nameservers.slice(0,6).map((ns:string,i:number) => <Row key={i} label={`NS ${i+1}`} value={ns} k={`ns-${i}`}/>) : <p className="text-gray-500 text-sm py-2">Check DNS tab</p>}{results.whois.dnssec && <Row label="DNSSEC" value={results.whois.dnssec} k="dnssec" badge={<Badge status={results.whois.dnssec==='signed'?'good':'warning'} text={results.whois.dnssec}/>}/>}</Section>
                </div>
              )}

              {activeTab === 'dns' && results.dns && (
                <div className="space-y-4">
                  {['A','AAAA','MX','NS','TXT','CAA'].map(type => results.dns[type]?.length > 0 && (
                    <Section key={type} id={`dns-${type}`} title={`${type} Records (${results.dns[type].length})`} icon={Server} open={['A','MX','NS'].includes(type)}>
                      {results.dns[type].map((r:any,i:number) => <div key={i} className="flex justify-between items-center text-sm py-2 border-b border-gray-100 last:border-0"><code className="text-gray-700 bg-white px-2 py-1 rounded text-xs break-all max-w-lg">{r.value}</code><div className="flex items-center gap-2 ml-2"><span className="text-gray-400 text-xs">TTL:{r.ttl}s</span><CopyBtn text={r.value} k={`dns-${type}-${i}`}/></div></div>)}
                    </Section>
                  ))}
                </div>
              )}

              {activeTab === 'ssl' && (
                <div className="grid md:grid-cols-2 gap-4">
                  {results.ssl?.error ? <div className="md:col-span-2 bg-yellow-50 rounded-xl p-4 flex items-center gap-3"><AlertTriangle className="text-yellow-600" size={20}/><span className="text-yellow-800">{results.ssl.error}</span></div> : results.ssl ? <>
                    <Section id="ssl-cert" title="Certificate" icon={Lock} color="text-green-500"><Row label="Status" value={results.ssl.valid?'Valid':'Invalid'} k="ssl-s" badge={<Badge status={results.ssl.valid?'good':'bad'} text={results.ssl.valid?'Valid':'Invalid'}/>}/><Row label="Issuer" value={results.ssl.issuer} k="ssl-i"/><Row label="Subject" value={results.ssl.subject} k="ssl-sub"/><Row label="Valid From" value={fmtDate(results.ssl.validFrom)} k="ssl-f"/><Row label="Valid Until" value={fmtDate(results.ssl.validTo)} k="ssl-t" badge={results.ssl.daysRemaining!==undefined && <Badge status={results.ssl.daysRemaining>30?'good':results.ssl.daysRemaining>7?'warning':'bad'} text={`${results.ssl.daysRemaining}d`}/>}/></Section>
                    <Section id="ssl-det" title="Details" icon={Shield} color="text-purple-500"><Row label="Protocol" value={results.ssl.protocol} k="ssl-p"/><Row label="Key Algo" value={results.ssl.keyAlgorithm} k="ssl-a"/><Row label="Key Size" value={results.ssl.keySize?`${results.ssl.keySize} bits`:undefined} k="ssl-ks"/>{results.ssl.altNames?.length>0 && <div className="py-2"><span className="text-gray-500 text-sm block mb-2">Alt Names ({results.ssl.altNames.length})</span><div className="flex flex-wrap gap-1">{results.ssl.altNames.slice(0,5).map((n:string,i:number)=><span key={i} className="text-xs bg-gray-200 px-2 py-1 rounded">{n}</span>)}{results.ssl.altNames.length>5&&<span className="text-xs bg-gray-200 px-2 py-1 rounded">+{results.ssl.altNames.length-5}</span>}</div></div>}</Section>
                  </> : <div className="md:col-span-2 text-center py-8 text-gray-500">No SSL data</div>}
                </div>
              )}

              {activeTab === 'security' && results.security && (
                <div className="space-y-4">
                  {results.security.score !== undefined && <div className="bg-gray-50 rounded-xl p-4"><div className="flex items-center gap-4"><div className={`text-4xl font-bold ${results.security.score>=80?'text-green-600':results.security.score>=50?'text-yellow-600':'text-red-600'}`}>{results.security.score}/100</div><div className="flex-1"><div className="text-sm text-gray-600 mb-1">Security Score</div><div className="w-full bg-gray-200 rounded-full h-3"><div className={`h-3 rounded-full ${results.security.score>=80?'bg-green-500':results.security.score>=50?'bg-yellow-500':'bg-red-500'}`} style={{width:`${results.security.score}%`}}/></div></div></div></div>}
                  <Section id="sec-h" title="Security Headers" icon={Shield}>{Object.entries(results.security.headers||{}).map(([k,d]:any)=><div key={k} className="flex justify-between items-center py-2 border-b border-gray-100 last:border-0"><span className="text-gray-700 text-sm">{k}</span><Badge status={d.present?'good':'warning'} text={d.present?'Present':'Missing'}/></div>)}</Section>
                  {results.security.technologies?.length>0 && <Section id="tech" title="Technologies" icon={Server} color="text-purple-500"><div className="flex flex-wrap gap-2">{results.security.technologies.map((t:string,i:number)=><span key={i} className="text-sm bg-blue-100 text-blue-700 px-3 py-1 rounded-full">{t}</span>)}</div></Section>}
                  
                  {/* Blacklist info for domain lookups */}
                  {!results.isIP && results.blacklists && results.blacklists.length > 0 && (
                    <Section id="sec-bl" title="IP Blacklist Status" icon={Shield} color="text-red-500">
                      <div className="space-y-2">
                        {results.blacklists.map((bl: any, i: number) => (
                          <div key={i} className="flex justify-between items-center py-2 border-b border-gray-100 last:border-0">
                            <span className="text-gray-700 text-sm">{bl.name}</span>
                            <Badge status={bl.listed ? 'bad' : 'good'} text={bl.listed ? 'Listed' : 'Clean'} />
                          </div>
                        ))}
                      </div>
                    </Section>
                  )}
                </div>
              )}

              {activeTab === 'email' && results.email && (
                <div className="space-y-4">
                  <Section id="mx" title="Mail Servers" icon={Mail} color="text-orange-500">{results.email.mx?.length>0 ? results.email.mx.map((m:any,i:number)=><Row key={i} label={`Priority ${m.priority}`} value={m.host} k={`mx-${i}`}/>) : <p className="text-gray-500 text-sm py-2">No MX records</p>}</Section>
                  <Section id="auth" title="Authentication" icon={Shield} color="text-green-500">
                    <div className="space-y-3">
                      <div className="p-3 bg-white rounded-lg border"><div className="flex justify-between mb-2"><span className="font-medium">SPF</span><Badge status={results.email.spf?.valid?'good':'warning'} text={results.email.spf?.valid?'Valid':'Missing'}/></div>{results.email.spf?.record && <code className="text-xs text-gray-600 break-all block bg-gray-50 p-2 rounded">{results.email.spf.record}</code>}</div>
                      <div className="p-3 bg-white rounded-lg border"><div className="flex justify-between mb-2"><span className="font-medium">DKIM</span><Badge status={results.email.dkim?.found?'good':'info'} text={results.email.dkim?.found?`Found (${results.email.dkim.selector})`:'Not detected'}/></div></div>
                      <div className="p-3 bg-white rounded-lg border"><div className="flex justify-between mb-2"><span className="font-medium">DMARC</span><Badge status={results.email.dmarc?.valid?'good':'warning'} text={results.email.dmarc?.valid?`Policy: ${results.email.dmarc.policy}`:'Missing'}/></div>{results.email.dmarc?.record && <code className="text-xs text-gray-600 break-all block bg-gray-50 p-2 rounded">{results.email.dmarc.record}</code>}</div>
                    </div>
                  </Section>
                </div>
              )}

              {activeTab === 'ip' && results.ip && (
                <div className="grid md:grid-cols-2 gap-4">
                  <Section id="loc" title="Location" icon={MapPin} color="text-red-500"><Row label="IP" value={results.ip.ip} k="ip"/><Row label="City" value={results.ip.city} k="city"/><Row label="Region" value={results.ip.region} k="region"/><Row label="Country" value={results.ip.country} k="country"/><Row label="Postal" value={results.ip.postal} k="postal"/><Row label="Timezone" value={results.ip.timezone} k="tz"/>{results.ip.lat&&results.ip.lon&&<Row label="Coords" value={`${results.ip.lat}, ${results.ip.lon}`} k="coords"/>}{results.ip.reverseDns&&<Row label="rDNS" value={results.ip.reverseDns} k="rdns"/>}</Section>
                  <Section id="net" title="Network" icon={Server} color="text-purple-500"><Row label="ISP" value={results.ip.isp} k="isp"/><Row label="Org" value={results.ip.org} k="org"/><Row label="ASN" value={results.ip.asn} k="asn"/>{results.ip.isHosting!==undefined&&<div className="flex justify-between items-center py-2 border-b border-gray-100"><span className="text-gray-500 text-sm">Type</span><Badge status="info" text={results.ip.isHosting?'Datacenter':'Residential'}/></div>}{results.ip.isProxy&&<div className="flex justify-between items-center py-2"><span className="text-gray-500 text-sm">Proxy/VPN</span><Badge status="warning" text="Detected"/></div>}</Section>
                  
                  {/* Redirects section for domain lookups */}
                  {!results.isIP && results.redirects && results.redirects.length > 0 && (
                    <Section id="redirects" title={`Redirects (${results.redirects.length} hops)`} icon={ArrowRight} color="text-orange-500">
                      <div className="space-y-2">
                        {results.redirects.map((r: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 py-2 border-b border-gray-100 last:border-0">
                            <span className={`text-xs px-2 py-0.5 rounded font-mono ${r.status >= 300 && r.status < 400 ? 'bg-yellow-100 text-yellow-700' : r.status >= 200 && r.status < 300 ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-700'}`}>{r.status}</span>
                            <code className="text-xs text-gray-600 break-all flex-1">{r.url}</code>
                            {i < results.redirects.length - 1 && <ArrowRight size={12} className="text-gray-400 flex-shrink-0" />}
                          </div>
                        ))}
                      </div>
                    </Section>
                  )}
                  
                  {/* Shared Hosting section for domain lookups */}
                  {!results.isIP && results.sharedHosting && results.sharedHosting.length > 0 && (
                    <Section id="shared-hosting" title={`Shared Hosting (${results.sharedHosting.length} domains)`} icon={Users} color="text-blue-500">
                      <div className="max-h-48 overflow-y-auto">
                        {results.sharedHosting.slice(0, 20).map((domain: string, i: number) => (
                          <div key={i} className="flex justify-between items-center py-1.5 border-b border-gray-100 last:border-0">
                            <span className="text-gray-700 text-sm">{domain}</span>
                            <CopyBtn text={domain} k={`shared-${i}`} />
                          </div>
                        ))}
                        {results.sharedHosting.length > 20 && (
                          <p className="text-gray-400 text-xs py-2 text-center">+{results.sharedHosting.length - 20} more domains</p>
                        )}
                      </div>
                    </Section>
                  )}
                </div>
              )}

              {/* Subdomains tab for domain lookups */}
              {activeTab === 'subdomains' && !results.isIP && (
                <div className="space-y-4">
                  <Section id="subdomains" title={`Discovered Subdomains (${results.subdomains?.length || 0})`} icon={Globe} color="text-green-500">
                    {results.subdomains?.length > 0 ? (
                      <div className="max-h-96 overflow-y-auto">
                        <div className="grid md:grid-cols-2 gap-x-4">
                          {results.subdomains.map((sub: string, i: number) => (
                            <div key={i} className="flex justify-between items-center py-1.5 border-b border-gray-100 last:border-0">
                              <span className="text-gray-700 text-sm font-mono">{sub}</span>
                              <CopyBtn text={sub} k={`sub-${i}`} />
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <p className="text-gray-500 text-sm py-4 text-center">No subdomains discovered via Certificate Transparency logs</p>
                    )}
                  </Section>
                  <p className="text-gray-400 text-xs text-center">Data sourced from crt.sh Certificate Transparency logs</p>
                </div>
              )}

              {/* Blacklist tab for IP lookups */}
              {activeTab === 'blacklist' && results.isIP && (
                <div className="space-y-4">
                  <Section id="blacklists" title="DNS Blacklist Check" icon={Shield} color="text-red-500">
                    {results.blacklists?.length > 0 ? (
                      <div className="space-y-2">
                        {results.blacklists.map((bl: any, i: number) => (
                          <div key={i} className="flex justify-between items-center py-2 border-b border-gray-100 last:border-0">
                            <div>
                              <span className="text-gray-700 text-sm font-medium">{bl.name}</span>
                              <span className="text-gray-400 text-xs ml-2">({bl.host})</span>
                            </div>
                            <Badge status={bl.listed ? 'bad' : 'good'} text={bl.listed ? 'Listed' : 'Clean'} />
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-gray-500 text-sm py-4 text-center">No blacklist data available</p>
                    )}
                  </Section>
                  <div className="bg-gray-50 rounded-xl p-4 text-center">
                    <div className={`text-2xl font-bold ${blacklistCount === 0 ? 'text-green-600' : 'text-red-600'}`}>
                      {blacklistCount === 0 ? '✓ Clean' : `⚠ Listed on ${blacklistCount} blacklist${blacklistCount > 1 ? 's' : ''}`}
                    </div>
                  </div>
                </div>
              )}

              {/* Network WHOIS tab for IP lookups */}
              {activeTab === 'network' && results.isIP && (
                <div className="space-y-4">
                  <Section id="ip-whois" title="RIR Registration Data" icon={Server} color="text-purple-500">
                    {results.ipWhois ? (
                      <>
                        <Row label="Network Name" value={results.ipWhois.name} k="net-name" />
                        <Row label="Handle" value={results.ipWhois.handle} k="net-handle" />
                        <Row label="CIDR / Range" value={results.ipWhois.cidr} k="net-cidr" />
                        <Row label="Country" value={results.ipWhois.country} k="net-country" />
                        <Row label="Type" value={results.ipWhois.type} k="net-type" />
                        <Row label="Organization" value={results.ipWhois.organization} k="net-org" />
                        {results.ipWhois.abuseContact && <Row label="Abuse Contact" value={results.ipWhois.abuseContact} k="net-abuse" />}
                        {results.ipWhois.registrationDate && <Row label="Registered" value={fmtDate(results.ipWhois.registrationDate)} k="net-reg" />}
                        {results.ipWhois.lastChanged && <Row label="Last Changed" value={fmtDate(results.ipWhois.lastChanged)} k="net-changed" />}
                        {results.ipWhois.parentHandle && <Row label="Parent Handle" value={results.ipWhois.parentHandle} k="net-parent" />}
                      </>
                    ) : (
                      <p className="text-gray-500 text-sm py-4 text-center">No RIR data available</p>
                    )}
                  </Section>
                </div>
              )}

              {/* Shared Hosting tab for IP lookups */}
              {activeTab === 'shared' && results.isIP && (
                <div className="space-y-4">
                  <Section id="shared" title={`Domains on this IP (${results.sharedHosting?.length || 0})`} icon={Users} color="text-blue-500">
                    {results.sharedHosting?.length > 0 ? (
                      <div className="max-h-96 overflow-y-auto">
                        <div className="grid md:grid-cols-2 gap-x-4">
                          {results.sharedHosting.map((domain: string, i: number) => (
                            <div key={i} className="flex justify-between items-center py-1.5 border-b border-gray-100 last:border-0">
                              <span className="text-gray-700 text-sm">{domain}</span>
                              <CopyBtn text={domain} k={`ip-shared-${i}`} />
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <p className="text-gray-500 text-sm py-4 text-center">No other domains found on this IP</p>
                    )}
                  </Section>
                  <p className="text-gray-400 text-xs text-center">Data sourced from HackerTarget reverse IP lookup</p>
                </div>
              )}

              {/* Fixes/Recommendations tab */}
              {activeTab === 'fixes' && (
                <div className="space-y-4">
                  {/* Overall Assessment */}
                  <div className="bg-gradient-to-r from-gray-50 to-gray-100 rounded-xl p-6">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                        <Wrench size={20} className="text-blue-500" />
                        Security Assessment
                      </h3>
                      {results.security?.score !== undefined && (
                        <div className={`text-2xl font-bold ${results.security.score >= 80 ? 'text-green-600' : results.security.score >= 50 ? 'text-yellow-600' : 'text-red-600'}`}>
                          {results.security.score}/100
                        </div>
                      )}
                    </div>
                    <p className="text-gray-600 text-sm">
                      {recommendationCount === 0 ? (
                        '✓ Excellent! No security issues detected. Your configuration follows best practices.'
                      ) : recommendationCount <= 3 ? (
                        `Found ${recommendationCount} recommendation${recommendationCount > 1 ? 's' : ''} to improve your security posture.`
                      ) : recommendationCount <= 6 ? (
                        `Found ${recommendationCount} recommendations. Consider addressing the critical and high priority items first.`
                      ) : (
                        `Found ${recommendationCount} recommendations. Your security configuration needs attention - start with critical issues.`
                      )}
                    </p>
                    {recommendationCount > 0 && (
                      <div className="flex gap-2 mt-3 flex-wrap">
                        {['critical', 'high', 'medium', 'low'].map(sev => {
                          const count = results.recommendations?.filter((r: any) => r.severity === sev).length || 0;
                          if (count === 0) return null;
                          const colors: Record<string, string> = {
                            critical: 'bg-red-100 text-red-700',
                            high: 'bg-orange-100 text-orange-700',
                            medium: 'bg-yellow-100 text-yellow-700',
                            low: 'bg-blue-100 text-blue-700'
                          };
                          return (
                            <span key={sev} className={`px-2 py-1 rounded-full text-xs font-medium ${colors[sev]}`}>
                              {count} {sev}
                            </span>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* Recommendations List */}
                  {results.recommendations?.length > 0 ? (
                    <div className="space-y-3">
                      {results.recommendations.map((rec: any, idx: number) => {
                        const severityColors: Record<string, { bg: string; border: string; badge: string; icon: string }> = {
                          critical: { bg: 'bg-red-50', border: 'border-red-200', badge: 'bg-red-100 text-red-700', icon: 'text-red-500' },
                          high: { bg: 'bg-orange-50', border: 'border-orange-200', badge: 'bg-orange-100 text-orange-700', icon: 'text-orange-500' },
                          medium: { bg: 'bg-yellow-50', border: 'border-yellow-200', badge: 'bg-yellow-100 text-yellow-700', icon: 'text-yellow-600' },
                          low: { bg: 'bg-blue-50', border: 'border-blue-200', badge: 'bg-blue-100 text-blue-700', icon: 'text-blue-500' }
                        };
                        const colors = severityColors[rec.severity] || severityColors.low;
                        const isExpanded = expandedFixes[idx] || false;

                        return (
                          <div key={idx} className={`rounded-xl border ${colors.border} ${colors.bg} overflow-hidden`}>
                            <button
                              onClick={() => toggleFix(idx)}
                              className="w-full p-4 text-left hover:bg-white/50 transition-colors"
                            >
                              <div className="flex items-start gap-3">
                                <div className={`mt-0.5 ${colors.icon}`}>
                                  {rec.severity === 'critical' ? <XCircle size={18} /> : 
                                   rec.severity === 'high' ? <AlertTriangle size={18} /> :
                                   rec.severity === 'medium' ? <AlertCircle size={18} /> :
                                   <Info size={18} />}
                                </div>
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 flex-wrap mb-1">
                                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors.badge}`}>
                                      {rec.severity.toUpperCase()}
                                    </span>
                                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-gray-200 text-gray-700">
                                      {rec.category}
                                    </span>
                                  </div>
                                  <h4 className="font-semibold text-gray-900">{rec.title}</h4>
                                  <p className="text-sm text-gray-600 mt-1">{rec.description}</p>
                                  <div className="flex items-center gap-1 mt-2 text-xs text-gray-500">
                                    <Shield size={12} />
                                    <span>{rec.impact}</span>
                                  </div>
                                </div>
                                <div className="text-gray-400 flex-shrink-0">
                                  {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                                </div>
                              </div>
                            </button>
                            
                            {isExpanded && (
                              <div className="px-4 pb-4 pt-0">
                                <div className="bg-gray-900 rounded-lg p-4 relative">
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="text-xs text-gray-400 font-medium">Fix / Configuration</span>
                                    <button
                                      onClick={() => copy(rec.fix, `fix-${idx}`)}
                                      className="flex items-center gap-1 px-2 py-1 rounded bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs"
                                    >
                                      {copied === `fix-${idx}` ? <Check size={12} /> : <Copy size={12} />}
                                      {copied === `fix-${idx}` ? 'Copied!' : 'Copy'}
                                    </button>
                                  </div>
                                  <pre className="text-sm text-gray-100 font-mono whitespace-pre-wrap overflow-x-auto">
                                    {rec.fix}
                                  </pre>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="bg-green-50 border border-green-200 rounded-xl p-8 text-center">
                      <CheckCircle size={48} className="text-green-500 mx-auto mb-3" />
                      <h3 className="text-lg font-semibold text-green-800">All Clear!</h3>
                      <p className="text-green-600 text-sm mt-1">
                        No security recommendations at this time. Your configuration looks good.
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
        <p className="text-center text-slate-500 text-xs mt-6">Domain Intelligence Pro • No API keys required</p>
      </div>
    </div>
  );
}
