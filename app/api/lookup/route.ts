import { NextRequest, NextResponse } from 'next/server';
import * as https from 'https';
import * as tls from 'tls';

// Security header recommendations database
const HEADER_RECOMMENDATIONS: Record<string, {
  description: string;
  recommended: string;
  impact: string;
  apache: string;
  nginx: string;
  cloudflare: string;
}> = {
  'Strict-Transport-Security': {
    description: 'Forces browsers to use HTTPS for all future requests to the domain, preventing protocol downgrade attacks and cookie hijacking.',
    recommended: 'max-age=31536000; includeSubDomains; preload',
    impact: 'Prevents man-in-the-middle attacks, SSL stripping, and ensures all traffic is encrypted.',
    apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    cloudflare: 'Go to SSL/TLS → Edge Certificates → Enable "Always Use HTTPS" and configure HSTS in the dashboard'
  },
  'Content-Security-Policy': {
    description: 'Controls which resources the browser is allowed to load, preventing XSS attacks and data injection.',
    recommended: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
    impact: 'Prevents cross-site scripting (XSS), clickjacking, and other code injection attacks.',
    apache: `Header set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"`,
    nginx: `add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;`,
    cloudflare: 'Use Transform Rules or Workers to add the header, or configure in Page Rules'
  },
  'X-Frame-Options': {
    description: 'Prevents the page from being embedded in iframes, protecting against clickjacking attacks.',
    recommended: 'DENY',
    impact: 'Prevents clickjacking attacks where malicious sites overlay invisible iframes.',
    apache: 'Header always set X-Frame-Options "DENY"',
    nginx: 'add_header X-Frame-Options "DENY" always;',
    cloudflare: 'Use Transform Rules → Modify Response Header → Add "X-Frame-Options: DENY"'
  },
  'X-Content-Type-Options': {
    description: 'Prevents browsers from MIME-sniffing a response away from the declared content-type.',
    recommended: 'nosniff',
    impact: 'Prevents MIME type confusion attacks that could lead to XSS.',
    apache: 'Header always set X-Content-Type-Options "nosniff"',
    nginx: 'add_header X-Content-Type-Options "nosniff" always;',
    cloudflare: 'Use Transform Rules → Modify Response Header → Add "X-Content-Type-Options: nosniff"'
  },
  'X-XSS-Protection': {
    description: 'Legacy XSS filter built into older browsers. While deprecated, still useful for older browser support.',
    recommended: '1; mode=block',
    impact: 'Enables browser XSS filtering in legacy browsers that support it.',
    apache: 'Header always set X-XSS-Protection "1; mode=block"',
    nginx: 'add_header X-XSS-Protection "1; mode=block" always;',
    cloudflare: 'Use Transform Rules → Modify Response Header → Add "X-XSS-Protection: 1; mode=block"'
  },
  'Referrer-Policy': {
    description: 'Controls how much referrer information is included with requests.',
    recommended: 'strict-origin-when-cross-origin',
    impact: 'Prevents leaking sensitive URL data to third parties while maintaining functionality.',
    apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    cloudflare: 'Use Transform Rules → Modify Response Header → Add "Referrer-Policy: strict-origin-when-cross-origin"'
  },
  'Permissions-Policy': {
    description: 'Controls which browser features and APIs can be used on the page.',
    recommended: 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
    impact: 'Limits attack surface by disabling potentially dangerous browser APIs.',
    apache: 'Header always set Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"',
    nginx: 'add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;',
    cloudflare: 'Use Transform Rules → Modify Response Header → Add the Permissions-Policy header'
  }
};

interface Recommendation {
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  title: string;
  description: string;
  fix: string;
  impact: string;
}

function generateRecommendations(data: {
  isIP: boolean;
  whois?: any;
  dns?: any;
  ssl?: any;
  security?: any;
  email?: any;
  blacklists?: any[];
  ipWhois?: any;
}): Recommendation[] {
  const recommendations: Recommendation[] = [];

  // SSL Recommendations
  if (data.ssl && !data.ssl.error) {
    if (data.ssl.daysRemaining !== undefined && data.ssl.daysRemaining <= 7) {
      recommendations.push({
        severity: 'critical',
        category: 'SSL',
        title: 'SSL Certificate Expiring Imminently',
        description: `Your SSL certificate expires in ${data.ssl.daysRemaining} days. An expired certificate will cause browsers to show security warnings and block access.`,
        fix: `# Renew your SSL certificate immediately

# For Let's Encrypt with Certbot:
sudo certbot renew --force-renewal

# For other CAs, generate a new CSR:
openssl req -new -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr

# Then submit to your CA and install the new certificate`,
        impact: 'Prevents site access blocking, security warnings, and loss of user trust.'
      });
    } else if (data.ssl.daysRemaining !== undefined && data.ssl.daysRemaining <= 30) {
      recommendations.push({
        severity: 'high',
        category: 'SSL',
        title: 'SSL Certificate Expiring Soon',
        description: `Your SSL certificate expires in ${data.ssl.daysRemaining} days. Plan renewal to avoid service disruption.`,
        fix: `# Schedule SSL certificate renewal

# For Let's Encrypt, verify auto-renewal is set up:
sudo certbot renew --dry-run

# Set up a cron job for automatic renewal:
0 0 1 * * certbot renew --quiet`,
        impact: 'Ensures uninterrupted HTTPS access and maintains user trust.'
      });
    }
    
    if (!data.ssl.valid) {
      recommendations.push({
        severity: 'critical',
        category: 'SSL',
        title: 'Invalid SSL Certificate',
        description: 'Your SSL certificate is invalid. This could be due to expiration, hostname mismatch, or certificate chain issues.',
        fix: `# Debug SSL certificate issues:
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Common fixes:
# 1. Renew if expired
# 2. Ensure certificate matches domain
# 3. Install full certificate chain (intermediate certs)

# Install intermediate certificates:
cat your_certificate.crt intermediate.crt root.crt > fullchain.crt`,
        impact: 'Browsers will block access to your site, causing complete loss of HTTPS traffic.'
      });
    }
  }

  // Security Headers Recommendations
  if (data.security?.headers) {
    const headers = data.security.headers;
    
    for (const [header, info] of Object.entries(headers) as [string, {present: boolean; value: string | null}][]) {
      if (!info.present && HEADER_RECOMMENDATIONS[header]) {
        const rec = HEADER_RECOMMENDATIONS[header];
        const severity = header === 'Strict-Transport-Security' || header === 'Content-Security-Policy' 
          ? 'high' 
          : header === 'X-Frame-Options' || header === 'X-Content-Type-Options'
            ? 'medium'
            : 'low';
        
        recommendations.push({
          severity,
          category: 'Security Headers',
          title: `Missing ${header}`,
          description: rec.description,
          fix: `# Recommended value:
${rec.recommended}

# Apache (.htaccess or httpd.conf):
${rec.apache}

# Nginx (server block):
${rec.nginx}

# Cloudflare:
# ${rec.cloudflare}`,
          impact: rec.impact
        });
      }
    }
    
    if (data.security.score !== undefined && data.security.score < 50) {
      recommendations.push({
        severity: 'high',
        category: 'Security Headers',
        title: 'Low Security Score',
        description: `Your security score is ${data.security.score}/100. Multiple security headers are missing, leaving your site vulnerable to various attacks.`,
        fix: `# Add all recommended security headers at once

# Apache - Add to .htaccess or httpd.conf:
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none';"
</IfModule>

# Nginx - Add to server block:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=()" always;`,
        impact: 'Significantly improves protection against XSS, clickjacking, and other web attacks.'
      });
    }
  }

  // Email Authentication Recommendations
  if (data.email) {
    if (!data.email.spf?.valid) {
      recommendations.push({
        severity: 'high',
        category: 'Email Auth',
        title: 'Missing SPF Record',
        description: 'SPF (Sender Policy Framework) is not configured. This allows attackers to spoof emails from your domain.',
        fix: `# Add SPF record to your DNS

# Basic SPF (allows your domain's MX servers):
v=spf1 mx -all

# If using Google Workspace:
v=spf1 include:_spf.google.com -all

# If using Microsoft 365:
v=spf1 include:spf.protection.outlook.com -all

# If using multiple providers:
v=spf1 include:_spf.google.com include:sendgrid.net -all

# Add as TXT record on your domain root (@)`,
        impact: 'Prevents email spoofing and improves email deliverability.'
      });
    }

    if (!data.email.dkim?.found) {
      recommendations.push({
        severity: 'medium',
        category: 'Email Auth',
        title: 'DKIM Not Detected',
        description: 'DKIM (DomainKeys Identified Mail) signature was not found. DKIM cryptographically signs emails to verify authenticity.',
        fix: `# DKIM setup varies by email provider

# Google Workspace:
# 1. Go to Apps → Google Workspace → Gmail → Authenticate Email
# 2. Generate DKIM key
# 3. Add the TXT record to DNS

# Example DKIM record (selector: google):
# Host: google._domainkey
# Value: v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY

# Microsoft 365:
# 1. Go to Exchange Admin → Protection → DKIM
# 2. Enable DKIM for your domain
# 3. Add the provided CNAME records

# Self-hosted: Use opendkim
sudo apt install opendkim opendkim-tools
opendkim-genkey -s default -d yourdomain.com`,
        impact: 'Proves email authenticity and improves deliverability.'
      });
    }

    if (!data.email.dmarc?.valid) {
      recommendations.push({
        severity: 'high',
        category: 'Email Auth',
        title: 'Missing DMARC Record',
        description: 'DMARC is not configured. Without DMARC, receiving servers have no policy for handling emails that fail SPF/DKIM.',
        fix: `# Add DMARC record to your DNS

# Start with monitoring mode (recommended):
v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc@yourdomain.com; fo=1

# After reviewing reports, move to quarantine:
v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=100

# Finally, enforce rejection:
v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; pct=100

# Add as TXT record on _dmarc.yourdomain.com`,
        impact: 'Prevents email spoofing and phishing attacks using your domain.'
      });
    } else if (data.email.dmarc?.policy === 'none') {
      recommendations.push({
        severity: 'medium',
        category: 'Email Auth',
        title: 'DMARC Policy Set to None',
        description: 'Your DMARC policy is set to "none", which only monitors but doesn\'t protect against spoofed emails.',
        fix: `# Upgrade your DMARC policy

# Review your DMARC reports first, then upgrade to quarantine:
v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=25

# Gradually increase pct to 100, then move to reject:
v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; pct=100

# Update the TXT record on _dmarc.yourdomain.com`,
        impact: 'Enforces email authentication and blocks spoofed messages.'
      });
    }

    if (!data.email.mx?.length) {
      recommendations.push({
        severity: 'low',
        category: 'Email Auth',
        title: 'No MX Records Found',
        description: 'No mail exchange (MX) records are configured. The domain cannot receive email.',
        fix: `# Add MX records to your DNS

# For Google Workspace:
@ MX 1 aspmx.l.google.com
@ MX 5 alt1.aspmx.l.google.com
@ MX 5 alt2.aspmx.l.google.com
@ MX 10 alt3.aspmx.l.google.com
@ MX 10 alt4.aspmx.l.google.com

# For Microsoft 365:
@ MX 0 yourdomain-com.mail.protection.outlook.com

# For self-hosted:
@ MX 10 mail.yourdomain.com`,
        impact: 'Enables email delivery to the domain.'
      });
    }
  }

  // DNS/DNSSEC Recommendations
  if (data.whois?.dnssec === 'unsigned') {
    recommendations.push({
      severity: 'medium',
      category: 'DNS',
      title: 'DNSSEC Not Enabled',
      description: 'DNSSEC is not configured. DNS responses are not cryptographically signed, making them vulnerable to spoofing.',
      fix: `# Enable DNSSEC with your registrar/DNS provider

# Cloudflare (automatic):
# 1. Go to DNS → Settings → Enable DNSSEC
# 2. Add DS record to your registrar

# For other providers, generate DNSSEC keys:
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE yourdomain.com
dnssec-keygen -a RSASHA256 -b 4096 -n ZONE -f KSK yourdomain.com

# Sign your zone and add DS record to parent

# Verify with:
dig +short DS yourdomain.com`,
      impact: 'Protects against DNS spoofing and cache poisoning attacks.'
    });
  }

  // CAA Records
  if (data.dns?.CAA?.length === 0) {
    recommendations.push({
      severity: 'low',
      category: 'DNS',
      title: 'No CAA Records',
      description: 'CAA (Certificate Authority Authorization) records are not set. Any CA could issue certificates for your domain.',
      fix: `# Add CAA records to restrict certificate issuance

# Allow only Let's Encrypt:
@ CAA 0 issue "letsencrypt.org"
@ CAA 0 issuewild "letsencrypt.org"
@ CAA 0 iodef "mailto:security@yourdomain.com"

# Allow Let's Encrypt and DigiCert:
@ CAA 0 issue "letsencrypt.org"
@ CAA 0 issue "digicert.com"
@ CAA 0 issuewild "letsencrypt.org"
@ CAA 0 iodef "mailto:security@yourdomain.com"

# Verify with:
dig CAA yourdomain.com`,
      impact: 'Prevents unauthorized certificate issuance and potential MITM attacks.'
    });
  }

  // Blacklist Recommendations
  const listedBlacklists = data.blacklists?.filter(b => b.listed) || [];
  if (listedBlacklists.length > 0) {
    recommendations.push({
      severity: 'critical',
      category: 'Reputation',
      title: `IP Listed on ${listedBlacklists.length} Blacklist${listedBlacklists.length > 1 ? 's' : ''}`,
      description: `Your IP is listed on: ${listedBlacklists.map(b => b.name).join(', ')}. This can cause email delivery failures and reputation issues.`,
      fix: `# Steps to delist your IP:

${listedBlacklists.map(bl => `# ${bl.name} (${bl.host}):
# Check listing reason: https://mxtoolbox.com/blacklists.aspx
# Request removal at the blacklist's website`).join('\n\n')}

# General steps:
# 1. Identify and fix the cause (malware, spam, open relay)
# 2. Scan server for malware: clamscan -r /
# 3. Check for open relay: telnet yourserver 25
# 4. Review mail logs: tail -f /var/log/mail.log
# 5. Request delisting from each blacklist
# 6. Monitor for re-listing

# Spamhaus removal: https://www.spamhaus.org/lookup/
# SpamCop removal: https://www.spamcop.net/bl.shtml
# Barracuda removal: https://www.barracudacentral.org/lookups`,
      impact: 'Restores email deliverability and domain reputation.'
    });
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  recommendations.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return recommendations;
}

const isIP = (s: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s.trim());
const extractDomain = (s: string) => s.trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0];
const calcAge = (c: string) => { try { const d = new Date(c); if (isNaN(d.getTime())) return null; const y = Math.floor((Date.now()-d.getTime())/(365.25*24*60*60*1000)); const m = Math.floor(((Date.now()-d.getTime())%(365.25*24*60*60*1000))/(30.44*24*60*60*1000)); return y>0?`${y}y ${m}m old`:`${m}m old`; } catch { return null; } };
const reverseIP = (ip: string) => ip.split('.').reverse().join('.');

async function fetchDNS(domain: string) {
  const types = ['A','AAAA','MX','NS','TXT','CAA'] as const;
  const tMap: Record<string,number> = {A:1,AAAA:28,MX:15,NS:2,TXT:16,CAA:257};
  const rec: Record<string,{value:string,ttl:number}[]> = {};
  await Promise.all(types.map(async t => {
    try { const r = await fetch(`https://dns.google/resolve?name=${domain}&type=${t}`); const d = await r.json();
      rec[t] = d.Status===0 && d.Answer ? d.Answer.filter((a:any)=>a.type===tMap[t]).map((a:any)=>({value:String(a.data||'').replace(/^"|"$/g,''),ttl:a.TTL})) : [];
    } catch { rec[t]=[]; }
  }));
  return rec;
}

async function fetchReverseDNS(ip: string) {
  try { const r = ip.split('.').reverse().join('.'); const res = await fetch(`https://dns.google/resolve?name=${r}.in-addr.arpa&type=PTR`); const d = await res.json(); return d.Status===0 && d.Answer ? d.Answer[0]?.data?.replace(/\.$/,'') : null; } catch { return null; }
}

async function fetchWhois(domain: string) {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`,{headers:{Accept:'application/json'}});
    if (!res.ok) throw new Error('RDAP failed');
    const d = await res.json();
    const findE = (roles:string[]) => d.entities?.find((e:any)=>e.roles?.some((r:string)=>roles.includes(r)));
    const getV = (e:any,f:string) => e?.vcardArray?.[1]?.find((v:any)=>v[0]===f)?.[3];
    const regE = findE(['registrar']), rntE = findE(['registrant']), abuE = findE(['abuse']);
    const evts = d.events||[];
    return {
      domain: d.ldhName||domain,
      registrar: getV(regE,'fn')||regE?.publicIds?.[0]?.identifier||'N/A',
      registrant: getV(rntE,'fn')||'Redacted for Privacy',
      created: evts.find((e:any)=>e.eventAction==='registration')?.eventDate||'N/A',
      expires: evts.find((e:any)=>e.eventAction==='expiration')?.eventDate||'N/A',
      updated: evts.find((e:any)=>e.eventAction==='last changed'||e.eventAction==='last update of RDAP database')?.eventDate||'N/A',
      nameservers: d.nameservers?.map((n:any)=>n.ldhName?.toLowerCase())||[],
      status: d.status||[],
      dnssec: d.secureDNS?.delegationSigned?'signed':'unsigned',
      abuseContact: getV(abuE,'email')||null
    };
  } catch { return {domain,registrar:'N/A',registrant:'N/A',created:'N/A',expires:'N/A',updated:'N/A',nameservers:[],status:[],dnssec:'unknown',abuseContact:null}; }
}

async function fetchSSL(domain: string): Promise<any> {
  return new Promise(resolve => {
    try {
      const req = https.request({host:domain,port:443,method:'HEAD',rejectUnauthorized:false,timeout:10000}, res => {
        const sock = res.socket as tls.TLSSocket;
        const cert = sock.getPeerCertificate(true);
        if (!cert||!Object.keys(cert).length) { resolve({error:'No certificate'}); return; }
        const vFrom = new Date(cert.valid_from), vTo = new Date(cert.valid_to), now = new Date();
        const days = Math.floor((vTo.getTime()-now.getTime())/(1000*60*60*24));
        resolve({valid:now>=vFrom&&now<=vTo,issuer:cert.issuer?.O||cert.issuer?.CN||'Unknown',subject:cert.subject?.CN||domain,validFrom:cert.valid_from,validTo:cert.valid_to,daysRemaining:days,serialNumber:cert.serialNumber,protocol:sock.getProtocol?.()||'TLS',keyAlgorithm:cert.asn1Curve||cert.bits?'RSA':'ECDSA',keySize:cert.bits||null,signatureAlgorithm:(cert as any).signatureAlgorithm||'Unknown',altNames:cert.subjectaltname?.split(', ').map((s:string)=>s.replace('DNS:',''))||[]});
      });
      req.on('error',()=>resolve({error:'SSL connection failed'}));
      req.on('timeout',()=>{req.destroy();resolve({error:'Timeout'});});
      req.end();
    } catch { resolve({error:'SSL check failed'}); }
  });
}

async function fetchSecurityHeaders(domain: string) {
  try {
    const ctrl = new AbortController(); const to = setTimeout(()=>ctrl.abort(),10000);
    const res = await fetch(`https://${domain}`,{method:'HEAD',redirect:'follow',signal:ctrl.signal});
    clearTimeout(to);
    const hdr: Record<string,{present:boolean,value:string|null}> = {};
    ['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options','X-Content-Type-Options','X-XSS-Protection','Referrer-Policy','Permissions-Policy'].forEach(h=>{const v=res.headers.get(h);hdr[h]={present:!!v,value:v?.substring(0,200)||null};});
    let score = 5; Object.values(hdr).forEach(h=>{if(h.present)score+=13;});
    const tech: string[] = [];
    const srv=res.headers.get('server')||'', xpb=res.headers.get('x-powered-by')||'';
    if(srv.includes('nginx'))tech.push('Nginx'); if(srv.includes('Apache'))tech.push('Apache'); if(srv.includes('cloudflare'))tech.push('Cloudflare');
    if(xpb.includes('PHP'))tech.push('PHP'); if(xpb.includes('Express'))tech.push('Express.js'); if(xpb.includes('Next'))tech.push('Next.js');
    if(res.headers.get('cf-ray'))tech.push('Cloudflare CDN'); if(res.headers.get('x-vercel-id'))tech.push('Vercel');
    return {headers:hdr,score:Math.min(100,score),technologies:tech};
  } catch { return {headers:{},score:0,technologies:[]}; }
}

async function fetchEmailAuth(domain: string, dns: any) {
  const result: any = {mx:[],spf:{valid:false,record:null},dkim:{found:false,selector:null},dmarc:{valid:false,record:null,policy:null}};
  if(dns.MX?.length) result.mx = dns.MX.map((r:any)=>{const p=r.value.split(' ');return{priority:parseInt(p[0])||0,host:p.slice(1).join(' ').replace(/\.$/,'')||r.value};}).sort((a:any,b:any)=>a.priority-b.priority);
  const spf = dns.TXT?.find((r:any)=>r.value.toLowerCase().startsWith('v=spf1'));
  if(spf) result.spf = {valid:true,record:spf.value};
  try { const r=await fetch(`https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`); const d=await r.json(); if(d.Status===0&&d.Answer){const rec=d.Answer[0]?.data?.replace(/^"|"$/g,''); if(rec?.toLowerCase().startsWith('v=dmarc1')){result.dmarc={valid:true,record:rec,policy:rec.match(/p=(none|quarantine|reject)/i)?.[1]||'none'};}} } catch {}
  for(const sel of ['default','google','selector1','selector2','k1']) { try { const r=await fetch(`https://dns.google/resolve?name=${sel}._domainkey.${domain}&type=TXT`); const d=await r.json(); if(d.Status===0&&d.Answer){result.dkim={found:true,selector:sel};break;} } catch {} }
  return result;
}

async function fetchIPInfo(ip: string) {
  try {
    const res = await fetch(`https://ipwho.is/${ip}`); const d = await res.json();
    if(d.success) { const rdns = await fetchReverseDNS(ip); return {ip,city:d.city||'N/A',region:d.region||'N/A',country:d.country||'N/A',postal:d.postal||'N/A',lat:d.latitude,lon:d.longitude,timezone:d.timezone?.id||'N/A',isp:d.connection?.isp||'N/A',org:d.connection?.org||'N/A',asn:d.connection?.asn?`AS${d.connection.asn}`:'N/A',isHosting:d.is_datacenter||false,isProxy:d.is_proxy||d.is_vpn||false,reverseDns:rdns}; }
  } catch {}
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,hosting,proxy`); const d = await res.json();
    if(d.status==='success') { const rdns = await fetchReverseDNS(ip); return {ip,city:d.city||'N/A',region:d.regionName||'N/A',country:d.country||'N/A',postal:d.zip||'N/A',lat:d.lat,lon:d.lon,timezone:d.timezone||'N/A',isp:d.isp||'N/A',org:d.org||'N/A',asn:d.as||'N/A',isHosting:d.hosting||false,isProxy:d.proxy||false,reverseDns:rdns}; }
  } catch {}
  return {ip,city:'N/A',region:'N/A',country:'N/A',postal:'N/A',lat:null,lon:null,timezone:'N/A',isp:'N/A',org:'N/A',asn:'N/A',isHosting:false,isProxy:false,reverseDns:null};
}

async function resolveIP(domain: string) { try { const r=await fetch(`https://dns.google/resolve?name=${domain}&type=A`); const d=await r.json(); return d.Answer?.find((a:any)=>a.type===1)?.data||null; } catch { return null; } }

// NEW: Blacklist Check (DNSBL)
async function fetchBlacklists(ip: string) {
  const blacklists = [
    { name: 'Spamhaus ZEN', host: 'zen.spamhaus.org' },
    { name: 'SpamCop', host: 'bl.spamcop.net' },
    { name: 'Barracuda', host: 'b.barracudacentral.org' },
    { name: 'UCEPROTECT', host: 'dnsbl-1.uceprotect.net' },
    { name: 'S5H', host: 'all.s5h.net' }
  ];
  const reversed = reverseIP(ip);
  const results: { name: string; host: string; listed: boolean }[] = [];
  
  await Promise.all(blacklists.map(async (bl) => {
    try {
      const res = await fetch(`https://dns.google/resolve?name=${reversed}.${bl.host}&type=A`);
      const data = await res.json();
      // If Status is 0 (NOERROR) and has an Answer, the IP is listed
      results.push({ name: bl.name, host: bl.host, listed: data.Status === 0 && !!data.Answer?.length });
    } catch {
      results.push({ name: bl.name, host: bl.host, listed: false });
    }
  }));
  
  return results;
}

// NEW: Shared Hosting / Reverse IP lookup
async function fetchSharedHosting(ip: string) {
  try {
    const res = await fetch(`https://api.hackertarget.com/reverseiplookup/?q=${ip}`, { signal: AbortSignal.timeout(10000) });
    const text = await res.text();
    if (text.includes('error') || text.includes('API count exceeded')) return [];
    const domains = text.split('\n').map(d => d.trim()).filter(d => d && !d.includes('error'));
    return domains.slice(0, 100); // Limit to 100
  } catch {
    return [];
  }
}

// NEW: IP WHOIS from RIR (RDAP)
async function fetchIPWhois(ip: string) {
  try {
    const res = await fetch(`https://rdap.org/ip/${ip}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
    if (!res.ok) return null;
    const data = await res.json();
    
    // Extract relevant fields
    const findEntity = (roles: string[]) => data.entities?.find((e: any) => e.roles?.some((r: string) => roles.includes(r)));
    const getVcard = (e: any, field: string) => e?.vcardArray?.[1]?.find((v: any) => v[0] === field)?.[3];
    
    const abuseEntity = findEntity(['abuse']);
    const registrantEntity = findEntity(['registrant']);
    
    return {
      name: data.name || 'N/A',
      handle: data.handle || 'N/A',
      cidr: data.cidr0_cidrs?.map((c: any) => `${c.v4prefix || c.v6prefix}/${c.length}`).join(', ') || 
            (data.startAddress && data.endAddress ? `${data.startAddress} - ${data.endAddress}` : 'N/A'),
      country: data.country || 'N/A',
      type: data.type || 'N/A',
      organization: getVcard(registrantEntity, 'fn') || data.entities?.[0]?.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || 'N/A',
      abuseContact: getVcard(abuseEntity, 'email') || null,
      registrationDate: data.events?.find((e: any) => e.eventAction === 'registration')?.eventDate || null,
      lastChanged: data.events?.find((e: any) => e.eventAction === 'last changed')?.eventDate || null,
      parentHandle: data.parentHandle || null
    };
  } catch {
    return null;
  }
}

// NEW: Certificate Transparency / Subdomain Discovery
async function fetchSubdomains(domain: string) {
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${domain}&output=json`, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) return [];
    const data = await res.json();
    
    // Extract and deduplicate subdomains
    const subdomains = new Set<string>();
    for (const cert of data) {
      const names = cert.name_value?.split('\n') || [];
      for (const name of names) {
        const clean = name.trim().toLowerCase().replace(/^\*\./, '');
        if (clean && clean.endsWith(domain) && clean !== domain) {
          subdomains.add(clean);
        }
      }
    }
    
    // Sort and limit to 50
    return Array.from(subdomains).sort().slice(0, 50);
  } catch {
    return [];
  }
}

// NEW: HTTP Redirect Chain
async function fetchRedirectChain(domain: string) {
  const chain: { url: string; status: number; location: string | null }[] = [];
  let currentUrl = `http://${domain}`;
  const maxHops = 10;
  
  try {
    for (let i = 0; i < maxHops; i++) {
      const ctrl = new AbortController();
      const timeout = setTimeout(() => ctrl.abort(), 5000);
      
      try {
        const res = await fetch(currentUrl, { 
          method: 'HEAD', 
          redirect: 'manual',
          signal: ctrl.signal 
        });
        clearTimeout(timeout);
        
        const location = res.headers.get('location');
        chain.push({
          url: currentUrl,
          status: res.status,
          location
        });
        
        // If not a redirect, stop
        if (res.status < 300 || res.status >= 400 || !location) break;
        
        // Handle relative URLs
        if (location.startsWith('/')) {
          const url = new URL(currentUrl);
          currentUrl = `${url.protocol}//${url.host}${location}`;
        } else {
          currentUrl = location;
        }
      } catch (e) {
        clearTimeout(timeout);
        // If we can't fetch, just stop
        break;
      }
    }
  } catch {
    // Ignore errors
  }
  
  return chain;
}

export async function GET(req: NextRequest) {
  const q = req.nextUrl.searchParams.get('q');
  if(!q) return NextResponse.json({error:'Missing query'},{ status:400 });
  const input = extractDomain(q), isIp = isIP(input);
  try {
    if(isIp) {
      const [ip, security, blacklists, sharedHosting, ipWhois] = await Promise.all([
        fetchIPInfo(input),
        fetchSecurityHeaders(input).catch(()=>null),
        fetchBlacklists(input),
        fetchSharedHosting(input),
        fetchIPWhois(input)
      ]);
      const recommendations = generateRecommendations({ isIP: true, security, blacklists, ipWhois });
      return NextResponse.json({query:input,isIP:true,ip,security,blacklists,sharedHosting,ipWhois,recommendations});
    } else {
      const [whois,dns,ssl,security,subdomains,redirects] = await Promise.all([
        fetchWhois(input),
        fetchDNS(input),
        fetchSSL(input),
        fetchSecurityHeaders(input),
        fetchSubdomains(input),
        fetchRedirectChain(input)
      ]);
      if(!whois.nameservers.length && dns.NS?.length) whois.nameservers = dns.NS.map((r:any)=>r.value.replace(/\.$/,'').toLowerCase());
      const email = await fetchEmailAuth(input,dns);
      const resolvedIP = await resolveIP(input);
      
      // Fetch IP-related data if we have an IP
      let ip = null;
      let blacklists: { name: string; host: string; listed: boolean }[] = [];
      let sharedHosting: string[] = [];
      let ipWhois = null;
      
      if (resolvedIP) {
        [ip, blacklists, sharedHosting, ipWhois] = await Promise.all([
          fetchIPInfo(resolvedIP),
          fetchBlacklists(resolvedIP),
          fetchSharedHosting(resolvedIP),
          fetchIPWhois(resolvedIP)
        ]);
      }
      
      const recommendations = generateRecommendations({ isIP: false, whois, dns, ssl, security, email, blacklists, ipWhois });
      return NextResponse.json({
        query:input,
        isIP:false,
        whois,
        dns,
        ssl,
        security,
        email,
        ip,
        resolvedIP,
        blacklists,
        sharedHosting,
        ipWhois,
        subdomains,
        redirects,
        recommendations,
        meta:{domainAge:calcAge(whois.created),timestamp:new Date().toISOString()}
      });
    }
  } catch(e) { console.error(e); return NextResponse.json({error:'Lookup failed'},{status:500}); }
}
