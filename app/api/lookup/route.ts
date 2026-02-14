import { NextRequest, NextResponse } from 'next/server';
import * as https from 'https';
import * as tls from 'tls';

const isIP = (s: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s.trim());
const extractDomain = (s: string) => s.trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split('?')[0];
const calcAge = (c: string) => { try { const d = new Date(c); if (isNaN(d.getTime())) return null; const y = Math.floor((Date.now()-d.getTime())/(365.25*24*60*60*1000)); const m = Math.floor(((Date.now()-d.getTime())%(365.25*24*60*60*1000))/(30.44*24*60*60*1000)); return y>0?`${y}y ${m}m old`:`${m}m old`; } catch { return null; } };

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

export async function GET(req: NextRequest) {
  const q = req.nextUrl.searchParams.get('q');
  if(!q) return NextResponse.json({error:'Missing query'},{ status:400 });
  const input = extractDomain(q), isIp = isIP(input);
  try {
    if(isIp) {
      const [ip,security] = await Promise.all([fetchIPInfo(input),fetchSecurityHeaders(input).catch(()=>null)]);
      return NextResponse.json({query:input,isIP:true,ip,security});
    } else {
      const [whois,dns,ssl,security] = await Promise.all([fetchWhois(input),fetchDNS(input),fetchSSL(input),fetchSecurityHeaders(input)]);
      if(!whois.nameservers.length && dns.NS?.length) whois.nameservers = dns.NS.map((r:any)=>r.value.replace(/\.$/,'').toLowerCase());
      const email = await fetchEmailAuth(input,dns);
      const resolvedIP = await resolveIP(input);
      const ip = resolvedIP ? await fetchIPInfo(resolvedIP) : null;
      return NextResponse.json({query:input,isIP:false,whois,dns,ssl,security,email,ip,resolvedIP,meta:{domainAge:calcAge(whois.created),timestamp:new Date().toISOString()}});
    }
  } catch(e) { console.error(e); return NextResponse.json({error:'Lookup failed'},{status:500}); }
}
