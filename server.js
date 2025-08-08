require("dotenv").config();

const express = require("express");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const axios = require("axios");
const dns = require("dns").promises;
const path = require("path");

const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const OTX_API_KEY = process.env.OTX_API_KEY;
const PORT = process.env.PORT || 3000;

if (!SHODAN_API_KEY || !VIRUSTOTAL_API_KEY || !OTX_API_KEY) {
  throw new Error("Missing required API keys.");
}

// Express Init
const app = express();
app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  keyGenerator: (req) => req.ip,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Validate Query
function validateQuery(query_type, query_value) {
  if (!query_value) throw new Error("Query value cannot be empty.");

  if (query_type === "ip") {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    if (!ipRegex.test(query_value)) throw new Error("Invalid IP address format.");
  } else if (query_type === "domain") {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
    if (!domainRegex.test(query_value)) throw new Error("Invalid domain format.");
  } else if (query_type === "file") {
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    if (!hashRegex.test(query_value)) throw new Error("Invalid file hash (must be MD5, SHA1, or SHA256).");
  } else if (query_type === "url") {
    const urlRegex = /^https?:\/\/[^\s/$.?#].[^\s]*$/;
    if (!urlRegex.test(query_value)) throw new Error("Invalid URL format.");
  } else {
    throw new Error("Unsupported query type.");
  }
}

// Resolve Domain to IP
async function resolveDomainToIP(domain) {
  try {
    const addresses = await dns.lookup(domain);
    return addresses.address;
  } catch (err) {
    throw new Error("Domain resolution failed.");
  }
}

// Deduplicate CVEs
function dedupeVulns(vulns) {
  const seen = new Set();
  return vulns.filter((v) => {
    if (seen.has(v.cve_id)) return false;
    seen.add(v.cve_id);
    return true;
  });
}

// Consolidate all feeds
function consolidateReputation(shodan, virustotal, otx) {
  const hostnames = shodan.hostnames_domains.hostnames || [];
  const domains = [
    ...(shodan.hostnames_domains.domains || []),
    virustotal?.last_analysis_results?.domain || [],
    virustotal?.whois?.domain || [],
  ].flat().filter(Boolean);

  const services = shodan.services || [];
  const banners = services.map(svc => svc.banner).filter(Boolean);

  const iocs = [...new Set([...hostnames, ...domains, ...banners])];

  return {
    ip: shodan.ip_info.ip,
    hostname: hostnames[0] || null,
    country: shodan.ip_info.country,
    city: shodan.ip_info.city,
    isp: shodan.ip_info.isp,
    asn: shodan.ip_info.asn,
    organization: shodan.ip_info.organization,
    operating_system: shodan.ip_info.operating_system,

    open_ports: shodan.open_ports,
    services,
    ssl: shodan.ssl_details,
    cloud_provider: shodan.cloud_provider,
    vulnerabilities: dedupeVulns(shodan.vulnerabilities),

    reputation_score: virustotal.reputation || 0,
    malicious_reports: virustotal.last_analysis_stats?.malicious || 0,
    benign_reports: virustotal.last_analysis_stats?.harmless || 0,

    otx_summary: otx?.pulse_info?.count
      ? `Seen in ${otx.pulse_info.count} OTX threat pulses`
      : "No active pulses",

    hostnames,
    domains: [...new Set(domains)],
    iocs,
  };
}

// Format Shodan
function formatShodanData(data) {
  const {
    ip_str: ip,
    country_name: country,
    city,
    isp,
    org: organization,
    asn,
    latitude,
    longitude,
    os: operating_system,
    hostnames,
    domains,
    ports,
    ssl,
    data: services,
    tags,
    cloud,
  } = data;

  const sslDetails = ssl && ssl.cert ? {
    subject: ssl.cert.subject,
    issuer: ssl.cert.issuer,
    sha256_fingerprint: ssl.cert.fingerprint,
    expiration_date: ssl.cert.expired ? "Expired" : ssl.cert.expiry,
    tls_version: ssl.tls?.version,
    cipher: ssl.tls?.cipher,
  } : null;

  const vulnerabilities = [];
  const enrichedServices = [];

  if (Array.isArray(services)) {
    services.forEach((svc) => {
      const port = svc.port || "Unknown";
      const product = svc.product || "Unknown";
      const banner = svc.data?.slice(0, 200) || "";
      const cpes = Array.isArray(svc.cpe) ? svc.cpe : (svc.cpe ? [svc.cpe] : ["Unknown"]);

      enrichedServices.push({
        port,
        transport: svc.transport,
        product,
        banner,
        timestamp: svc.timestamp,
        module: svc._shodan?.module,
        hostnames: svc.hostnames || [],
        domains: svc.domains || [],
      });

      if (svc.vulns) {
        Object.entries(svc.vulns).slice(0, 20).forEach(([cve, details]) => {
          const cvss = typeof details === "object" && details.cvss ? details.cvss : "Unknown";
          const epss = typeof details === "object" && details.epss ? details.epss : "Unknown";
          const description = typeof details === "object" && details.summary ? details.summary : "No description available";

          vulnerabilities.push({
            cve_id: cve,
            description,
            severity: cvss,
            epss: epss,
            port,
            service: product,
            cpe: cpes,
            mitre: "Pending",
            veris: {
              action: "Pending",
              variety: "Pending",
              vector: "Pending",
            },
          });
        });
      }
    });
  }

  return {
    ip_info: {
      ip,
      country,
      city,
      isp,
      organization,
      asn,
      latitude,
      longitude,
      operating_system: operating_system || "Unknown",
    },
    hostnames_domains: {
      hostnames: hostnames || [],
      domains: domains || [],
      tags: tags || [],
    },
    open_ports: ports?.map((port) => ({
      port,
      service: services?.find((s) => s.port === port)?.product || "Unknown",
      active: services?.find((s) => s.port === port)?.data ? "Active and responsive" : "Unknown",
    })) || [],
    vulnerabilities,
    ssl_details: sslDetails,
    cloud_provider: cloud ? {
      service_provider: cloud.provider,
      region: cloud.region,
      service_type: cloud.service,
    } : null,
    services: enrichedServices,
    additional_details: `The system is running ${operating_system || "an unknown OS"}.`,
  };
}

// Shodan API
async function fetchShodanData(ip) {
  try {
    const res = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
      params: { key: SHODAN_API_KEY },
    });
    return formatShodanData(res.data);
  } catch (err) {
    throw new Error(`Shodan API error: ${err.message}`);
  }
}

// VirusTotal API
async function fetchVirusTotalData(query_type, query_value) {
  try {
    let query = query_value;
    if (query_type === "url") {
      query = Buffer.from(query_value).toString("base64").replace(/=/g, "");
    }

    const endpointMap = {
      domain: `/domains/${query_value}`,
      ip: `/ip_addresses/${query_value}`,
      file: `/files/${query_value}`,
      url: `/urls/${query}`,
    };

    const endpoint = endpointMap[query_type];
    if (!endpoint) throw new Error("Invalid query type for VirusTotal.");

    const res = await axios.get(`https://www.virustotal.com/api/v3${endpoint}`, {
      headers: { "x-apikey": VIRUSTOTAL_API_KEY },
    });
    return res.data.data.attributes;
  } catch (err) {
    throw new Error(`VirusTotal API error: ${err.message}`);
  }
}

// OTX API
async function fetchOTXData(query_value) {
  try {
    const url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(query_value)}/general`;
    const res = await axios.get(url, {
      headers: { "X-OTX-API-KEY": OTX_API_KEY },
    });
    return res.data;
  } catch (err) {
    throw new Error(`OTX API error: ${err.message}`);
  }
}

// Status Check
app.get("/status", (req, res) => {
  res.json({ status: "online", message: "Threat Intelligence API is running." });
});

// Unified Reputation Endpoint
app.post("/execute-query", async (req, res) => {
  const { query_type, query_value } = req.body;
  if (!query_type || !query_value) {
    return res.status(400).json({ error: "query_type and query_value required", code: 400 });
  }

  try {
    // Validate query
    validateQuery(query_type, query_value);

    // Resolve domain to IP if query_type is domain
    let ip = query_value;
    if (query_type === "domain") {
      ip = await resolveDomainToIP(query_value);
    }

    // Fetch data from APIs (skip Shodan for file and URL queries)
    const shodanPromise = (query_type === "ip" || query_type === "domain")
      ? fetchShodanData(ip)
      : Promise.resolve(null);
    const vtPromise = fetchVirusTotalData(query_type, query_value);
    const otxPromise = (query_type === "domain" || query_type === "url")
      ? fetchOTXData(query_value)
      : Promise.resolve(null);

    const [shodan, vt, otx] = await Promise.all([shodanPromise, vtPromise, otxPromise]);

    // Consolidate results if Shodan data is available
    const consolidated = shodan
      ? consolidateReputation(shodan, vt, otx)
      : {
          query_type,
          query_value,
          virustotal: vt,
          otx: otx || null,
        };

    res.json(consolidated);
  } catch (err) {
    res.status(500).json({ error: err.message, code: 500 });
  }
});

// Serve Static Assets
app.use("/static", express.static(path.join(__dirname, "public")));

// Start Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
