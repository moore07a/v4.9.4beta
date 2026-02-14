module.exports = function createPublicContentModule(deps) {
  const { app, crypto, addLog, resolvePublicBaseUrls, rotationSeed, hash32, express, PORT } = deps;

// ================== ENHANCED PUBLIC CONTENT SURFACE ==================
const PUBLIC_CONTENT_SURFACE = (process.env.PUBLIC_CONTENT_SURFACE || "0") === "1";
const PUBLIC_SITE_PERSONA = (process.env.PUBLIC_SITE_PERSONA || "rotating").toLowerCase();
const PUBLIC_SITE_NAME_OVERRIDE = (process.env.PUBLIC_SITE_NAME || "").trim();
const PUBLIC_SITE_BASE_URL = (process.env.PUBLIC_SITE_BASE_URL || "").trim();
const PUBLIC_ROTATION_MODE = (process.env.PUBLIC_ROTATION_MODE || "daily").trim().toLowerCase();
const PUBLIC_GENERATE_PATHS = parseInt(process.env.PUBLIC_GENERATE_PATHS || "25", 10);
const PUBLIC_ENABLE_ANALYTICS = (process.env.PUBLIC_ENABLE_ANALYTICS || "1") === "1";
const PUBLIC_ENABLE_BACKGROUND = (process.env.PUBLIC_ENABLE_BACKGROUND || "1") === "1";
const EFFECTIVE_PORT = PORT || process.env.PORT || 8080;

// Safety gate: allow explicit force-enable while keeping default-off posture.
function isPublicContentSurfaceEnabled() {
  const forceEnable = (process.env.PUBLIC_CONTENT_SURFACE_FORCE || "").trim().toLowerCase();
  const forced = forceEnable === "1" || forceEnable === "true" || forceEnable === "yes";
  return PUBLIC_CONTENT_SURFACE || forced;
}

// ================== MULTIPLE PERSONAS ==================
// Each persona is a completely different "cover story"
const PERSONAS = {
  // Persona 1: CDN / Edge Computing Provider
  cdn: {
    name: "EdgeFlow",
    tagline: "Global edge network for modern applications",
    description: "Accelerate your content with our global edge network",
    sitekey: "edgeflow",
    contentTypes: ['html', 'json', 'xml'],
    logo: "⚡",
    primaryColor: "#0066cc",
    secondaryColor: "#4c9aff",
    features: [
      "Global CDN with 200+ edge locations",
      "DDoS protection included",
      "Serverless compute at the edge",
      "Image optimization pipeline",
      "Real-time purging API",
      "Custom SSL certificates"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Network", path: "/network" },
      { text: "Pricing", path: "/pricing" },
      { text: "Documentation", path: "/docs" },
      { text: "Status", path: "/status" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/edge/locations", "/api/v1/metrics"]
  },
  
  // Persona 2: Media Streaming Platform
  media: {
    name: "StreamWave",
    tagline: "High-quality video streaming infrastructure",
    description: "Stream video content at any scale with our reliable platform",
    sitekey: "streamwave",
    contentTypes: ['html', 'json', 'xml'],
    logo: "🎬",
    primaryColor: "#9c27b0",
    secondaryColor: "#ce93d8",
    features: [
      "Adaptive bitrate streaming",
      "DRM and content protection",
      "Live transcoding",
      "Video analytics dashboard",
      "Multi-platform playback SDKs",
      "Sub-second latency options"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Features", path: "/features" },
      { text: "Pricing", path: "/pricing" },
      { text: "Developers", path: "/developers" },
      { text: "Status", path: "/status" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/streams", "/api/v1/analytics"]
  },
  
  // Persona 3: Cloud Storage Provider
  storage: {
    name: "CloudVault",
    tagline: "Secure object storage for any workload",
    description: "Store, protect, and serve data with enterprise-grade durability",
    sitekey: "cloudvault",
    contentTypes: ['html', 'json', 'xml'],
    logo: "☁️",
    primaryColor: "#2e7d32",
    secondaryColor: "#81c784",
    features: [
      "S3-compatible object storage",
      "99.999999999% durability",
      "Server-side encryption",
      "Lifecycle management",
      "Cross-region replication",
      "Presigned URL generation"
    ],
    footerLinks: [
    { text: "Home", path: "/" },
    { text: "Solutions", path: "/solutions" },
    { text: "Pricing", path: "/pricing" },
    { text: "Docs", path: "/docs" },
    { text: "Status", path: "/status" },
    { text: "Security", path: "/security" },
    { text: "Support", path: "/support" }
  ],
  apiEndpoints: ["/api/v1/status", "/api/v1/buckets", "/api/v1/objects"]
},
  
  // Persona 4: API Gateway / Proxy Service
  api: {
    name: "API Gateway Pro",
    tagline: "Enterprise API management platform",
    description: "Secure, scale, and monitor your APIs with our intelligent gateway",
    sitekey: "apigateway",
    contentTypes: ['html', 'json', 'xml'],
    logo: "🔌",
    primaryColor: "#d32f2f",
    secondaryColor: "#ef9a9a",
    features: [
      "Rate limiting and throttling",
      "API key authentication",
      "Request/response transformation",
      "Analytics and monitoring",
      "GraphQL federation",
      "OpenAPI/Swagger support"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Products", path: "/products" },
      { text: "Pricing", path: "/pricing" },
      { text: "Docs", path: "/docs" },
      { text: "Blog", path: "/blog" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/keys", "/api/v1/analytics"]
  },
  
  // Persona 5: Security / WAF Provider
  security: {
    name: "ShieldEdge",
    tagline: "Web application security for modern threats",
    description: "Protect your applications from bots, DDoS, and OWASP Top 10",
    sitekey: "shieldedge",
    contentTypes: ['html', 'json', 'xml'],
    logo: "🛡️",
    primaryColor: "#ff6f00",
    secondaryColor: "#ffb74d",
    features: [
      "Web Application Firewall",
      "Bot mitigation engine",
      "DDoS protection",
      "Rate limiting",
      "Security analytics",
      "Compliance reporting"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "Products", path: "/products" },
      { text: "Pricing", path: "/pricing" },
      { text: "Docs", path: "/docs" },
      { text: "Status", path: "/status" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: ["/api/v1/status", "/api/v1/threats", "/api/v1/rules"]
  },
  
  // Persona 6: Health & Wellness (keep as fallback)
  wellness: {
    name: "Wellness Hub",
    tagline: "Evidence-based health guidance",
    description: "Practical wellness advice for busy professionals",
    sitekey: "wellness",
    contentTypes: ['html'],
    logo: "🌿",
    primaryColor: "#2e7d32",
    secondaryColor: "#81c784",
    features: [
      "Morning mobility routines",
      "Sustainable nutrition tips",
      "Sleep optimization",
      "Stress management",
      "Workout plans for home",
      "Recovery protocols"
    ],
    footerLinks: [
      { text: "Home", path: "/" },
      { text: "About", path: "/about" },
      { text: "Articles", path: "/articles" },
      { text: "Guides", path: "/guides" },
      { text: "Contact", path: "/contact" }
    ],
    apiEndpoints: []
  }
};

// Select active persona (deterministic based on date)
function getActivePersona() {
  if (PUBLIC_SITE_PERSONA !== "rotating" && PERSONAS[PUBLIC_SITE_PERSONA]) {
    return PERSONAS[PUBLIC_SITE_PERSONA];
  }
  
  // Rotate personas deterministically
  const personaKeys = Object.keys(PERSONAS);
  const seed = rotationSeed();
  const index = hash32(seed) % personaKeys.length;
  const personaKey = personaKeys[index];
  
  return PERSONAS[personaKey];
}

const PUBLIC_SITE_NAME = PUBLIC_SITE_NAME_OVERRIDE || getActivePersona().name;

// ================== GENERATE DUMMY PATHS ==================
function generateAllPaths(persona, rotationSeed) {
  const paths = [];
  const seed = rotationSeed || 'default-seed'; // Use provided seed or fallback
  
  // Add standard footer links
  persona.footerLinks.forEach(link => {
    if (link.path !== '/') paths.push(link.path);
  });
  
  // Add blog/articles section (10-15 posts)
  for (let i = 1; i <= 12; i++) {
    const topics = ['getting-started', 'tutorial', 'guide', 'announcement', 'best-practices', 'case-study'];
    const topic = topics[hash32(`${seed}:blog:${i}`) % topics.length];
    
    paths.push(`/blog/${topic}-${i}`);
    paths.push(`/blog/post-${i}`);
    paths.push(`/articles/${i}`);
  }
  
  // Add product/service pages
  const productTypes = ['enterprise', 'pro', 'business', 'starter', 'custom'];
  productTypes.forEach((type, idx) => {
    paths.push(`/pricing/${type}`);
    paths.push(`/features/${type}`);
  });
  
  // Add documentation section
  const docSections = ['getting-started', 'api', 'sdk', 'faq', 'troubleshooting', 'changelog'];
  docSections.forEach(section => {
    paths.push(`/docs/${section}`);
    
    // Sub-pages
    for (let i = 1; i <= 3; i++) {
      paths.push(`/docs/${section}/part-${i}`);
    }
  });
  
  // Add resource pages
  paths.push('/resources');
  paths.push('/whitepapers');
  paths.push('/case-studies');
  paths.push('/webinars');
  paths.push('/events');
  
  // Add legal pages
  paths.push('/privacy');
  paths.push('/terms');
  paths.push('/security');
  paths.push('/compliance');
  paths.push('/sla');
  
  // Add company pages
  paths.push('/about');
  paths.push('/careers');
  paths.push('/partners');
  paths.push('/news');
  paths.push('/press');
  
  // Add random generated paths (deterministic based on seed)
  for (let i = 0; i < PUBLIC_GENERATE_PATHS; i++) {
    const randomId = hash32(`${seed}:random:${i}`).toString(36).slice(0, 8);
    paths.push(`/p/${randomId}`);
    paths.push(`/shared/${randomId}`);
    paths.push(`/preview/${randomId}`);
    paths.push(`/embed/${randomId}`);
  }
  
  // Remove duplicates and sort
  return [...new Set(paths)].sort();
}

// ================== ENHANCED PAGE GENERATOR ==================

function renderEnhancedPublicPage(req, page) {
  const persona = getActivePersona();
  const seed = `${rotationSeed()}:${persona.sitekey}:${page.path}`;
  
  // Generate dynamic navigation
  const navLinks = persona.footerLinks
    .map(link => `<a class="nav-link ${link.path === page.path ? 'active' : ''}" href="${link.path}">${link.text}</a>`)
    .join("");
  
  // Pick features deterministically for this page
  const pageFeatures = deterministicPick(persona.features, seed, 4)
    .map(feature => `<li>${feature}</li>`)
    .join("");
  
  // Generate fake metrics (consistent per day)
  const dailyRequests = hash32(`${seed}:requests`) % 90000 + 10000;
  const uptime = (99.9 + (hash32(`${seed}:uptime`) % 10) / 100).toFixed(2);
  const latency = (hash32(`${seed}:latency`) % 40 + 15).toFixed(0);
  
  // Page-specific content
  let pageContent = "";
  let pageTitle = page.title || persona.name;
  let pageDescription = page.summary || persona.tagline;
  
  if (page.path === '/') {
    pageTitle = persona.name;
    pageDescription = persona.description;
  } else if (page.path === '/pricing') {
    pageTitle = "Pricing Plans";
    pageDescription = `Flexible ${persona.name} pricing for any scale`;
    
    // ✅ PRICING PAGE WITH COMPLETE TIERS
    pageContent = `
      <div style="margin-top: 40px;">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; margin-top: 30px;">
          
          <!-- STARTER PLAN -->
          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 32px 24px; position: relative;">
            <h3 style="font-size: 24px; margin: 0 0 8px 0; color: var(--text);">Starter</h3>
            <div style="font-size: 14px; color: var(--muted); margin-bottom: 24px;">For small projects & teams</div>
            <div style="margin-bottom: 24px;">
              <span style="font-size: 48px; font-weight: 700; color: var(--primary);">$49</span>
              <span style="font-size: 16px; color: var(--muted);">/month</span>
            </div>
            <ul style="list-style: none; padding: 0; margin: 0 0 32px 0;">
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ 1 TB storage</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ 10 GB/month egress</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ 30-day retention</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ Basic support</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px; color: var(--muted);">✗ SSO</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px; color: var(--muted);">✗ Compliance reporting</li>
            </ul>
            <a href="/signup" style="display: block; text-align: center; background: #f1f5f9; color: var(--text); text-decoration: none; padding: 12px; border-radius: 8px; font-weight: 500; border: 1px solid var(--border);">Get Started</a>
          </div>
          
          <!-- BUSINESS PLAN (FEATURED) -->
          <div style="background: white; border: 2px solid var(--primary); border-radius: 16px; padding: 32px 24px; position: relative; transform: scale(1.02); box-shadow: 0 10px 25px rgba(46, 125, 50, 0.1);">
            <div style="position: absolute; top: -12px; left: 50%; transform: translateX(-50%); background: var(--primary); color: white; padding: 4px 16px; border-radius: 20px; font-size: 14px; font-weight: 600; letter-spacing: 0.5px;">MOST POPULAR</div>
            <h3 style="font-size: 24px; margin: 0 0 8px 0; color: var(--text);">Business</h3>
            <div style="font-size: 14px; color: var(--muted); margin-bottom: 24px;">For growing companies</div>
            <div style="margin-bottom: 24px;">
              <span style="font-size: 48px; font-weight: 700; color: var(--primary);">$199</span>
              <span style="font-size: 16px; color: var(--muted);">/month</span>
            </div>
            <ul style="list-style: none; padding: 0; margin: 0 0 32px 0;">
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ 10 TB storage</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ 100 GB/month egress</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ 90-day retention</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ Priority support</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ SSO authentication</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px; color: var(--muted);">✗ Compliance reporting</li>
            </ul>
            <a href="/signup" style="display: block; text-align: center; background: var(--primary); color: white; text-decoration: none; padding: 12px; border-radius: 8px; font-weight: 500;">Get Started</a>
          </div>
          
          <!-- ENTERPRISE PLAN -->
          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 32px 24px; position: relative;">
            <h3 style="font-size: 24px; margin: 0 0 8px 0; color: var(--text);">Enterprise</h3>
            <div style="font-size: 14px; color: var(--muted); margin-bottom: 24px;">For large organizations</div>
            <div style="margin-bottom: 24px;">
              <span style="font-size: 48px; font-weight: 700; color: var(--primary);">Custom</span>
            </div>
            <ul style="list-style: none; padding: 0; margin: 0 0 32px 0;">
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ Unlimited storage</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ Custom egress</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ Unlimited retention</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ 24/7 phone support</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ Compliance reporting</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 8px;">✓ Dedicated account manager</li>
            </ul>
            <a href="/contact" style="display: block; text-align: center; background: #f1f5f9; color: var(--text); text-decoration: none; padding: 12px; border-radius: 8px; font-weight: 500; border: 1px solid var(--border);">Contact Sales</a>
          </div>
          
        </div>
        
        <!-- ANNUAL SAVINGS NOTE -->
        <div style="text-align: center; margin-top: 40px; padding: 20px; background: #f8fafc; border-radius: 8px; color: var(--muted);">
          💰 Save 20% with annual billing • All plans include 99.999999999% durability • 30-day free trial
        </div>
      </div>
    `;

  } else if (page.path === '/solutions') {
    pageTitle = "Solutions";
    pageDescription = `Industry solutions powered by ${persona.name}`;

    pageContent = `
      <div style="margin-top: 20px;">
        <h2 style="font-size: 28px; margin-bottom: 30px;">Solutions for every industry</h2>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; margin-bottom: 50px;">

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 32px;">
            <div style="font-size: 40px; margin-bottom: 20px;">🛒</div>
            <h3 style="font-size: 22px; margin: 0 0 10px 0;">E-commerce</h3>
            <p style="color: var(--muted); margin-bottom: 20px;">Store product images, user content, and backups.</p>
            <ul style="list-style: none; padding: 0; margin: 0;">
              <li style="padding: 6px 0; display: flex; align-items: center; gap: 8px;">✓ 11x9s durability</li>
              <li style="padding: 6px 0; display: flex; align-items: center; gap: 8px;">✓ Global CDN</li>
              <li style="padding: 6px 0; display: flex; align-items: center; gap: 8px;">✓ Image optimization</li>
            </ul>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 32px;">
            <div style="font-size: 40px; margin-bottom: 20px;">🏥</div>
            <h3 style="font-size: 22px; margin: 0 0 10px 0;">Healthcare</h3>
            <p style="color: var(--muted); margin-bottom: 20px;">HIPAA-compliant storage for medical imaging and records.</p>
            <ul style="list-style: none; padding: 0; margin: 0;">
              <li style="padding: 6px 0; display: flex; align-items: center; gap: 8px;">✓ HIPAA eligibility</li>
              <li style="padding: 6px 0; display: flex; align-items: center; gap: 8px;">✓ Audit logging</li>
              <li style="padding: 6px 0; display: flex; align-items: center; gap: 8px;">✓ Access controls</li>
            </ul>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 32px;">
            <div style="font-size: 40px; margin-bottom: 20px;">🎬</div>
            <h3 style="font-size: 22px; margin: 0 0 10px 0;">Media & Entertainment</h3>
            <p style="color: var(--muted); margin-bottom: 20px;">Store and stream video content at scale.</p>
            <ul style="list-style: none; padding: 0; margin: 0;">
              <li style="padding: 6px 0; display: flex; align-items: center; gap: 8px;">✓ Video transcoding</li>
              <li style="padding: 6px 0; display: flex; align-items: center; gap: 8px;">✓ Adaptive bitrate</li>
              <li style="padding: 6px 0; display: flex; align-items: center; gap: 8px;">✓ DRM support</li>
            </ul>
          </div>

        </div>

        <div style="background: #f8fafc; border-radius: 16px; padding: 40px; text-align: center; margin-top: 30px;">
          <h3 style="font-size: 24px; margin: 0 0 15px 0;">Not sure which solution fits?</h3>
          <p style="color: var(--muted); margin-bottom: 25px; font-size: 18px;">Talk to our solutions architects for a personalized recommendation.</p>
          <a href="/contact" style="display: inline-block; background: var(--primary); color: white; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: 500;">Contact Sales</a>
        </div>
      </div>
    `;

  } else if (page.path === '/docs') {
    pageTitle = "Documentation";
    pageDescription = `Technical documentation for ${persona.name}`;

    pageContent = `
      <div style="margin-top: 20px;">
        <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 40px;">

          <div>
            <h2 style="font-size: 24px; margin-top: 0;">Getting Started</h2>
            <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 30px;">
              <h3 style="margin-top: 0;">Quickstart Guide</h3>
              <p style="color: var(--muted);">Create your first bucket, upload objects, and generate access keys in 5 minutes.</p>
              <a href="/docs/getting-started" style="color: var(--primary); text-decoration: none; font-weight: 500;">Read guide →</a>
            </div>

            <h2 style="font-size: 24px;">API Reference</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
              <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 20px;">
                <div style="font-size: 20px; margin-bottom: 10px;">📦</div>
                <h4 style="margin: 0 0 8px 0;">Buckets</h4>
                <p style="color: var(--muted); font-size: 14px;">Create, list, delete</p>
              </div>
              <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 20px;">
                <div style="font-size: 20px; margin-bottom: 10px;">📄</div>
                <h4 style="margin: 0 0 8px 0;">Objects</h4>
                <p style="color: var(--muted); font-size: 14px;">Upload, download, copy</p>
              </div>
              <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 20px;">
                <div style="font-size: 20px; margin-bottom: 10px;">🔐</div>
                <h4 style="margin: 0 0 8px 0;">Presigned URLs</h4>
                <p style="color: var(--muted); font-size: 14px;">Generate temporary links</p>
              </div>
            </div>
          </div>

          <div>
            <div style="background: #f8fafc; border-radius: 12px; padding: 24px;">
              <h3 style="margin-top: 0;">SDKs & Tools</h3>
              <ul style="list-style: none; padding: 0;">
                <li style="padding: 10px 0; border-bottom: 1px solid var(--border);">Python SDK</li>
                <li style="padding: 10px 0; border-bottom: 1px solid var(--border);">Node.js SDK</li>
                <li style="padding: 10px 0; border-bottom: 1px solid var(--border);">Java SDK</li>
                <li style="padding: 10px 0; border-bottom: 1px solid var(--border);">AWS S3 Compatible</li>
                <li style="padding: 10px 0;">CLI Tool</li>
              </ul>
            </div>

            <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-top: 30px;">
              <h3 style="margin-top: 0;">Need help?</h3>
              <p style="color: var(--muted);">Our support team is available 24/7.</p>
              <a href="/support" style="display: inline-block; background: var(--primary); color: white; padding: 10px 20px; border-radius: 6px; text-decoration: none; margin-top: 10px;">Contact Support</a>
            </div>
          </div>

        </div>
      </div>
    `;

  } else if (page.path === '/about') {
    pageTitle = "About";
    pageDescription = `Learn more about ${persona.name}`;

    pageContent = `
      <div style="margin-top: 20px;">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 50px; align-items: center; margin-bottom: 60px;">
          <div>
            <h2 style="font-size: 32px; margin-top: 0;">Our mission</h2>
            <p style="font-size: 18px; color: var(--muted); line-height: 1.6;">Make enterprise-grade object storage accessible to every business, from startups to global enterprises.</p>
          </div>
          <div style="text-align: center;">
            <div style="font-size: 80px;">☁️</div>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; margin-bottom: 60px;">
          <div style="text-align: center;">
            <div style="font-size: 36px; font-weight: bold; color: var(--primary);">2020</div>
            <div style="color: var(--muted);">Founded</div>
          </div>
          <div style="text-align: center;">
            <div style="font-size: 36px; font-weight: bold; color: var(--primary);">50+</div>
            <div style="color: var(--muted);">Team members</div>
          </div>
          <div style="text-align: center;">
            <div style="font-size: 36px; font-weight: bold; color: var(--primary);">5,000+</div>
            <div style="color: var(--muted);">Customers</div>
          </div>
        </div>

        <div style="background: #f8fafc; border-radius: 16px; padding: 40px;">
          <h3 style="font-size: 24px; margin-top: 0; text-align: center;">Trusted by innovative companies</h3>
          <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 30px; margin-top: 40px; opacity: 0.7;">
            <div style="text-align: center; font-size: 20px; font-weight: 500;">Acme Corp</div>
            <div style="text-align: center; font-size: 20px; font-weight: 500;">Globex</div>
            <div style="text-align: center; font-size: 20px; font-weight: 500;">Initech</div>
            <div style="text-align: center; font-size: 20px; font-weight: 500;">Umbrella</div>
          </div>
        </div>
      </div>
    `;

  } else if (page.path === '/contact') {
    pageTitle = "Contact";
    pageDescription = "Reach sales and support";

    pageContent = `
      <div style="margin-top: 20px;">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 50px;">

          <div>
            <h2 style="font-size: 28px; margin-top: 0;">Get in touch</h2>
            <p style="color: var(--muted); font-size: 18px; margin-bottom: 30px;">Questions? Our team is here to help.</p>

            <div style="margin-bottom: 30px;">
              <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                <div style="background: var(--primary-light); color: var(--primary); width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 20px;">💬</div>
                <div>
                  <div style="font-weight: 600;">Live chat</div>
                  <div style="color: var(--muted);">Available 24/7</div>
                </div>
              </div>

              <div style="display: flex; align-items: center; gap: 15px;">
                <div style="background: var(--primary-light); color: var(--primary); width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 20px;">📞</div>
                <div>
                  <div style="font-weight: 600;">Phone</div>
                  <div style="color: var(--muted);">+1 (888) 555-0123</div>
                </div>
              </div>
            </div>
          </div>

          <div style="background: #f8fafc; border-radius: 16px; padding: 32px;">
            <h3 style="margin-top: 0;">Send us a message</h3>
            <div style="display: grid; gap: 20px;">
              <input type="text" placeholder="Name" style="padding: 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 16px; width: 100%;" disabled value="Demo contact form">
              <input type="email" placeholder="Email" style="padding: 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 16px; width: 100%;" disabled>
              <textarea placeholder="How can we help?" rows="4" style="padding: 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 16px; width: 100%;" disabled></textarea>
              <div style="background: var(--primary); color: white; padding: 12px; border-radius: 8px; text-align: center; opacity: 0.7;">Send Message (Demo)</div>
            </div>
          </div>

        </div>
      </div>
    `;



  } else if (page.path === '/features') {
    pageTitle = "Features";
    pageDescription = "Enterprise-grade object storage capabilities";

    pageContent = `
      <div style="margin-top: 20px;">

        <!-- Hero Section -->
        <div style="text-align: center; margin-bottom: 60px;">
          <h2 style="font-size: 36px; margin-bottom: 20px; color: var(--text);">Everything you need for modern data storage</h2>
          <p style="font-size: 20px; color: var(--muted); max-width: 800px; margin: 0 auto;">S3-compatible, globally distributed, and secure by default — without the complexity.</p>
        </div>

        <!-- Core Features Grid -->
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; margin-bottom: 60px;">

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px; transition: all 0.2s;">
            <div style="font-size: 48px; margin-bottom: 24px;">📦</div>
            <h3 style="font-size: 24px; margin: 0 0 12px 0;">S3-Compatible API</h3>
            <p style="color: var(--muted); margin-bottom: 20px; line-height: 1.6;">Drop-in replacement for AWS S3. Use existing SDKs, tools, and libraries without code changes.</p>
            <ul style="list-style: none; padding: 0; margin: 0;">
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ AWS SDK compatible</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Multipart uploads</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Bucket policies</li>
            </ul>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 48px; margin-bottom: 24px;">🔒</div>
            <h3 style="font-size: 24px; margin: 0 0 12px 0;">Enterprise Security</h3>
            <p style="color: var(--muted); margin-bottom: 20px; line-height: 1.6;">Military-grade encryption at rest and in transit. Fine-grained access controls for every object.</p>
            <ul style="list-style: none; padding: 0; margin: 0;">
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ AES-256 encryption</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ TLS 1.3 everywhere</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ IAM-compatible</li>
            </ul>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 48px; margin-bottom: 24px;">🌍</div>
            <h3 style="font-size: 24px; margin: 0 0 12px 0;">Global Distribution</h3>
            <p style="color: var(--muted); margin-bottom: 20px; line-height: 1.6;">Automatically replicate data across regions for low-latency access and disaster recovery.</p>
            <ul style="list-style: none; padding: 0; margin: 0;">
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ 200+ edge locations</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Cross-region replication</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Geo-redundant</li>
            </ul>
          </div>

        </div>

        <!-- Second Row -->
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; margin-bottom: 60px;">

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 48px; margin-bottom: 24px;">⚡</div>
            <h3 style="font-size: 24px; margin: 0 0 12px 0;">High Performance</h3>
            <p style="color: var(--muted); margin-bottom: 20px; line-height: 1.6;">Low-latency access with intelligent caching and optimized data paths.</p>
            <ul style="list-style: none; padding: 0; margin: 0;">
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ < 20ms average latency</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ 10 Gbps per connection</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Parallel transfers</li>
            </ul>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 48px; margin-bottom: 24px;">🔄</div>
            <h3 style="font-size: 24px; margin: 0 0 12px 0;">Lifecycle Management</h3>
            <p style="color: var(--muted); margin-bottom: 20px; line-height: 1.6;">Automate data retention, archival, and deletion policies with simple rules.</p>
            <ul style="list-style: none; padding: 0; margin: 0;">
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Automated tiering</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Expiration policies</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Legal holds</li>
            </ul>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 48px; margin-bottom: 24px;">📊</div>
            <h3 style="font-size: 24px; margin: 0 0 12px 0;">Analytics & Monitoring</h3>
            <p style="color: var(--muted); margin-bottom: 20px; line-height: 1.6;">Real-time visibility into storage usage, access patterns, and performance.</p>
            <ul style="list-style: none; padding: 0; margin: 0;">
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Real-time metrics</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Access logs</li>
              <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: var(--muted);">✓ Custom dashboards</li>
            </ul>
          </div>

        </div>

        <!-- Advanced Features Section -->
        <div style="margin-top: 80px; margin-bottom: 40px;">
          <h3 style="font-size: 28px; text-align: center; margin-bottom: 40px;">Advanced capabilities</h3>

          <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px;">

            <div style="background: #f8fafc; border-radius: 12px; padding: 24px; text-align: center;">
              <div style="font-size: 32px; margin-bottom: 16px;">🔗</div>
              <h4 style="margin: 0 0 8px 0;">Presigned URLs</h4>
              <p style="color: var(--muted); font-size: 14px;">Time-limited access to private objects</p>
            </div>

            <div style="background: #f8fafc; border-radius: 12px; padding: 24px; text-align: center;">
              <div style="font-size: 32px; margin-bottom: 16px;">🔄</div>
              <h4 style="margin: 0 0 8px 0;">Versioning</h4>
              <p style="color: var(--muted); font-size: 14px;">Preserve and restore object versions</p>
            </div>

            <div style="background: #f8fafc; border-radius: 12px; padding: 24px; text-align: center;">
              <div style="font-size: 32px; margin-bottom: 16px;">🏷️</div>
              <h4 style="margin: 0 0 8px 0;">Object tagging</h4>
              <p style="color: var(--muted); font-size: 14px;">Categorize and manage with metadata</p>
            </div>

            <div style="background: #f8fafc; border-radius: 12px; padding: 24px; text-align: center;">
              <div style="font-size: 32px; margin-bottom: 16px;">🔐</div>
              <h4 style="margin: 0 0 8px 0;">Bucket policies</h4>
              <p style="color: var(--muted); font-size: 14px;">Fine-grained access control</p>
            </div>

            <div style="background: #f8fafc; border-radius: 12px; padding: 24px; text-align: center;">
              <div style="font-size: 32px; margin-bottom: 16px;">📋</div>
              <h4 style="margin: 0 0 8px 0;">Event notifications</h4>
              <p style="color: var(--muted); font-size: 14px;">Real-time object change alerts</p>
            </div>

            <div style="background: #f8fafc; border-radius: 12px; padding: 24px; text-align: center;">
              <div style="font-size: 32px; margin-bottom: 16px;">🔍</div>
              <h4 style="margin: 0 0 8px 0;">Inventory reports</h4>
              <p style="color: var(--muted); font-size: 14px;">Daily object listings</p>
            </div>

            <div style="background: #f8fafc; border-radius: 12px; padding: 24px; text-align: center;">
              <div style="font-size: 32px; margin-bottom: 16px;">⏱️</div>
              <h4 style="margin: 0 0 8px 0;">S3 Object Lock</h4>
              <p style="color: var(--muted); font-size: 14px;">WORM compliance storage</p>
            </div>

            <div style="background: #f8fafc; border-radius: 12px; padding: 24px; text-align: center;">
              <div style="font-size: 32px; margin-bottom: 16px;">📈</div>
              <h4 style="margin: 0 0 8px 0;">Storage Lens</h4>
              <p style="color: var(--muted); font-size: 14px;">Organization-wide analytics</p>
            </div>

          </div>
        </div>

        <!-- CTA Banner -->
        <div style="background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%); border-radius: 24px; padding: 48px; text-align: center; margin-top: 60px; color: white;">
          <h3 style="font-size: 32px; margin: 0 0 16px 0; color: white;">Ready to get started?</h3>
          <p style="font-size: 18px; margin-bottom: 32px; opacity: 0.95;">Start with 10GB free — no credit card required.</p>
          <div style="display: flex; gap: 16px; justify-content: center;">
            <a href="/signup" style="background: white; color: var(--primary); padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: 600;">Start free</a>
            <a href="/contact" style="background: rgba(255,255,255,0.2); color: white; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: 500;">Contact sales</a>
          </div>
        </div>

      </div>
    `;

  } else if (page.path === '/developers') {
    pageTitle = "Developers";
    pageDescription = "Build on CloudVault with powerful APIs and SDKs";

    pageContent = `
      <div style="margin-top: 20px;">

        <!-- Hero -->
        <div style="text-align: center; margin-bottom: 60px;">
          <h2 style="font-size: 36px; margin-bottom: 20px; color: var(--text);">Developer-first object storage</h2>
          <p style="font-size: 20px; color: var(--muted); max-width: 700px; margin: 0 auto;">S3-compatible API, multi-language SDKs, and comprehensive documentation.</p>
        </div>

        <!-- Quick Start Card -->
        <div style="background: linear-gradient(145deg, #0f172a 0%, #1e293b 100%); border-radius: 24px; padding: 40px; margin-bottom: 60px; color: white;">
          <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 40px; align-items: center;">
            <div>
              <h3 style="font-size: 28px; margin: 0 0 16px 0; color: white;">Get started in 5 minutes</h3>
              <p style="font-size: 18px; opacity: 0.9; margin-bottom: 24px;">Create a bucket, generate access keys, and upload your first object.</p>
              <div style="display: flex; gap: 16px;">
                <a href="/docs/quickstart" style="background: var(--primary); color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 500;">Quickstart guide →</a>
                <a href="/docs/api" style="background: rgba(255,255,255,0.1); color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none;">API reference</a>
              </div>
            </div>
            <div style="background: #0f172a; border-radius: 16px; padding: 24px; font-family: monospace; font-size: 14px;">
              <div style="color: #86d986;">$ pip install cloudvault</div>
              <div style="color: #94a3b8; margin-top: 12px;">import cloudvault</div>
              <div style="color: #94a3b8;">client = cloudvault.Client()</div>
              <div style="color: #94a3b8;">bucket = client.create_bucket("my-app")</div>
              <div style="color: #86d986; margin-top: 12px;">✓ Bucket created</div>
            </div>
          </div>
        </div>

        <!-- SDKs Grid -->
        <h3 style="font-size: 28px; margin-bottom: 30px;">Official SDKs</h3>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 60px;">

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 24px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 16px;">🐍</div>
            <h4 style="margin: 0 0 8px 0;">Python</h4>
            <p style="color: var(--muted); font-size: 14px; margin-bottom: 16px;">v3.2.1</p>
            <div style="display: flex; justify-content: center; gap: 12px;">
              <a href="/docs/python" style="color: var(--primary); text-decoration: none; font-size: 14px;">Docs</a>
              <span style="color: var(--border);">|</span>
              <a href="#" style="color: var(--primary); text-decoration: none; font-size: 14px;">GitHub</a>
            </div>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 24px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 16px;">📘</div>
            <h4 style="margin: 0 0 8px 0;">Node.js</h4>
            <p style="color: var(--muted); font-size: 14px; margin-bottom: 16px;">v2.8.0</p>
            <div style="display: flex; justify-content: center; gap: 12px;">
              <a href="/docs/nodejs" style="color: var(--primary); text-decoration: none; font-size: 14px;">Docs</a>
              <span style="color: var(--border);">|</span>
              <a href="#" style="color: var(--primary); text-decoration: none; font-size: 14px;">GitHub</a>
            </div>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 24px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 16px;">☕</div>
            <h4 style="margin: 0 0 8px 0;">Java</h4>
            <p style="color: var(--muted); font-size: 14px; margin-bottom: 16px;">v1.5.2</p>
            <div style="display: flex; justify-content: center; gap: 12px;">
              <a href="/docs/java" style="color: var(--primary); text-decoration: none; font-size: 14px;">Docs</a>
              <span style="color: var(--border);">|</span>
              <a href="#" style="color: var(--primary); text-decoration: none; font-size: 14px;">GitHub</a>
            </div>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 24px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 16px;">🦀</div>
            <h4 style="margin: 0 0 8px 0;">Go</h4>
            <p style="color: var(--muted); font-size: 14px; margin-bottom: 16px;">v1.2.4</p>
            <div style="display: flex; justify-content: center; gap: 12px;">
              <a href="/docs/go" style="color: var(--primary); text-decoration: none; font-size: 14px;">Docs</a>
              <span style="color: var(--border);">|</span>
              <a href="#" style="color: var(--primary); text-decoration: none; font-size: 14px;">GitHub</a>
            </div>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 24px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 16px;">📱</div>
            <h4 style="margin: 0 0 8px 0;">Swift</h4>
            <p style="color: var(--muted); font-size: 14px; margin-bottom: 16px;">v1.1.0</p>
            <div style="display: flex; justify-content: center; gap: 12px;">
              <a href="/docs/swift" style="color: var(--primary); text-decoration: none; font-size: 14px;">Docs</a>
              <span style="color: var(--border);">|</span>
              <a href="#" style="color: var(--primary); text-decoration: none; font-size: 14px;">GitHub</a>
            </div>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 24px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 16px;">📱</div>
            <h4 style="margin: 0 0 8px 0;">Kotlin</h4>
            <p style="color: var(--muted); font-size: 14px; margin-bottom: 16px;">v1.0.3</p>
            <div style="display: flex; justify-content: center; gap: 12px;">
              <a href="/docs/kotlin" style="color: var(--primary); text-decoration: none; font-size: 14px;">Docs</a>
              <span style="color: var(--border);">|</span>
              <a href="#" style="color: var(--primary); text-decoration: none; font-size: 14px;">GitHub</a>
            </div>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 24px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 16px;">💎</div>
            <h4 style="margin: 0 0 8px 0;">Ruby</h4>
            <p style="color: var(--muted); font-size: 14px; margin-bottom: 16px;">v1.4.1</p>
            <div style="display: flex; justify-content: center; gap: 12px;">
              <a href="/docs/ruby" style="color: var(--primary); text-decoration: none; font-size: 14px;">Docs</a>
              <span style="color: var(--border);">|</span>
              <a href="#" style="color: var(--primary); text-decoration: none; font-size: 14px;">GitHub</a>
            </div>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 16px; padding: 24px; text-align: center;">
            <div style="font-size: 48px; margin-bottom: 16px;">🐘</div>
            <h4 style="margin: 0 0 8px 0;">PHP</h4>
            <p style="color: var(--muted); font-size: 14px; margin-bottom: 16px;">v2.0.1</p>
            <div style="display: flex; justify-content: center; gap: 12px;">
              <a href="/docs/php" style="color: var(--primary); text-decoration: none; font-size: 14px;">Docs</a>
              <span style="color: var(--border);">|</span>
              <a href="#" style="color: var(--primary); text-decoration: none; font-size: 14px;">GitHub</a>
            </div>
          </div>

        </div>

        <!-- Tools & Integrations -->
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 60px;">

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <h3 style="font-size: 24px; margin-top: 0; display: flex; align-items: center; gap: 12px;">
              <span style="font-size: 32px;">🛠️</span> CLI Tools
            </h3>
            <p style="color: var(--muted); margin-bottom: 24px;">Manage your buckets and objects from the command line.</p>
            <div style="background: #f8fafc; border-radius: 12px; padding: 20px; font-family: monospace; font-size: 14px;">
              <div style="color: #475569;">$ cvctl mb my-bucket</div>
              <div style="color: #475569; margin-top: 8px;">$ cvctl cp file.txt s3://my-bucket/</div>
              <div style="color: #475569; margin-top: 8px;">$ cvctl presign s3://my-bucket/file.txt --expires 3600</div>
            </div>
            <a href="/docs/cli" style="display: inline-block; margin-top: 20px; color: var(--primary); text-decoration: none; font-weight: 500;">View CLI documentation →</a>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <h3 style="font-size: 24px; margin-top: 0; display: flex; align-items: center; gap: 12px;">
              <span style="font-size: 32px;">🔌</span> Integrations
            </h3>
            <p style="color: var(--muted); margin-bottom: 24px;">Connect CloudVault with your favorite tools.</p>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="color: var(--primary);">✓</span> Terraform
              </div>
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="color: var(--primary);">✓</span> Kubernetes
              </div>
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="color: var(--primary);">✓</span> Docker
              </div>
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="color: var(--primary);">✓</span> GitHub Actions
              </div>
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="color: var(--primary);">✓</span> Jenkins
              </div>
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="color: var(--primary);">✓</span> GitLab CI
              </div>
            </div>
            <a href="/docs/integrations" style="display: inline-block; margin-top: 20px; color: var(--primary); text-decoration: none; font-weight: 500;">Browse all integrations →</a>
          </div>

        </div>

        <!-- API Examples -->
        <div style="margin-bottom: 60px;">
          <h3 style="font-size: 28px; margin-bottom: 30px;">API examples</h3>
          <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px;">

            <div style="background: #0f172a; border-radius: 16px; padding: 24px; color: white;">
              <h4 style="color: white; margin-top: 0; margin-bottom: 20px;">Create bucket</h4>
              <pre style="margin: 0; font-family: monospace; font-size: 13px; color: #cbd5e1; white-space: pre-wrap;">
PUT /bucket-name HTTP/1.1
Host: s3.cloudvault.com
Authorization: AWS4-HMAC-SHA256 ...
Date: ${new Date().toISOString().split('T')[0]}</pre>
            </div>

            <div style="background: #0f172a; border-radius: 16px; padding: 24px; color: white;">
              <h4 style="color: white; margin-top: 0; margin-bottom: 20px;">Upload object</h4>
              <pre style="margin: 0; font-family: monospace; font-size: 13px; color: #cbd5e1; white-space: pre-wrap;">
PUT /bucket-name/photo.jpg HTTP/1.1
Host: s3.cloudvault.com
Content-Length: 45678
Content-Type: image/jpeg</pre>
            </div>

            <div style="background: #0f172a; border-radius: 16px; padding: 24px; color: white;">
              <h4 style="color: white; margin-top: 0; margin-bottom: 20px;">Presigned URL</h4>
              <pre style="margin: 0; font-family: monospace; font-size: 13px; color: #cbd5e1; white-space: pre-wrap;">
GET /bucket-name/file.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...&X-Amz-Expires=3600</pre>
            </div>

          </div>
          <div style="text-align: center; margin-top: 30px;">
            <a href="/docs/api" style="display: inline-block; background: var(--primary); color: white; padding: 12px 28px; border-radius: 8px; text-decoration: none; font-weight: 500;">View full API reference</a>
          </div>
        </div>

        <!-- Community Section -->
        <div style="background: #f8fafc; border-radius: 24px; padding: 40px; text-align: center; margin-top: 40px;">
          <h3 style="font-size: 28px; margin-bottom: 16px;">Join our developer community</h3>
          <p style="color: var(--muted); font-size: 18px; max-width: 600px; margin: 0 auto 32px;">Connect with other developers, get help, and share what you're building.</p>
          <div style="display: flex; gap: 20px; justify-content: center;">
            <a href="#" style="display: flex; align-items: center; gap: 8px; color: var(--text); text-decoration: none; padding: 10px 20px; background: white; border-radius: 8px;">GitHub</a>
            <a href="#" style="display: flex; align-items: center; gap: 8px; color: var(--text); text-decoration: none; padding: 10px 20px; background: white; border-radius: 8px;">Discord</a>
            <a href="#" style="display: flex; align-items: center; gap: 8px; color: var(--text); text-decoration: none; padding: 10px 20px; background: white; border-radius: 8px;">Stack Overflow</a>
            <a href="#" style="display: flex; align-items: center; gap: 8px; color: var(--text); text-decoration: none; padding: 10px 20px; background: white; border-radius: 8px;">Twitter</a>
          </div>
        </div>

      </div>
    `;
  } else if (page.path === '/network') {
    pageTitle = "Global Edge Network";
    pageDescription = "200+ locations. 100+ Tbps capacity. 99.99% availability.";

    pageContent = `
      <div style="margin-top: 20px;">

        <!-- Hero Section -->
        <div style="text-align: center; margin-bottom: 60px;">
          <h2 style="font-size: 42px; margin-bottom: 20px; color: var(--text);">The world's most connected edge network</h2>
          <p style="font-size: 20px; color: var(--muted); max-width: 800px; margin: 0 auto;">Deliver content at lightning speed with our globally distributed edge infrastructure.</p>
        </div>

        <!-- Global Stats -->
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 30px; margin-bottom: 60px;">
          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px; text-align: center;">
            <div style="font-size: 48px; font-weight: 700; color: var(--primary); margin-bottom: 8px;">200+</div>
            <div style="font-size: 16px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px;">Edge Locations</div>
          </div>
          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px; text-align: center;">
            <div style="font-size: 48px; font-weight: 700; color: var(--primary); margin-bottom: 8px;">100+</div>
            <div style="font-size: 16px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px;">Tbps Capacity</div>
          </div>
          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px; text-align: center;">
            <div style="font-size: 48px; font-weight: 700; color: var(--primary); margin-bottom: 8px;">99.99%</div>
            <div style="font-size: 16px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px;">Network Availability</div>
          </div>
          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px; text-align: center;">
            <div style="font-size: 48px; font-weight: 700; color: var(--primary); margin-bottom: 8px;">&lt; 20ms</div>
            <div style="font-size: 16px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px;">Global Latency</div>
          </div>
        </div>

        <!-- World Map Visualization -->
        <div style="background: linear-gradient(145deg, #0f172a 0%, #1e293b 100%); border-radius: 32px; padding: 60px 40px; margin-bottom: 60px; color: white; position: relative; overflow: hidden;">

          <!-- Decorative grid lines -->
          <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; opacity: 0.1; background-image: radial-gradient(circle at 20% 30%, white 1px, transparent 1px), radial-gradient(circle at 80% 70%, white 1px, transparent 1px); background-size: 50px 50px;"></div>

          <div style="position: relative; z-index: 2;">
            <h3 style="font-size: 28px; margin: 0 0 40px 0; color: white; text-align: center;">Global edge presence</h3>

            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 30px; margin-bottom: 40px;">

              <div>
                <h4 style="color: white; margin-bottom: 20px; font-size: 18px;">🌎 North America</h4>
                <ul style="list-style: none; padding: 0; margin: 0;">
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Ashburn, VA</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Dallas, TX</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Los Angeles, CA</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Chicago, IL</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Toronto, ON</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">+12 more</li>
                </ul>
              </div>

              <div>
                <h4 style="color: white; margin-bottom: 20px; font-size: 18px;">🌍 Europe</h4>
                <ul style="list-style: none; padding: 0; margin: 0;">
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• London, UK</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Frankfurt, DE</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Paris, FR</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Amsterdam, NL</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Stockholm, SE</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">+8 more</li>
                </ul>
              </div>

              <div>
                <h4 style="color: white; margin-bottom: 20px; font-size: 18px;">🌏 Asia Pacific</h4>
                <ul style="list-style: none; padding: 0; margin: 0;">
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Tokyo, JP</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Singapore, SG</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Sydney, AU</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Mumbai, IN</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Seoul, KR</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">+6 more</li>
                </ul>
              </div>

              <div>
                <h4 style="color: white; margin-bottom: 20px; font-size: 18px;">🌎 South America & More</h4>
                <ul style="list-style: none; padding: 0; margin: 0;">
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• São Paulo, BR</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Buenos Aires, AR</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Santiago, CL</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Dubai, AE</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">• Johannesburg, ZA</li>
                  <li style="padding: 8px 0; display: flex; align-items: center; gap: 10px; color: #cbd5e1;">+4 more</li>
                </ul>
              </div>

            </div>
          </div>
        </div>

        <!-- Network Features Grid -->
        <h3 style="font-size: 28px; margin-bottom: 30px;">Why choose EdgeFlow network</h3>
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; margin-bottom: 60px;">

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 40px; margin-bottom: 20px;">⚡</div>
            <h4 style="font-size: 20px; margin: 0 0 12px 0;">Intelligent routing</h4>
            <p style="color: var(--muted); line-height: 1.6;">Real-time traffic optimization using Anycast and BGP anycast. Automatically routes users to the fastest available edge location.</p>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 40px; margin-bottom: 20px;">🛡️</div>
            <h4 style="font-size: 20px; margin: 0 0 12px 0;">DDoS mitigation</h4>
            <p style="color: var(--muted); line-height: 1.6;">Always-on protection against layer 3/4/7 attacks. 10 Tbps+ mitigation capacity distributed globally.</p>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 40px; margin-bottom: 20px;">🚀</div>
            <h4 style="font-size: 20px; margin: 0 0 12px 0;">Instant purge</h4>
            <p style="color: var(--muted); line-height: 1.6;">Global cache purging in under 5 seconds. Update content instantly across all 200+ edge locations.</p>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 40px; margin-bottom: 20px;">🔒</div>
            <h4 style="font-size: 20px; margin: 0 0 12px 0;">SSL/TLS everywhere</h4>
            <p style="color: var(--muted); line-height: 1.6;">Automatic HTTPS with custom certificates. TLS 1.3 enforced across the entire edge network.</p>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 40px; margin-bottom: 20px;">📊</div>
            <h4 style="font-size: 20px; margin: 0 0 12px 0;">Real-time analytics</h4>
            <p style="color: var(--muted); line-height: 1.6;">Live traffic visualization, cache hit ratios, bandwidth usage, and error rates per edge location.</p>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 20px; padding: 32px;">
            <div style="font-size: 40px; margin-bottom: 20px;">🌐</div>
            <h4 style="font-size: 20px; margin: 0 0 12px 0;">IPv6 ready</h4>
            <p style="color: var(--muted); line-height: 1.6;">Dual-stack support at all edge locations. Native IPv6 connectivity with zero configuration.</p>
          </div>

        </div>

        <!-- Performance Comparison -->
        <div style="background: #f8fafc; border-radius: 24px; padding: 40px; margin-bottom: 60px;">
          <h3 style="font-size: 24px; margin-top: 0; margin-bottom: 30px;">Global performance comparison</h3>

          <div style="display: grid; grid-template-columns: 1fr 2fr 2fr; gap: 20px; align-items: center; margin-bottom: 20px; padding: 12px; background: white; border-radius: 12px;">
            <div style="font-weight: 600;">Region</div>
            <div style="font-weight: 600;">EdgeFlow latency</div>
            <div style="font-weight: 600;">Traditional CDN</div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 2fr 2fr; gap: 20px; align-items: center; margin-bottom: 12px; padding: 12px;">
            <div>North America</div>
            <div style="display: flex; align-items: center; gap: 10px;">
              <span style="font-weight: 600; color: var(--primary);">14ms</span>
              <div style="background: #e2e8f0; height: 8px; width: 100px; border-radius: 4px; overflow: hidden;">
                <div style="background: var(--primary); width: 30%; height: 8px;"></div>
              </div>
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
              <span>28ms</span>
              <div style="background: #e2e8f0; height: 8px; width: 100px; border-radius: 4px; overflow: hidden;">
                <div style="background: #94a3b8; width: 60%; height: 8px;"></div>
              </div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 2fr 2fr; gap: 20px; align-items: center; margin-bottom: 12px; padding: 12px;">
            <div>Europe</div>
            <div style="display: flex; align-items: center; gap: 10px;">
              <span style="font-weight: 600; color: var(--primary);">18ms</span>
              <div style="background: #e2e8f0; height: 8px; width: 100px; border-radius: 4px; overflow: hidden;">
                <div style="background: var(--primary); width: 35%; height: 8px;"></div>
              </div>
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
              <span>32ms</span>
              <div style="background: #e2e8f0; height: 8px; width: 100px; border-radius: 4px; overflow: hidden;">
                <div style="background: #94a3b8; width: 65%; height: 8px;"></div>
              </div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 2fr 2fr; gap: 20px; align-items: center; margin-bottom: 12px; padding: 12px;">
            <div>Asia Pacific</div>
            <div style="display: flex; align-items: center; gap: 10px;">
              <span style="font-weight: 600; color: var(--primary);">22ms</span>
              <div style="background: #e2e8f0; height: 8px; width: 100px; border-radius: 4px; overflow: hidden;">
                <div style="background: var(--primary); width: 45%; height: 8px;"></div>
              </div>
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
              <span>45ms</span>
              <div style="background: #e2e8f0; height: 8px; width: 100px; border-radius: 4px; overflow: hidden;">
                <div style="background: #94a3b8; width: 90%; height: 8px;"></div>
              </div>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 2fr 2fr; gap: 20px; align-items: center; padding: 12px;">
            <div>South America</div>
            <div style="display: flex; align-items: center; gap: 10px;">
              <span style="font-weight: 600; color: var(--primary);">35ms</span>
              <div style="background: #e2e8f0; height: 8px; width: 100px; border-radius: 4px; overflow: hidden;">
                <div style="background: var(--primary); width: 70%; height: 8px;"></div>
              </div>
            </div>
            <div style="display: flex; align-items: center; gap: 10px;">
              <span>58ms</span>
              <div style="background: #e2e8f0; height: 8px; width: 100px; border-radius: 4px; overflow: hidden;">
                <div style="background: #94a3b8; width: 100%; height: 8px;"></div>
              </div>
            </div>
          </div>

          <div style="margin-top: 30px; padding: 20px; background: white; border-radius: 12px; text-align: center;">
            <p style="margin: 0; color: var(--muted);">EdgeFlow delivers content <strong style="color: var(--primary);">2.1x faster</strong> on average compared to traditional CDNs</p>
          </div>
        </div>

        <!-- Edge Locations Map (Text-based) -->
        <div style="margin-bottom: 60px;">
          <h3 style="font-size: 24px; margin-bottom: 30px;">Recently added edge locations</h3>
          <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px;">

            <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center;">
              <div style="font-size: 24px; margin-bottom: 8px;">🇦🇪</div>
              <div style="font-weight: 600;">Dubai</div>
              <div style="color: var(--muted); font-size: 14px;">UAE</div>
              <div style="margin-top: 12px; background: #dcfce7; color: #166534; padding: 4px 8px; border-radius: 20px; font-size: 12px; display: inline-block;">Live</div>
            </div>

            <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center;">
              <div style="font-size: 24px; margin-bottom: 8px;">🇿🇦</div>
              <div style="font-weight: 600;">Johannesburg</div>
              <div style="color: var(--muted); font-size: 14px;">South Africa</div>
              <div style="margin-top: 12px; background: #dcfce7; color: #166534; padding: 4px 8px; border-radius: 20px; font-size: 12px; display: inline-block;">Live</div>
            </div>

            <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center;">
              <div style="font-size: 24px; margin-bottom: 8px;">🇮🇩</div>
              <div style="font-weight: 600;">Jakarta</div>
              <div style="color: var(--muted); font-size: 14px;">Indonesia</div>
              <div style="margin-top: 12px; background: #dcfce7; color: #166534; padding: 4px 8px; border-radius: 20px; font-size: 12px; display: inline-block;">Live</div>
            </div>

            <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center;">
              <div style="font-size: 24px; margin-bottom: 8px;">🇨🇱</div>
              <div style="font-weight: 600;">Santiago</div>
              <div style="color: var(--muted); font-size: 14px;">Chile</div>
              <div style="margin-top: 12px; background: #fef9c3; color: #854d0e; padding: 4px 8px; border-radius: 20px; font-size: 12px; display: inline-block;">Coming soon</div>
            </div>

            <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center;">
              <div style="font-size: 24px; margin-bottom: 8px;">🇳🇬</div>
              <div style="font-weight: 600;">Lagos</div>
              <div style="color: var(--muted); font-size: 14px;">Nigeria</div>
              <div style="margin-top: 12px; background: #fef9c3; color: #854d0e; padding: 4px 8px; border-radius: 20px; font-size: 12px; display: inline-block;">Q2 2026</div>
            </div>

          </div>
        </div>

        <!-- Bandwidth Pricing -->
        <div style="background: linear-gradient(145deg, var(--primary) 0%, var(--primary-light) 100%); border-radius: 24px; padding: 40px; color: white; margin-bottom: 40px;">
          <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 40px; align-items: center;">
            <div>
              <h3 style="font-size: 28px; margin: 0 0 16px 0; color: white;">Global bandwidth pricing</h3>
              <p style="font-size: 18px; opacity: 0.95; margin-bottom: 24px;">Simple, transparent pricing across all edge locations. No regional markups.</p>
              <div style="display: flex; gap: 40px;">
                <div>
                  <div style="font-size: 14px; opacity: 0.9;">North America & Europe</div>
                  <div style="font-size: 32px; font-weight: 700;">$0.08</div>
                  <div style="font-size: 14px; opacity: 0.9;">per GB</div>
                </div>
                <div>
                  <div style="font-size: 14px; opacity: 0.9;">Asia Pacific</div>
                  <div style="font-size: 32px; font-weight: 700;">$0.10</div>
                  <div style="font-size: 14px; opacity: 0.9;">per GB</div>
                </div>
                <div>
                  <div style="font-size: 14px; opacity: 0.9;">South America</div>
                  <div style="font-size: 32px; font-weight: 700;">$0.12</div>
                  <div style="font-size: 14px; opacity: 0.9;">per GB</div>
                </div>
              </div>
            </div>
            <div style="text-align: right;">
              <div style="font-size: 60px; margin-bottom: 10px;">🌐</div>
              <div style="font-size: 18px; font-weight: 600;">Volume discounts available</div>
              <div style="opacity: 0.9;">Contact sales for >50 TB/month</div>
            </div>
          </div>
        </div>

        <!-- Trust Signals -->
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 30px 0; border-top: 1px solid var(--border); margin-top: 20px;">
          <div style="display: flex; gap: 40px;">
            <div style="display: flex; align-items: center; gap: 12px;">
              <div style="font-size: 24px;">🏆</div>
              <div style="font-weight: 500;">Gartner Peer Insights</div>
            </div>
            <div style="display: flex; align-items: center; gap: 12px;">
              <div style="font-size: 24px;">⭐</div>
              <div style="font-weight: 500;">4.9/5 customer rating</div>
            </div>
            <div style="display: flex; align-items: center; gap: 12px;">
              <div style="font-size: 24px;">🔒</div>
              <div style="font-weight: 500;">SOC2 Type II</div>
            </div>
          </div>
          <a href="/contact" style="background: var(--primary); color: white; padding: 12px 28px; border-radius: 8px; text-decoration: none; font-weight: 500;">Get started</a>
        </div>

      </div>
    `;

  } else if (page.path === '/status') {
    pageTitle = "System Status";
    pageDescription = "Real-time operational status";

    pageContent = `
      <div style="margin-top: 20px;">
        <div style="background: #f0f9f0; border: 1px solid #86d986; border-radius: 12px; padding: 24px; display: flex; align-items: center; gap: 16px; margin-bottom: 40px;">
          <div style="background: #4caf50; width: 12px; height: 12px; border-radius: 50%;"></div>
          <div style="font-weight: 600;">All systems operational</div>
          <div style="color: var(--muted); margin-left: auto;">Last updated: ${new Date().toLocaleString()}</div>
        </div>

        <div style="display: grid; gap: 16px;">
          <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 24px; display: flex; align-items: center; justify-content: space-between;">
            <div>
              <div style="font-weight: 600; margin-bottom: 4px;">API</div>
              <div style="color: var(--muted); font-size: 14px;">US East, US West, EU, Asia</div>
            </div>
            <div style="display: flex; align-items: center; gap: 20px;">
              <div style="color: #4caf50; font-weight: 500;">Operational</div>
              <div style="color: var(--muted);">99.97% uptime</div>
            </div>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 24px; display: flex; align-items: center; justify-content: space-between;">
            <div>
              <div style="font-weight: 600; margin-bottom: 4px;">Storage</div>
              <div style="color: var(--muted); font-size: 14px;">S3-compatible object storage</div>
            </div>
            <div style="display: flex; align-items: center; gap: 20px;">
              <div style="color: #ff9800; font-weight: 500;">Degraded</div>
              <div style="color: var(--muted);">EU region</div>
            </div>
          </div>

          <div style="background: white; border: 1px solid var(--border); border-radius: 12px; padding: 24px; display: flex; align-items: center; justify-content: space-between;">
            <div>
              <div style="font-weight: 600; margin-bottom: 4px;">CDN</div>
              <div style="color: var(--muted); font-size: 14px;">Global edge network</div>
            </div>
            <div style="display: flex; align-items: center; gap: 20px;">
              <div style="color: #4caf50; font-weight: 500;">Operational</div>
              <div style="color: var(--muted);">200+ edge locations</div>
            </div>
          </div>
        </div>
      </div>
    `;

  } else if (page.path.includes('/docs')) {
    pageTitle = "Documentation";
    pageDescription = `Technical documentation for ${persona.name}`;
  }
  
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${pageTitle} - ${persona.name}</title>
  <meta name="description" content="${pageDescription}" />
  <meta name="robots" content="index, follow" />
  <meta name="generator" content="${persona.sitekey}-${rotationSeed()}" />
  <style>
    :root {
      --primary: ${persona.primaryColor};
      --primary-light: ${persona.secondaryColor};
      --bg: #f8fafc;
      --surface: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e2e8f0;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      line-height: 1.6;
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--text);
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 24px;
    }
    header {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 20px 0;
      margin-bottom: 40px;
    }
    .header-content {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
    }
    .logo {
      font-size: 24px;
      font-weight: bold;
      color: var(--primary);
      text-decoration: none;
    }
    .logo span {
      margin-right: 8px;
    }
    nav {
      display: flex;
      gap: 24px;
      flex-wrap: wrap;
    }
    .nav-link {
      color: var(--muted);
      text-decoration: none;
      font-size: 15px;
      padding: 8px 0;
      border-bottom: 2px solid transparent;
      transition: all 0.2s;
    }
    .nav-link:hover,
    .nav-link.active {
      color: var(--primary);
      border-bottom-color: var(--primary);
    }
    main {
      min-height: 60vh;
    }
    .hero {
      background: linear-gradient(135deg, var(--surface) 0%, #fafbfc 100%);
      border-radius: 16px;
      padding: 48px 40px;
      margin-bottom: 40px;
      border: 1px solid var(--border);
    }
    h1 {
      font-size: 42px;
      margin: 0 0 16px 0;
      color: var(--text);
    }
    .lead {
      font-size: 20px;
      color: var(--muted);
      max-width: 800px;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 24px;
      margin: 48px 0;
    }
    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      text-align: center;
    }
    .stat-value {
      font-size: 32px;
      font-weight: bold;
      color: var(--primary);
      margin-bottom: 8px;
    }
    .stat-label {
      color: var(--muted);
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .features {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 24px;
      margin: 40px 0;
    }
    .feature-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
    }
    .feature-icon {
      font-size: 24px;
      margin-bottom: 16px;
    }
    .feature-title {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 12px;
    }
    .feature-desc {
      color: var(--muted);
      font-size: 14px;
    }
    .page-content {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 32px;
      margin: 40px 0;
    }
    footer {
      margin-top: 80px;
      padding: 40px 0;
      border-top: 1px solid var(--border);
    }
    .footer-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 40px;
      margin-bottom: 32px;
    }
    .footer-section h4 {
      color: var(--text);
      font-size: 14px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 16px;
    }
    .footer-section a {
      display: block;
      color: var(--muted);
      text-decoration: none;
      font-size: 14px;
      margin-bottom: 8px;
    }
    .footer-section a:hover {
      color: var(--primary);
    }
    .copyright {
      text-align: center;
      color: var(--muted);
      font-size: 13px;
      padding-top: 32px;
      border-top: 1px solid var(--border);
    }
    @media (max-width: 768px) {
      .header-content {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      nav {
        width: 100%;
        justify-content: space-between;
      }
      h1 { font-size: 32px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="container header-content">
      <a href="/" class="logo">
  <span>${persona.logo}</span> ${PUBLIC_SITE_NAME || persona.name}
      </a>
      <nav>
        ${navLinks}
      </nav>
    </div>
  </header>
  
  <main class="container">
    ${page.path === '/' ? `
      <div class="hero">
        <h1>${persona.tagline}</h1>
        <p class="lead">${persona.description}</p>
      </div>
      
      <div class="stats">
        <div class="stat-card">
          <div class="stat-value">${dailyRequests.toLocaleString()}</div>
          <div class="stat-label">Daily Requests</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${uptime}%</div>
          <div class="stat-label">Uptime SLA</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${latency}ms</div>
          <div class="stat-label">Avg Latency</div>
        </div>
      </div>
      
      <h2>Platform Features</h2>
      <div class="features">
        ${persona.features.slice(0, 6).map(feature => `
          <div class="feature-card">
            <div class="feature-icon">${persona.logo}</div>
            <div class="feature-title">${feature}</div>
            <div class="feature-desc">Enterprise-grade ${feature.toLowerCase()} for demanding workloads.</div>
          </div>
        `).join('')}
      </div>
    ` : pageContent ? `
      <div class="page-content">
        <h1>${pageTitle}</h1>
        <p style="color: var(--muted); font-size: 18px; margin-bottom: 32px;">${pageDescription}</p>
        ${pageContent}
      </div>
    ` : `
      <div class="page-content">
        <h1>${pageTitle}</h1>
        <p style="color: var(--muted); font-size: 18px; margin-bottom: 32px;">${pageDescription}</p>
        
        <div style="display: grid; grid-template-columns: 1fr; gap: 24px;">
          <div style="padding: 24px; background: #f8fafc; border-radius: 8px;">
            <h3 style="margin-top: 0;">Page Information</h3>
            <ul style="margin-bottom: 0;">
              ${pageFeatures}
            </ul>
          </div>
        </div>
      </div>
    `}
  </main>
  
  <footer>
    <div class="container">
      <div class="footer-grid">
        <div class="footer-section">
          <h4>Product</h4>
          ${persona.footerLinks.slice(0, 4).map(link => `<a href="${link.path}">${link.text}</a>`).join('')}
        </div>
        <div class="footer-section">
          <h4>Resources</h4>
          <a href="/docs">Documentation</a>
          <a href="/blog">Blog</a>
          <a href="/status">Status</a>
          <a href="/security">Security</a>
        </div>
        <div class="footer-section">
          <h4>Company</h4>
          <a href="/about">About</a>
          <a href="/careers">Careers</a>
          <a href="/partners">Partners</a>
          <a href="/contact">Contact</a>
        </div>
        <div class="footer-section">
          <h4>Legal</h4>
          <a href="/privacy">Privacy</a>
          <a href="/terms">Terms</a>
          <a href="/compliance">Compliance</a>
          <a href="/sla">SLA</a>
        </div>
      </div>
      <div class="copyright">
        <p>© ${new Date().getFullYear()} ${PUBLIC_SITE_NAME || persona.name}. All rights reserved.</p>
      </div>
    </div>
  </footer>
  
  ${PUBLIC_ENABLE_ANALYTICS ? `
  <!-- Analytics -->
  <script>
    (function() {
      // Page view tracking
      const pageView = {
        path: '${page.path}',
        referrer: document.referrer || '(direct)',
        timestamp: Date.now(),
        persona: '${persona.sitekey}',
        session: '${seed.slice(0, 12)}'
      };
      
      // Send analytics asynchronously
      if (navigator.sendBeacon) {
        navigator.sendBeacon('/_collect', JSON.stringify(pageView));
      }
      
      // Simulate interaction after delay
      setTimeout(() => {
        if (document.visibilityState === 'visible') {
          fetch('/_interact', { 
            method: 'POST',
            keepalive: true 
          }).catch(() => {});
        }
      }, 8000 + Math.random() * 7000);
    })();
  </script>
  ` : ''}
</body>
</html>`;
}

// ================== GENERATE API RESPONSES ==================
function generateDummyAPIResponse(path, persona, seed) {
  const endpoint = path.split('/').pop();
  const timestamp = new Date().toISOString();
  const requestId = crypto.createHash('md5').update(`${seed}:${path}:${Date.now()}`).digest('hex').slice(0, 12);
  
  // Base response structure
  const response = {
    success: true,
    timestamp,
    request_id: requestId,
    service: persona.name,
    version: `v${hash32(`${seed}:version`) % 4 + 1}.0.0`
  };
  
  // Endpoint-specific data
  if (path.includes('/status')) {
    response.data = {
      status: 'operational',
      uptime: (99.9 + (hash32(`${seed}:uptime_api`) % 10) / 100).toFixed(2) + '%',
      latency_ms: hash32(`${seed}:latency_api`) % 30 + 10,
      services: {
        api: 'healthy',
        database: 'healthy',
        cache: 'healthy',
        storage: 'degraded'
      }
    };
  } else if (path.includes('/metrics')) {
    response.data = {
      requests_per_second: hash32(`${seed}:rps`) % 500 + 100,
      bandwidth_mbps: (hash32(`${seed}:bandwidth`) % 800 + 200).toFixed(2),
      active_connections: hash32(`${seed}:connections`) % 10000 + 1000,
      cache_hit_rate: (hash32(`${seed}:cache`) % 15 + 80).toFixed(1) + '%'
    };
  } else if (path.includes('/buckets') || path.includes('/objects')) {
    response.data = {
      buckets: Array.from({length: 3}, (_, i) => ({
        name: `bucket-${i + 1}-${seed.slice(0, 4)}`,
        objects: hash32(`${seed}:objects:${i}`) % 1000 + 100,
        size_gb: (hash32(`${seed}:size:${i}`) % 500 + 50).toFixed(2)
      }))
    };
  } else if (path.includes('/streams')) {
    response.data = {
      active_streams: hash32(`${seed}:streams`) % 500 + 50,
      viewers: hash32(`${seed}:viewers`) % 50000 + 5000,
      bitrates: ['240p', '480p', '720p', '1080p', '4K']
    };
  } else if (path.includes('/threats')) {
    response.data = {
      blocked_requests: hash32(`${seed}:blocked`) % 100000 + 5000,
      top_attack_types: [
        { type: 'SQL Injection', count: hash32(`${seed}:sql`) % 500 + 100 },
        { type: 'XSS', count: hash32(`${seed}:xss`) % 300 + 50 },
        { type: 'Bot', count: hash32(`${seed}:bot`) % 1000 + 200 }
      ]
    };
  } else {
    response.data = {
      message: 'Endpoint operational',
      documentation: 'https://docs.' + persona.sitekey + '.com',
      rate_limit: hash32(`${seed}:rate`) % 1000 + 500
    };
  }
  
  return JSON.stringify(response, null, 2);
}

// ================== DUMMY SITEMAP GENERATOR ==================
function generateEnhancedSitemap(req, persona, allPaths) {
  const baseUrls = resolvePublicBaseUrls(req, { requestHostOnly: true, preferConfiguredCanonical: true });
  const today = new Date().toISOString().split('T')[0];
  
  const urlEntries = [];
  for (const baseUrl of baseUrls) {
    // Add all generated paths
    allPaths.forEach(path => {
      const priority = path === '/' ? '1.0' : 
                      path.match(/^(p|shared|preview|embed)/) ? '0.3' : 
                      path.match(/^(blog|articles|docs)/) ? '0.7' : '0.5';
      
      const changefreq = path === '/' ? 'daily' :
                        path.includes('blog') ? 'weekly' :
                        path.includes('docs') ? 'monthly' : 'weekly';
      
      urlEntries.push(`
  <url>
    <loc>${baseUrl}${path}</loc>
    <lastmod>${today}</lastmod>
    <changefreq>${changefreq}</changefreq>
    <priority>${priority}</priority>
  </url>`);
    });
  }
  
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
  ${urlEntries.join('')}
</urlset>`;
}

// ================== BACKGROUND TRAFFIC GENERATOR ==================
function startPublicBackgroundTraffic() {
  if (!PUBLIC_ENABLE_BACKGROUND || !PUBLIC_CONTENT_SURFACE) return;
  
  const generateVisit = async () => {
    try {
      const persona = getActivePersona();
      const allPaths = generateAllPaths(persona, seed);
      
      // Pick a random path
      const randomPath = allPaths[Math.floor(Math.random() * allPaths.length)];
      
      // Random user agent (mix of browsers)
      const userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      ];
      
      // 30% chance of being a search engine bot
      const isBot = Math.random() < 0.3;
      const botAgents = [
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 (compatible; DuckDuckBot/1.0; +https://duckduckgo.com/duckduckbot)',
        'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)'
      ];
      
      const ua = isBot 
        ? botAgents[Math.floor(Math.random() * botAgents.length)]
        : userAgents[Math.floor(Math.random() * userAgents.length)];
      
      // Random referrer
      const referrers = [
        'https://www.google.com/search?q=' + encodeURIComponent(persona.name),
        'https://www.bing.com/search?q=' + encodeURIComponent(persona.sitekey),
        'https://github.com/search?q=' + persona.sitekey,
        'https://news.ycombinator.com',
        'https://twitter.com',
        'https://linkedin.com',
        randomPath.includes('blog') ? 'https://www.reddit.com/r/programming' : '',
        ''
      ];
      
      const referrer = referrers[Math.floor(Math.random() * referrers.length)];
      
      // Make request
      await fetch(`http://localhost:${EFFECTIVE_PORT}${randomPath}`, {
        headers: {
          'User-Agent': ua,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br',
          'DNT': '1',
          'Connection': 'keep-alive',
          'Upgrade-Insecure-Requests': '1',
          ...(referrer && { 'Referer': referrer })
        }
      });
      
      addLog(`[PUBLIC-TRAFFIC] Generated ${isBot ? 'bot' : 'human'} visit to ${randomPath} (${persona.sitekey})`);
      
    } catch (error) {
      // Silent fail
    }
    
    // Schedule next visit (30s - 3min)
    const delay = 30000 + Math.random() * 150000;
    setTimeout(generateVisit, delay);
  };
  
  // Start after random delay (0-60s)
  setTimeout(generateVisit, Math.random() * 60000);
}

// ================== REGISTER ENHANCED ROUTES ==================
function registerEnhancedPublicRoutes() {
  const publicSurfaceEnabled = isPublicContentSurfaceEnabled();
  if (!publicSurfaceEnabled) return;
  
  const persona = getActivePersona();
  const allPaths = generateAllPaths(persona, rotationSeed());
  const seed = rotationSeed();
  
  // ===== STATIC PAGES =====
  // Homepage
  app.get('/', (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderEnhancedPublicPage(req, { path: '/', title: 'Home' }));
  });
  
  // Register ALL generated paths
allPaths.forEach(path => {
  app.get(path, (req, res) => {
    const normalizedPath = String(path || '').toLowerCase();
    const acceptHeader = String(req.headers.accept || '').toLowerCase();
    const hasJsonExtension = normalizedPath.endsWith('.json');
    const isApiPath = normalizedPath.startsWith('/api/');
    const wantsJson = acceptHeader.includes('application/json');

    // Serve JSON only for explicit API/JSON requests.
    if (isApiPath || hasJsonExtension || wantsJson) {
      // API response
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-cache');
      res.send(generateDummyAPIResponse(path, persona, `${seed}:${path}`));
    } else {
      // ✅ FIX: Force HTML for these paths
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=300');
      
      const pageTitle = path.split('/').pop()
        .replace(/-/g, ' ')
        .replace(/^\w/, c => c.toUpperCase());
      
      res.send(renderEnhancedPublicPage(req, { 
        path, 
        title: pageTitle,
        summary: `${persona.name} - ${pageTitle}`
      }));
    }
  });
});
  
  // ===== API ENDPOINTS - ✅ DEDICATED STATUS ENDPOINT with PUBLIC_SITE_NAME =====
app.get("/api/v1/status", (req, res) => {
  const mem = process.memoryUsage();
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-cache");
  res.json({
    service: PUBLIC_SITE_NAME || persona.name,
    status: "operational",
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    version: `v${hash32(`${seed}:version`) % 4 + 1}.0.0`,
    metrics: {
      dailyRequests: hash32(`${seed}:requests`) % 90000 + 10000,
      uptime: (99.9 + (hash32(`${seed}:uptime`) % 10) / 100).toFixed(2) + '%',
      latency: (hash32(`${seed}:latency`) % 40 + 15).toFixed(0) + 'ms'
    },
    persona: {
      name: persona.name,
      sitekey: persona.sitekey
    }
  });
});
  
  persona.apiEndpoints.forEach(endpoint => {
    app.get(endpoint, (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-cache');
      res.send(generateDummyAPIResponse(endpoint, persona, `${seed}:${endpoint}`));
    });
  });
  
  // ===== ANALYTICS COLLECTOR =====
  if (PUBLIC_ENABLE_ANALYTICS) {
    app.post('/_collect', express.json({ limit: '2kb' }), (req, res) => {
      // Silently collect analytics
      res.status(204).end();
    });
    
    app.post('/_interact', (req, res) => {
      // Track interaction
      res.status(204).end();
    });
    
    // 1x1 transparent GIF for legacy tracking
    app.get('/_analytics.gif', (req, res) => {
      res.setHeader('Content-Type', 'image/gif');
      res.setHeader('Cache-Control', 'no-store, max-age=0');
      res.send(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));
    });
  }
  
  // ===== SITEMAP =====
app.get("/sitemap.xml", (req, res) => {
  const baseUrls = resolvePublicBaseUrls(req, { requestHostOnly: true, preferConfiguredCanonical: true });
  const today = new Date().toISOString().split('T')[0];
  
  // Generate ALL paths from your persona
  const allPaths = generateAllPaths(persona);
  
  // Add homepage and all generated paths
  const urlEntries = [];
  
  // Add all paths to sitemap
  allPaths.forEach(path => {
    // Skip API endpoints and analytics paths
    if (path.startsWith('/api/') || 
        path.startsWith('/_') || 
        path.includes('analytics') ||
        path.includes('collect') ||
        path.includes('interact')) {
      return;
    }
    
    baseUrls.forEach(baseUrl => {
      const priority = path === '/' ? '1.0' : 
                      path.match(/^(pricing|solutions|features)/) ? '0.9' :
                      path.match(/^(blog|articles|guides)/) ? '0.8' :
                      path.match(/^(docs|status|security)/) ? '0.7' : '0.6';
      
      const changefreq = path === '/' ? 'daily' :
                        path.includes('blog') ? 'weekly' :
                        path.includes('docs') ? 'monthly' : 'weekly';
      
      urlEntries.push(`
  <url>
    <loc>${baseUrl}${path}</loc>
    <lastmod>${today}</lastmod>
    <changefreq>${changefreq}</changefreq>
    <priority>${priority}</priority>
  </url>`);
    });
  });
  
  res.setHeader('Content-Type', 'application/xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=900');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">${urlEntries.join('')}
</urlset>`);
  
  addLog(`[SITEMAP] Generated ${urlEntries.length} URLs for ${persona.name}`);
});
  
  // ===== ROBOTS.TXT =====
  app.get('/robots.txt', (req, res) => {
    const baseUrls = resolvePublicBaseUrls(req, { requestHostOnly: true, preferConfiguredCanonical: true });
    const sitemapUrl = `${baseUrls[0]}/sitemap.xml`;
    
    const robots = `User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/internal/
Disallow: /_analytics
Disallow: /_collect
Disallow: /_interact

# Sitemap location
Sitemap: ${sitemapUrl}

# Crawl settings
Crawl-delay: 1

# Special directives for specific bots
User-agent: Googlebot
Allow: /blog/
Allow: /docs/

User-agent: Bingbot
Allow: /blog/
Allow: /docs/

User-agent: AhrefsBot
Crawl-delay: 2

User-agent: SemrushBot
Crawl-delay: 2`;
    
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(robots);
  });
  
  // ===== FAVICON =====
  app.get('/favicon.ico', (req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.status(204).end();
  });
}

// ================== INITIALIZATION ==================
function initEnhancedPublicContent() {
  if (!PUBLIC_CONTENT_SURFACE) return;
  
  // Register all routes
  registerEnhancedPublicRoutes();
  
  // Start background traffic
  startPublicBackgroundTraffic();
}

  return {
    PUBLIC_CONTENT_SURFACE,
    PUBLIC_ENABLE_BACKGROUND,
    PUBLIC_SITE_BASE_URL,
    isPublicContentSurfaceEnabled,
    getActivePersona,
    generateAllPaths,
    initEnhancedPublicContent,
  };
};
