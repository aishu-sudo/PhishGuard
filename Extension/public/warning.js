const params = new URLSearchParams(window.location.search);
const targetUrl = params.get("url");
const decodedUrl = targetUrl ? decodeURIComponent(targetUrl) : null;
const level = params.get("level");
const score = params.get("score");
const tabIdParam = params.get("tabId");
const tabId = tabIdParam !== null ? Number(tabIdParam) : null;

const container = document.getElementById("mainContainer");
const levelIcon = document.getElementById("levelIcon");
const levelTitle = document.getElementById("levelTitle");
const levelDescription = document.getElementById("levelDescription");
const riskBox = document.getElementById("riskBox");
const detailsBtn = document.getElementById("detailsBtn");
const detailsPanel = document.getElementById("detailsPanel");
const detailsContent = document.getElementById("detailsContent");

let investigationRequested = false;

document.getElementById("backBtn").addEventListener("click", function() {
    history.back();
});

document.getElementById("continueBtn").addEventListener("click", function() {
    if (!decodedUrl) return;
    chrome.runtime.sendMessage({ type: "PG_PROCEED_ANYWAY", tabId: tabId, url: decodedUrl },
        function() {
            if (chrome.runtime.lastError) {
                window.location.href = decodedUrl;
            }
        }
    );
});

detailsBtn.addEventListener("click", function() {
    var willShow = detailsPanel.classList.contains("hidden");
    detailsPanel.classList.toggle("hidden");
    if (willShow && !investigationRequested) {
        investigationRequested = true;
        loadInvestigation();
    }
});

function applyLevelStyling(level, score) {
    if (level === "RED") {
        container.classList.add("level-red");
        levelIcon.textContent = "🚨";
        levelTitle.textContent = "Dangerous Phishing Website Detected";
        levelDescription.textContent =
            "PhishGuard has strong evidence this website is attempting to steal passwords, OTPs, banking information, or personal data.";
    } else if (level === "YELLOW") {
        container.classList.add("level-yellow");
        levelIcon.textContent = "⚠️";
        levelTitle.textContent = "Suspicious Website Detected";
        levelDescription.textContent =
            "PhishGuard found some suspicious signals on this website. Review the details below before proceeding.";
    }

    riskBox.textContent = "Risk Score: " + Math.round(Number(score || 0) * 100) + "%";
}

function row(label, value) {
    var displayValue = (value === undefined || value === null || value === "") ? "—" : value;
    return '<div class="detail-row"><span class="label">' + label + '</span><span class="value">' + displayValue + '</span></div>';
}

function truncateUrl(url, maxLen) {
    if (!url || url.length <= maxLen) return url;
    return url.slice(0, maxLen) + "…";
}

function renderClusterSection(cert, sharedHost) {
    var certLine;
    var certFailed = cert.status && cert.status !== "ok" && cert.status !== "ok_degraded";

    if (certFailed) {
        certLine = '<span style="color:#f59e0b">Check failed (' + cert.status + (cert.status_code ? ' ' + cert.status_code : '') + ')</span>';
    } else if (cert.related) {
        var relatedCount = (cert.related_domains && cert.related_domains.length) ? cert.related_domains.length : 0;
        certLine = '<span class="badge-flag">Yes (' + relatedCount + ')</span>';
    } else {
        certLine = cert.status === "ok_degraded" ? "No (via live TLS certificate — crt.sh unavailable)" : "No";
    }

    var hostLine;
    if (sharedHost.status === "rate_limited") {
        hostLine = '<span style="color:#f59e0b">Rate limited (HackerTarget free-tier quota reached)</span>';
    } else if (sharedHost.status && sharedHost.status !== "ok") {
        hostLine = '<span style="color:#f59e0b">Check failed (' + sharedHost.status + ')</span>';
    } else {
        hostLine = sharedHost.reason || "No shared hosting signal";
    }

    return '<div class="detail-section">' +
        '<h3>Infrastructure Clustering</h3>' +
        row("Shares certificate with other domains", certLine) +
        row("Shared hosting signal", hostLine) +
        '</div>';
}

function renderSubdomainSection(subEnum) {
    if (!subEnum || subEnum.status === "skipped") {
        return '<div class="detail-section">' +
            '<h3>Live Subdomains Found</h3>' +
            row("Status", "Not run") +
            '</div>';
    }

    var subfinderStatus = subEnum.subfinder ? subEnum.subfinder.status : undefined;

    if (subfinderStatus === "tool_not_found") {
        return '<div class="detail-section">' +
            '<h3>Live Subdomains Found</h3>' +
            row("Status", '<span style="color:#f59e0b">Subfinder not installed</span>') +
            '</div>';
    }

    var aliveList = (subEnum.alive_check && subEnum.alive_check.alive) ? subEnum.alive_check.alive : [];
    var resolvedCount = (subEnum.dns_validation && subEnum.dns_validation.resolved_count !== undefined) ?
        subEnum.dns_validation.resolved_count : 0;
    var discoveredCount = (subEnum.subfinder && subEnum.subfinder.subdomain_count !== undefined) ?
        subEnum.subfinder.subdomain_count : 0;

    var html = '<div class="detail-section">' +
        '<h3>Live Subdomains Found</h3>' +
        row("Subdomains discovered", discoveredCount) +
        row("Subdomains resolving (DNS)", resolvedCount) +
        row("Subdomains alive (HTTP)", aliveList.length) +
        '</div>';

    if (aliveList.length > 0) {
        html += '<div class="detail-section">';
        var showCount = 15;
        for (var i = 0; i < Math.min(showCount, aliveList.length); i++) {
            var a = aliveList[i];
            var statusCode = (a.status_code !== undefined && a.status_code !== null) ? a.status_code : "?";
            var title = a.title || "no title";
            var fullUrl = a.url || "";
            var displayUrl = truncateUrl(fullUrl, 60);

            html += '<div class="detail-row" title="' + fullUrl.replace(/"/g, "&quot;") + '">' +
                '<span class="label">' + displayUrl + '</span>' +
                '<span class="value">' + statusCode + ' — ' + title + '</span>' +
                '</div>';
        }
        if (aliveList.length > showCount) {
            html += '<div class="detail-row"><span class="label"></span><span class="value" style="color:#64748b">…and ' + (aliveList.length - showCount) + ' more alive hosts</span></div>';
        }
        html += '</div>';
    }

    return html;
}

function renderFaviconSection(faviconComp) {
    var groups = (faviconComp && faviconComp.duplicate_groups) ? faviconComp.duplicate_groups : [];

    if (groups.length === 0) {
        return "";
    }

    var html = '<div class="detail-section"><h3>Shared Favicon Groups</h3>';

    for (var i = 0; i < groups.length; i++) {
        var g = groups[i];
        var hosts = g.shared_by || [];
        var showCount = 5;

        html += '<div class="detail-row"><span class="label">Hash ' + g.favicon_hash + '</span><span class="value">' + hosts.length + ' domains</span></div>';

        for (var j = 0; j < Math.min(showCount, hosts.length); j++) {
            html += '<div class="detail-row"><span class="label"></span><span class="value">• ' + hosts[j] + '</span></div>';
        }

        if (hosts.length > showCount) {
            html += '<div class="detail-row"><span class="label"></span><span class="value" style="color:#64748b">…and ' + (hosts.length - showCount) + ' more</span></div>';
        }
    }

    html += '</div>';
    return html;
}

function renderThreatIntel(ti) {
    if (!ti) {
        return '<div class="detail-section"><p>No investigation data available for this result.</p></div>';
    }

    var whois = ti.whois || {};
    var ssl = ti.ssl || {};
    var ip = ti.ip || {};
    var sb = ti.safe_browsing || {};
    var vt = ti.virustotal || {};
    var cluster = ti.infrastructure_cluster || {};
    var cert = cluster.certificate_transparency || {};
    var sharedHost = cluster.shared_hosting || {};
    var subEnum = cluster.subdomain_discovery || {};

    var html = "";

    html += '<div class="detail-section"><h3>WHOIS</h3>';
    if (whois.error) {
        html += row("Status", "Lookup failed (" + whois.error + ")");
    } else {
        html += row("Registrar", whois.registrar);
        html += row("Created", whois.creation_date);
        html += row("Domain age (days)", whois.age_days);
        html += row("Privacy protected", whois.privacy_protected ? "Yes" : "No");
    }
    html += '</div>';

    html += '<div class="detail-section"><h3>SSL Certificate</h3>';
    if (ssl.error) {
        html += row("Status", "Could not connect (" + ssl.error + ")");
    } else {
        html += row("Issuer", ssl.issuer);
        html += row("Valid from", ssl.valid_from);
        html += row("Valid until", ssl.valid_until);
    }
    html += '</div>';

    html += '<div class="detail-section"><h3>Hosting</h3>';
    html += row("IP address", ip.ip);
    if (ip.is_private) {
        html += row("Note", "Private/reserved IP — hosting lookup skipped");
    } else {
        html += row("Hosting provider", ip.hosting);
        html += row("Country", ip.country);
        html += row("ASN", ip.asn);
    }
    html += '</div>';

    html += '<div class="detail-section"><h3>Reputation</h3>';
    var sbLine = sb.flagged ?
        '<span class="badge-flag">FLAGGED</span>' :
        (sb.status === "ok" ? '<span class="badge-ok">Clean</span>' : (sb.status || "unknown"));
    html += row("Google Safe Browsing", sbLine);

    var vtLine = (vt.malicious !== undefined) ?
        (vt.malicious + " malicious / " + (vt.harmless !== undefined ? vt.harmless : 0) + " harmless") :
        (vt.status === "submitted" ? "Not previously scanned — just submitted to VirusTotal" : (vt.status || "unknown"));
    html += row("VirusTotal", vtLine);
    html += '</div>';

    html += renderClusterSection(cert, sharedHost);
    html += renderSubdomainSection(subEnum);
    html += renderFaviconSection(cluster.favicon_comparison);

    html += '<div class="disclaimer-note">' + (ti.disclaimer || "") + '</div>';

    return html;
}

function loadInvestigation() {
    if (!decodedUrl) {
        detailsContent.innerHTML = "<p>No URL context available.</p>";
        return;
    }

    detailsContent.innerHTML = "<p>Running full investigation (WHOIS, certificate transparency, reverse IP)&hellip; this can take up to a minute.</p>";

    chrome.runtime.sendMessage({ type: "PG_INVESTIGATE", url: decodedUrl },
        function(response) {
            if (chrome.runtime.lastError) {
                detailsContent.innerHTML = "<p>Could not reach the extension background service. Try reopening this page.</p>";
                return;
            }
            if (!response || !response.ok) {
                var errMsg = (response && response.error) || "Unknown error";
                detailsContent.innerHTML = "<p>Investigation failed: " + errMsg + "</p>";
                return;
            }
            detailsContent.innerHTML = renderThreatIntel(response.data);
        }
    );
}

function load() {
    if (!decodedUrl) {
        riskBox.textContent = "Risk Score: Unknown";
        detailsContent.innerHTML = "<p>No URL context available.</p>";
        return;
    }

    applyLevelStyling(level, score);
    detailsContent.innerHTML = "<p>Click to run a full investigation (WHOIS, certificate transparency, reverse IP, subdomains).</p>";
}

load();