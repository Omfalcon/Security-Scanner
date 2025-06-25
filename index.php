<?php
ob_start();
require_once 'includes/functions.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $action = $_POST['action'];
    $host = htmlspecialchars(trim($_POST['host']));
    $domain = htmlspecialchars(trim($_POST['domain']));
    $xss = htmlspecialchars(trim($_POST['xss']));

    if ($action === 'port_scan') {
        $timestamp = time();
        $currentDate = gmdate('Y-m-d', $timestamp);
        $output = "
        <h1>Port Scanner Actionable Report</h1>
        <h2>1. Executive Summary</h2>
        <p>Provide an overview of the port scan's purpose, key findings, and risks identified.</p>
        <p>Scan Date: $currentDate </p>
        <p>Target: $host </p>
        <p>Purpose: Assess the network's attack surface by identifying open ports and exposed services. </p>
        <p>Key Findings: </p>";
        
        $portsToScan = array_keys($GLOBALS['serviceMap']);
        $openPorts = scanPorts($host, $portsToScan);

        foreach ($openPorts as $portInfo) {
            $output .= "Port " . $portInfo['port'] . " with potential vulnerabilities<br>";
        }
        
        $output .= "
        <br>
        <h2>2. Vulnerabilities and Remediation</h2>
        <h3>High-Risk Ports</h3>
        <h4>Port 3389 (RDP)</h4>
        <p>Risk: The RDP port is filtered, but exposure could lead to brute-force or man-in-the-middle attacks.
        <br>
        Action:
        <br>
        Ensure multi-factor authentication is enabled.
        <br>
        Restrict RDP access to trusted IPs using a firewall or VPN.
        <br>
        Regularly update RDP service to prevent exploits.
        </p>
        <h4>Port 22 (SSH)</h4>
        <p>
        Risk: Open SSH service exposes the system to password-guessing attacks.
        <br>
        Action:
        <br>
        Disable password-based logins; use SSH keys.
        <br>
        Restrict SSH access to trusted IPs.
        <br>
        Implement tools like Fail2Ban to block malicious login attempts.
        </p>
        <br>

        <h3>Medium-Risk Ports</h3>
        <h4>Port 80 (HTTP)</h4>
        <p>
        Risk: HTTP traffic is unencrypted, making it vulnerable to interception.
        <br>
        Action:
        <br>
        Redirect all HTTP traffic to HTTPS.
        <br>
        Ensure SSL certificates are up to date.
        </p>
        <br>

        <h3>Low-Risk Ports</h3>
        <h4>Port 443 (HTTPS)</h4>
        <p>
        Risk: Generally considered safe, but outdated SSL/TLS configurations could be exploited.
        <br>
        Action:
        <br>
        Regularly audit SSL/TLS settings for weak ciphers or protocols.
        </p>
        <br>
        <br>

        <h2>3. Recommended Actions and Next Steps</h2>
        <p>
        Immediate Actions (Within 24-48 hours)
        <br>
        <br>
        Restrict access to high-risk ports (e.g., RDP, SSH) using a firewall or VPN.
Update outdated services (e.g., OpenSSH, Apache) to their latest versions.
Short-Term Actions (Within 1-2 weeks)
<br>
<br>

Implement network segmentation to isolate critical services.
Enable logging and monitoring for unusual activity on exposed ports.
Set up automated vulnerability scanning for continuous monitoring.
Long-Term Actions (Within 1-3 months)
<br>
<br>

Conduct a full vulnerability assessment, including web applications and database services.
Develop a patch management strategy to keep all services updated.
Train staff on security best practices and hardening techniques.
        </p>";
        
    } elseif ($action === 'wayback_sql_injection') {
        $output = "<h2>Actionable Report: SQL Injection Vulnerability</h2>
        <h2>1. Vulnerability Overview </h2>
        <p>
        SQL Injection is a web security vulnerability that allows attackers to interfere with the queries an application makes to its database. It generally occurs when untrusted data is inserted into a SQL query without proper validation or sanitization, allowing the attacker to execute arbitrary SQL code.
        </p>
        <br>
        <h2>2. Identified Vulnerability</h2>";

        $waybackUrls = getWaybackUrls($domain);
        if (is_string($waybackUrls)) {
            $output .= $waybackUrls;
        } else {
            foreach ($waybackUrls as $waybackUrl) {
                $params = extractQueryParameters($waybackUrl);
                if (!empty($params)) {
                    foreach ($params as $param) {
                        $output .= checkSQLInjection($waybackUrl, $param);
                    }
                }
            }
            $output .= "
            Risk Level: High <br> Type of SQL Injection: <br>- Error-based <br>- Union-based <br>- Blind SQL Injection <br>- Time-based blind SQL Injection<br><br>
                <h2>3. Impact</h2>
                <p>
                - Data Leakage:** Attackers can retrieve sensitive information like usernames, passwords, emails, credit card details, etc.<br>
                - Data Manipulation:** They can modify or delete data in the database.<br>
                - Authentication Bypass:** Attackers can gain unauthorized access to accounts or systems.<br>
                - Remote Code Execution:** In severe cases, attackers can execute system-level commands.<br>
                </p>
                <br>
                <h2>4. Actionable Steps for Mitigation</h2>
                <h3>1. Input Validation:</h3>
                <p>
                - Ensure that all inputs are strictly validated and sanitized.<br>
                - Use input validation libraries to reject harmful SQL queries.<br>
                - Apply whitelisting for specific characters allowed in input fields.<br>
                </p>
                <h3>2. Parameterized Queries (Prepared Statements):</h3>
                <p>- Always use parameterized queries or prepared statements for SQL queries to avoid direct inclusion of user inputs.</p>
                <h3>3. Use Stored Procedures:</h3>
                <p>- Implement stored procedures to handle data transactions, isolating SQL code from user input.</p>
                <h3>4. Least Privilege Principle:</h3>
                <p> - Limit database user privileges to only the required level. For instance, avoid allowing a web application database user to have DROP, DELETE, or UPDATE privileges unless necessary.</p>
                <h3>5. Web Application Firewall (WAF):</h3>
                <p>  - Use a WAF to detect and block SQL injection attempts based on suspicious patterns and anomalies.</p>
                <h3>6. Error Handling:</h3>
                <p>   - Avoid displaying detailed error messages that reveal database structures, query syntax, or vulnerable code paths to the end user.</p>";
        }
    } elseif ($action === 'check_xss') {
        $output = checkXSS($xss);
    }     elseif ($action === 'code_review') {
        $language = $_POST['language'] ?? 'php';
        $code = $_POST['code'] ?? '';
        $lines = explode("\n", $code);
        $output = "<h2>🚨 Rule-Based Code Review Report (" . strtoupper($language) . ")</h2><pre style='white-space: pre-wrap;'>";

        $rules = [];
        if ($language === 'php') {
            $rules = [
                'eval' => ['High', 'Avoid using eval(); consider alternatives like include/switch.', 'https://owasp.org/www-community/attacks/Code_Injection'],
                'exec' => ['High', 'Avoid exec(); may allow command execution.', 'https://owasp.org/www-community/attacks/Command_Injection'],
                'shell_exec' => ['High', 'Avoid shell_exec(); exposes system to attackers.', 'https://owasp.org/www-community/attacks/Command_Injection'],
                'system' => ['High', 'Avoid system(); risk of OS command injection.', 'https://owasp.org/www-community/attacks/Command_Injection'],
                'passthru' => ['High', 'Avoid passthru(); executes system commands directly.', 'https://owasp.org/www-community/attacks/Command_Injection'],
                'mysqli_query' => ['Medium', 'Use prepared statements instead of raw queries.', 'https://owasp.org/www-community/attacks/SQL_Injection'],
                'mysql_query' => ['High', 'Outdated function; use mysqli or PDO with parameter binding.', 'https://owasp.org/www-community/attacks/SQL_Injection'],
                '$_GET' => ['Medium', 'Sanitize user input using filter_input() or htmlspecialchars().', 'https://owasp.org/www-community/attacks/Input_Validation'],
                '$_POST' => ['Medium', 'Validate and sanitize all POST data to avoid injection.', 'https://owasp.org/www-community/attacks/Input_Validation'],
            ];
        } elseif ($language === 'javascript') {
            $rules = [
                'eval' => ['High', 'Avoid eval(); use JSON.parse or Function instead.', 'https://owasp.org/www-community/attacks/eval_javascript'],
                'innerHTML' => ['High', 'Avoid innerHTML; use DOM sanitizers or textContent.', 'https://owasp.org/www-community/attacks/xss'],
                'document.write' => ['High', 'Avoid document.write(); considered unsafe and outdated.', 'https://developer.mozilla.org/en-US/docs/Web/API/Document/write'],
                'setTimeout' => ['Medium', 'Avoid string as argument to setTimeout(); use anonymous function.', 'https://developer.mozilla.org/en-US/docs/Web/API/setTimeout'],
                'localStorage' => ['Medium', 'Do not store sensitive data like tokens in localStorage.', 'https://owasp.org/www-community/attacks/xss'],
            ];
        }

        $flagCount = 0;
        $severityCount = ['High' => 0, 'Medium' => 0, 'Low' => 0];

        foreach ($lines as $num => $line) {
            $lineNumber = $num + 1;
            $lineOut = htmlspecialchars($line);

            foreach ($rules as $keyword => [$severity, $advice, $link]) {
                if (stripos($line, $keyword) !== false) {
                    $output .= "<strong>⚠️ Line $lineNumber [$severity]</strong>: <code>$lineOut</code>\n👉 $advice <a href='$link' target='_blank'>[Learn more]</a>\n\n";
                    $flagCount++;
                    $severityCount[$severity]++;
                    break;
                }
            }
        }

        if ($flagCount === 0) {
            $output .= "✅ No security issues detected in the provided code.";
        } else {
            $output .= "\n🔍 Summary:\n";
            $output .= "- Total Lines Scanned: " . count($lines) . "\n";
            $output .= "- Issues Found: $flagCount\n";
            $output .= "- High Severity: {$severityCount['High']}\n";
            $output .= "- Medium Severity: {$severityCount['Medium']}\n";
        }

        $output .= "</pre>";
    }


}

require_once 'includes/header.php';
?>

<main>
    <div class="card inputcard">
        <h2>INPUT</h2>
        <div class="inputs">
            <form method="post" action="index.php">
                <label for="action">Select Scan:</label>
                <select id="action" name="action">
                    <option value="port_scan">Port Scan</option>
                    <option value="wayback_sql_injection">SQL Injection</option>
                    <option value="check_xss">XSS</option>
                    <option value="code_review">Code Review (PHP)</option>
                </select>

                <div class="in" id="hostInput">
                    <label for="host">Domain (for port scan):</label>
                    <input type="text" id="host" name="host">
                </div>

                <div class="in" id="domainInput">
                    <label for="domain">Domain (for SQL Injection):</label>
                    <input type="text" id="domain" name="domain">
                </div>

                <div class="in" id="xssInput">
                    <label for="xss">Domain (for XSS Injection):</label>
                    <input type="text" id="xss" name="xss">
                </div>
                <div class="in" id="codeInput" style="display: none;">
                    <label for="code">Paste Code:</label>
                    <textarea id="code" name="code" rows="10" style="width:100%;"></textarea>

                    <label for="language">Select Language:</label>
                    <select id="language" name="language">
                        <option value="php">PHP</option>
                        <option value="javascript">JavaScript</option>
                        <!-- add more as needed -->
                    </select>
                </div>

                <input class="submit" type="submit" value="Submit">
            </form>
        </div>
        <tooltip>
            <span id="tooltip1">TOOLTIP : A port scanner is a tool used to probe a computer or network for open
                ports. Open ports are communication endpoints that accept data, which can indicate running services
                or applications. </span>
            <span id="tooltip2">TOOLTIP : SQL Injection is a security vulnerability where an attacker can manipulate
                SQL queries by inserting malicious code through untrusted input. This can lead to unauthorized
                access or manipulation of a database. </span>
            <span id="tooltip3">TOOLTIP : An XSS (Cross-Site Scripting) attack lets an attacker inject malicious
                scripts into a website, which then execute in victims' browsers. This can steal sensitive
                information like cookies or session tokens. </span>
        </tooltip>
        <div class="credit">$-$quare $ecurity</div>
    </div>
    <div class="card outputcard">
        <h2>Report</h2>
        <div class="outputbox" id="outputbox">
            <?php echo $output ?? ''; ?>
        </div>
        <div class="loader" id="loader" style="display: none;">
            <div class="rl-loading-container">
                <div class="rl-loading-thumb rl-loading-thumb-1"></div>
                <div class="rl-loading-thumb rl-loading-thumb-2"></div>
                <div class="rl-loading-thumb rl-loading-thumb-3"></div>
            </div>
        </div>
        <button id="download-pdf">Download PDF</button>
    </div>
</main>
<script>
document.getElementById('action').addEventListener('change', function () {
    const hostInput = document.getElementById('hostInput');
    const domainInput = document.getElementById('domainInput');
    const xssInput = document.getElementById('xssInput');
    const codeInput = document.getElementById('codeInput');

    hostInput.style.display = 'none';
    domainInput.style.display = 'none';
    xssInput.style.display = 'none';
    codeInput.style.display = 'none';

    const selected = this.value;

    if (selected === 'port_scan') {
        hostInput.style.display = 'block';
    } else if (selected === 'wayback_sql_injection') {
        domainInput.style.display = 'block';
    } else if (selected === 'check_xss') {
        xssInput.style.display = 'block';
    } else if (selected === 'code_review') {
        codeInput.style.display = 'block';
    }
});
</script>


<?php
require_once 'includes/footer.php';
ob_end_flush();
?>
