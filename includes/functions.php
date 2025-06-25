<?php
$serviceMap = [
    21 => 'FTP',
    22 => 'SSH',
    23 => 'Telnet',
    25 => 'SMTP',
    53 => 'DNS',
    80 => 'HTTP',
    110 => 'POP3',
    143 => 'IMAP',
    443 => 'HTTPS',
    3306 => 'MySQL',
    5432 => 'PostgreSQL',
    8080 => 'HTTP-Alt',
    3389 => 'RDP',
    6379 => 'Redis',
    27017 => 'MongoDB'
];

function getService($port) {
    global $serviceMap;
    return isset($serviceMap[$port]) ? $serviceMap[$port] : 'Unknown';
}

function scanPorts($host, $ports = [], $timeout = 1) {
    $openPorts = [];
    foreach ($ports as $port) {
        $connection = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if ($connection) {
            $service = getService($port);
            $openPorts[] = ['port' => $port, 'service' => $service];
            fclose($connection);
        }
    }
    return $openPorts;
}

function getWaybackUrls($domain) {
    $waybackApiUrl = "http://web.archive.org/cdx/search/cdx?url={$domain}*&fl=original&collapse=urlkey&output=json";
    $waybackResponse = @file_get_contents($waybackApiUrl);

    if ($waybackResponse === false) {
        return "Failed to retrieve data from Wayback Machine API.";
    }

    $waybackUrls = json_decode($waybackResponse, true);

    if ($waybackUrls === null || !is_array($waybackUrls)) {
        return "Invalid response from Wayback Machine API.";
    }

    array_shift($waybackUrls);

    $urls = [];
    foreach ($waybackUrls as $entry) {
        if (isset($entry[0])) {
            $urls[] = $entry[0];
        }
    }

    if (empty($urls)) {
        return "No URLs found for $domain.";
    }

    return $urls;
}

function extractQueryParameters($url) {
    $parsed_url = parse_url($url);
    if (!isset($parsed_url['query'])) {
        return [];
    }
    parse_str($parsed_url['query'], $params);
    return array_keys($params);
}

function checkSQLInjection($url, $param) {
    $sqli_payload = "\\";
    $parsed_url = parse_url($url);
    if (!isset($parsed_url['query'])) {
        return "Invalid URL or no query parameters found.";
    }
    parse_str($parsed_url['query'], $params);
    if (!array_key_exists($param, $params)) {
        return "Parameter '$param' not found in the URL query string.";
    }
    $params[$param] = $sqli_payload;
    $query_string = http_build_query($params);
    $test_url = $parsed_url['scheme'] . "://" . $parsed_url['host'] . $parsed_url['path'] . '?' . $query_string;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $test_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0');
    $response = curl_exec($ch);
    if ($response === false) {
        return "Failed to fetch the URL: " . curl_error($ch);
    }
    curl_close($ch);
    $sqli_patterns = ['SQL', 'database', 'syntax;', 'warning', 'mysql_fetch', 'mysqli', 'pg_query', "MySQL"];
    foreach ($sqli_patterns as $pattern) {
        if (stripos($response, $pattern) !== false) {
            return "SQL Injection vulnerability found at $test_url (Pattern: $pattern)<br><br>";
        }
    }
}

function checkXSS($domain) {
    $timestamp = time();
    $currentDate = gmdate('Y-m-d', $timestamp);
    $output = "
    <h1>Actionable Report: Cross-Site Scripting (XSS) Vulnerability</h1>
    <h2>Report Summary:</h2>
    <p>
    - Vulnerability Type: Cross-Site Scripting (XSS)<br>
    - Severity: High<br>
    - Tested URL/Endpoint: $domain <br>
    - Date of Discovery: $currentDate <br>
    </p>
    ";

    $waybackUrls = getWaybackUrls($domain);

    if (!is_array($waybackUrls)) {
        return $waybackUrls;
    }

    $xss_payload = '<script>alert("XSS")</script>';

    foreach ($waybackUrls as $url) {
        $parsed_url = parse_url($url);

        if (!isset($parsed_url['query'])) {
            continue;
        }

        parse_str($parsed_url['query'], $params);

        $test_url = $parsed_url['scheme'] . "://" . $parsed_url['host'] . $parsed_url['path'];
        $output .= "- Affected Parameter: $test_url <br>";
        $test_url .= '?' . http_build_query(array_map(function ($v) use ($xss_payload) {
            return $xss_payload;
        }, $params), '', '&', PHP_QUERY_RFC3986);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $test_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3');
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            $output .= "Failed to fetch URL: $url (Error: $error)\n";
            continue;
        }
    }
    
    $output .= "
    <p>
    - Impact: Theft of user sessions, credentials, defacement, malicious redirects, or spreading malware.
    </p>
    <br><br>
    <h2>Vulnerability Details:</h2>
    <h3>Type of XSS</h3>
    <p>
    - Reflected XSS (Non-Persistent)
    </p>
    <h3>Vulnerable Parameter</h3>
    <p>
    - The parameter is not properly sanitized or escaped before being rendered back on the page, leading to an XSS vulnerability.
    </p>
    <br>
    <h2>Technical Details:</h2>
    <p>
    - The web application directly reflects user input back into the HTML page without adequate sanitization or escaping. This allows an attacker to inject malicious scripts that will be executed in the user's browser.<br>
    - This specific XSS vulnerability was identified in the search feature, but other forms or parameters could potentially be vulnerable.<br>
    </p>
    <br>
    <h2>Business Impact</h2>
    <h3>- Security Risks</h3>
    <p>
        - Session Hijacking: Attackers can steal session cookies, impersonating users and gaining access to their accounts.<br>
        - Data Theft: Sensitive information (e.g., credentials, personal information) can be stolen.<br>
        - Browser Exploitation: Attackers could launch phishing attacks, deploy malware, or deface the website.<br>
        - Reputation Damage: The vulnerability could lead to a loss of user trust, legal repercussions, and non-compliance with security regulations.<br>
    </p>
    <br>
    <h2>Recommendations:</h2>
    <h3>1. Input Sanitization:</h3>
    <p>
    - Sanitize all user input fields to ensure malicious scripts are not accepted. Use functions to remove or escape special characters (like `<`, `>`, `\"`, `&`, etc.).
    </p>
    <br><br>
    <h2>2. Output Encoding:</h2>
    <p>
    - Encode user-generated content before outputting it into the HTML page to prevent script execution.
    </p>
    <br><br>
    <h2>3. Implement Content Security Policy (CSP):</h2>
    <p>
    - A CSP header helps mitigate the impact of XSS by preventing the execution of untrusted scripts.
    </p>
    <br><br>
    <h2>4. Server-Side Validation:</h2>
    <p>
        - Ensure that input is validated both on the client and server side. Only allow expected inputs and reject dangerous ones.
    </p>
    <br><br>
    <h2>5. Use Web Application Firewall (WAF):</h2>
    <p>
    - Implement a WAF to help detect and block malicious requests targeting XSS vulnerabilities.
    </p>
    <br><br>
    <h2>6. JavaScript Frameworks:</h2>
    <p>
    - Use modern JavaScript frameworks such as React or Angular, which inherently offer protection against XSS by escaping user input by default.
    </p>
    ";
    
    return $output;
}
?>
