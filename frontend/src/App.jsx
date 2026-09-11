
import { useState } from "react";
import "./App.css";

// Render backend URL
const API_URL =
  "https://phishing-detection-3-c40k.onrender.com/check-url";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [history, setHistory] = useState([]);

  // ================= SECURITY ALERT SOUND =================

  const playAlert = () => {
    try {
      const AudioContext =
        window.AudioContext || window.webkitAudioContext;

      if (!AudioContext) return;

      const audioContext = new AudioContext();

      const playTone = (frequency, startTime, duration) => {
        const oscillator = audioContext.createOscillator();
        const gain = audioContext.createGain();

        oscillator.type = "square";

        oscillator.frequency.setValueAtTime(
          frequency,
          startTime
        );

        gain.gain.setValueAtTime(0.001, startTime);

        gain.gain.exponentialRampToValueAtTime(
          0.18,
          startTime + 0.02
        );

        gain.gain.exponentialRampToValueAtTime(
          0.001,
          startTime + duration
        );

        oscillator.connect(gain);
        gain.connect(audioContext.destination);

        oscillator.start(startTime);
        oscillator.stop(startTime + duration);
      };

      const now = audioContext.currentTime;

      playTone(900, now, 0.18);
      playTone(650, now + 0.23, 0.28);

      setTimeout(() => {
        audioContext.close();
      }, 700);
    } catch (error) {
      console.log("Security alert sound unavailable");
    }
  };

  // ================= URL SCANNER =================

  const checkURL = async (urlToCheck = url) => {
    let cleanURL = urlToCheck.trim();

    if (!cleanURL) {
      setMessage("Please enter a URL first.");
      return;
    }

    /*
      Automatically add HTTPS if the user enters:

      google.com
      www.google.com

      This makes the scanner easier to use.
    */
    if (
      !cleanURL.startsWith("http://") &&
      !cleanURL.startsWith("https://")
    ) {
      cleanURL = "https://" + cleanURL;
      setUrl(cleanURL);
    }

    setLoading(true);
    setMessage("");
    setResult(null);

    try {
      const response = await fetch(API_URL, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify({
          url: cleanURL,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || "Unable to analyze this URL."
        );
      }

      setResult(data);

      // Add scan to history
      const newScan = {
        url: cleanURL,
        risk_level: data.risk_level,
        threat_score: data.threat_score,
        time: new Date().toLocaleTimeString(),
      };

      setHistory((previousHistory) => {
        return [newScan, ...previousHistory].slice(0, 5);
      });

      // Play warning only for genuinely high-risk results
      if (
        data.risk_level === "High" ||
        data.risk_level === "Critical"
      ) {
        playAlert();
      }
    } catch (error) {
      console.error("Scan error:", error);

      setMessage(
        error.message ||
          "Could not connect to the backend. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  // ================= RISK HELPERS =================

  const getRiskClass = (risk) => {
    if (risk === "Critical" || risk === "High") {
      return "danger";
    }

    if (risk === "Medium") {
      return "warning";
    }

    return "safe";
  };

  const getRiskTitle = (risk) => {
    if (risk === "Critical") {
      return "Critical Threat";
    }

    if (risk === "High") {
      return "High Risk";
    }

    if (risk === "Medium") {
      return "Suspicious";
    }

    return "Likely Safe";
  };

  const getIndicatorIcon = (status) => {
    if (status === "danger") {
      return "✕";
    }

    if (status === "warning") {
      return "!";
    }

    return "✓";
  };

  // ================= CLEAR SCAN =================

  const clearScan = () => {
    setResult(null);
    setUrl("");
    setMessage("");
  };

  // ================= QUICK TESTS =================

  const runGoogleTest = () => {
    const testURL = "https://google.com";
    setUrl(testURL);
    checkURL(testURL);
  };

  const runYoutubeTest = () => {
    const testURL = "https://www.youtube.com/";
    setUrl(testURL);
    checkURL(testURL);
  };

  const runAmazonTest = () => {
    const testURL = "https://www.amazon.in/";
    setUrl(testURL);
    checkURL(testURL);
  };

  const runSuspiciousTest = () => {
    const testURL =
      "http://192.168.1.1/login/verify-account";

    setUrl(testURL);
    checkURL(testURL);
  };

  // ================= UI =================

  return (
    <div className="app">

      {/* ================= NAVBAR ================= */}

      <nav className="navbar">

        <div className="brand">

          <div className="brand-mark">
            P
          </div>

          <div className="brand-text">

            <h2>
              PhishGuard
            </h2>

            <span>
              URL Threat Intelligence
            </span>

          </div>

        </div>

        <div className="nav-status">

          <span className="status-dot"></span>

          <span>
            Scanner Online
          </span>

        </div>

      </nav>

      {/* ================= MAIN ================= */}

      <main>

        {/* ================= HERO ================= */}

        <section className="hero">

          <div className="hero-badge">
            AI-POWERED URL SECURITY
          </div>

          <h1>
            Don't click it.
            <br />

            <span>
              Scan it first.
            </span>
          </h1>

          <p>
            PhishGuard analyzes suspicious URLs
            using machine learning and security
            heuristics to identify potential
            phishing threats.
          </p>

        </section>

        {/* ================= SCANNER ================= */}

        <section className="scanner-card">

          <div className="scanner-header">

            <div>

              <span className="section-label">
                THREAT SCANNER
              </span>

              <h2>
                Scan a URL
              </h2>

              <p>
                Enter any website address to
                analyze its security.
              </p>

            </div>

            <div className="scanner-icon">
              ⌕
            </div>

          </div>

          <div className="input-area">

            <input
              type="text"
              value={url}
              onChange={(event) => {
                setUrl(event.target.value);
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  checkURL();
                }
              }}
              placeholder="https://example.com"
            />

            <button
              className="scan-button"
              onClick={() => checkURL()}
              disabled={loading}
            >
              {loading
                ? "Scanning..."
                : "Scan URL →"}
            </button>

          </div>

          {/* QUICK TESTS */}

          <div className="quick-tests">

            <span>
              Quick tests:
            </span>

            <button onClick={runGoogleTest}>
              Google
            </button>

            <button onClick={runYoutubeTest}>
              YouTube
            </button>

            <button onClick={runAmazonTest}>
              Amazon
            </button>

            <button onClick={runSuspiciousTest}>
              Suspicious URL
            </button>

          </div>

          {message && (
            <div className="error-message">
              {message}
            </div>
          )}

        </section>

        {/* ================= SCANNING ================= */}

        {loading && (
          <section className="scanning-card">

            <div className="scanner-loader"></div>

            <h3>
              Analyzing URL...
            </h3>

            <p>
              Extracting features and checking
              for suspicious patterns.
            </p>

            <div className="scan-steps">

              <span>
                ✓ URL parsing
              </span>

              <span>
                ✓ Feature extraction
              </span>

              <span>
                ◌ ML analysis
              </span>

              <span>
                ◌ Threat assessment
              </span>

            </div>

          </section>
        )}

        {/* ================= RESULT ================= */}

        {result && !loading && (
          <>

            {/* ================= SECURITY ASSESSMENT ================= */}

            <section
              className={`result-section ${getRiskClass(
                result.risk_level
              )}`}
            >

              <div className="result-heading">

                <div>

                  <span className="section-label">
                    SECURITY ASSESSMENT
                  </span>

                  <h2>
                    {getRiskTitle(
                      result.risk_level
                    )}
                  </h2>

                  <p className="scanned-url">
                    {result.url}
                  </p>

                </div>

                <button
                  className="clear-button"
                  onClick={clearScan}
                >
                  New Scan
                </button>

              </div>

              <div className="result-grid">

                {/* SCORE */}

                <div className="score-card">

                  <div
                    className="score-circle"
                    style={{
                      "--score": `${result.threat_score}%`,
                    }}
                  >

                    <div className="score-inner">

                      <strong>
                        {result.threat_score}
                      </strong>

                      <span>
                        / 100
                      </span>

                    </div>

                  </div>

                  <div className="risk-label">
                    {result.risk_level} Risk
                  </div>

                </div>

                {/* ASSESSMENT */}

                <div className="assessment-info">

                  <div className="assessment-boxes">

                    <div className="info-box">

                      <span>
                        ML SIGNAL
                      </span>

                      <strong>
                        {(
                          result.phishing_probability * 100
                        ).toFixed(1)}
                        %
                      </strong>

                      <small>
                        phishing probability
                      </small>

                    </div>

                    <div className="info-box">

                      <span>
                        FINAL RISK
                      </span>

                      <strong>
                        {result.threat_score}
                        /100
                      </strong>

                      <small>
                        combined threat score
                      </small>

                    </div>

                  </div>

                  {/* IMPORTANT:
                      Use backend-generated reasons instead
                      of inventing a generic explanation.
                  */}

                  <p className="explanation">

                    {result.reasons &&
                    result.reasons.length > 0
                      ? result.reasons[0]
                      : "The URL was analyzed using machine-learning and security indicators."}

                  </p>

                  <div className="analysis-note">

                    <strong>
                      How the score works:
                    </strong>{" "}

                    PhishGuard combines the
                    machine-learning signal with
                    URL security heuristics to
                    produce the final risk score.

                  </div>

                </div>

              </div>

            </section>

            {/* ================= INDICATORS ================= */}

            <section className="indicators-section">

              <div className="section-heading">

                <div>

                  <span className="section-label">
                    SECURITY CHECKS
                  </span>

                  <h2>
                    Detection Indicators
                  </h2>

                </div>

                <span className="check-count">

                  {result.indicators
                    ? result.indicators.length
                    : 0}{" "}

                  checks

                </span>

              </div>

              <div className="indicator-grid">

                {result.indicators &&
                  result.indicators.map(
                    (indicator, index) => (

                      <div
                        className={`indicator-card ${indicator.status}`}
                        key={index}
                      >

                        <div className="indicator-icon">

                          {getIndicatorIcon(
                            indicator.status
                          )}

                        </div>

                        <div>

                          <h3>
                            {indicator.name}
                          </h3>

                          <p>
                            {indicator.message}
                          </p>

                        </div>

                      </div>

                    )
                  )}

              </div>

            </section>

            {/* ================= REASONS ================= */}

            <section className="reasons-section">

              <div className="section-heading">

                <div>

                  <span className="section-label">
                    EXPLAINABLE AI
                  </span>

                  <h2>
                    Why this result?
                  </h2>

                </div>

              </div>

              <div className="reasons-list">

                {result.reasons &&
                  result.reasons.map(
                    (reason, index) => (

                      <div
                        className="reason-item"
                        key={index}
                      >

                        <span>
                          {index + 1}
                        </span>

                        <p>
                          {reason}
                        </p>

                      </div>

                    )
                  )}

              </div>

            </section>

            {/* ================= RECOMMENDATION ================= */}

            {result.recommendation && (
              <section className="reasons-section">

                <div className="section-heading">

                  <div>

                    <span className="section-label">
                      SECURITY RECOMMENDATION
                    </span>

                    <h2>
                      What should you do?
                    </h2>

                  </div>

                </div>

                <div className="reason-item">

                  <span>
                    !
                  </span>

                  <p>
                    {result.recommendation}
                  </p>

                </div>

              </section>
            )}

            {/* ================= FORENSICS ================= */}

            <section className="forensics-section">

              <div className="section-heading">

                <div>

                  <span className="section-label">
                    URL FORENSICS
                  </span>

                  <h2>
                    Technical Analysis
                  </h2>

                </div>

              </div>

              <div className="feature-grid">

                <div className="feature-card">

                  <span>
                    URL LENGTH
                  </span>

                  <strong>
                    {result.features?.url_length ?? "-"}
                  </strong>

                </div>

                <div className="feature-card">

                  <span>
                    DOMAIN LENGTH
                  </span>

                  <strong>
                    {result.features?.domain_length ?? "-"}
                  </strong>

                </div>

                <div className="feature-card">

                  <span>
                    SUBDOMAINS
                  </span>

                  <strong>
                    {result.features?.num_subdomains ?? "-"}
                  </strong>

                </div>

                <div className="feature-card">

                  <span>
                    DIGITS
                  </span>

                  <strong>
                    {result.features?.num_digits ?? "-"}
                  </strong>

                </div>

                <div className="feature-card">

                  <span>
                    HYPHENS
                  </span>

                  <strong>
                    {result.features?.num_hyphens ?? "-"}
                  </strong>

                </div>

                <div className="feature-card">

                  <span>
                    ENTROPY
                  </span>

                  <strong>
                    {result.features?.url_entropy ?? "-"}
                  </strong>

                </div>

                <div className="feature-card">

                  <span>
                    HTTPS
                  </span>

                  <strong>
                    {result.features?.has_https === 1
                      ? "YES"
                      : "NO"}
                  </strong>

                </div>

                <div className="feature-card">

                  <span>
                    IP ADDRESS
                  </span>

                  <strong>
                    {result.features?.has_ip === 1
                      ? "YES"
                      : "NO"}
                  </strong>

                </div>

              </div>

            </section>

          </>
        )}

        {/* ================= ARCHITECTURE ================= */}

        <section className="architecture-section">

          <div className="section-heading">

            <div>

              <span className="section-label">
                UNDER THE HOOD
              </span>

              <h2>
                How PhishGuard works
              </h2>

              <p>
                A hybrid detection pipeline combines
                machine learning with security rules
                to produce an explainable result.
              </p>

            </div>

          </div>

          <div className="architecture-flow">

            <div className="architecture-step">

              <span>
                01
              </span>

              <strong>
                URL
              </strong>

              <p>
                User submits a suspicious link.
              </p>

            </div>

            <div className="flow-arrow">
              →
            </div>

            <div className="architecture-step">

              <span>
                02
              </span>

              <strong>
                FEATURES
              </strong>

              <p>
                URL structure is analyzed.
              </p>

            </div>

            <div className="flow-arrow">
              →
            </div>

            <div className="architecture-step">

              <span>
                03
              </span>

              <strong>
                ML MODEL
              </strong>

              <p>
                Machine learning detects patterns.
              </p>

            </div>

            <div className="flow-arrow">
              →
            </div>

            <div className="architecture-step">

              <span>
                04
              </span>

              <strong>
                HEURISTICS
              </strong>

              <p>
                Security rules refine the result.
              </p>

            </div>

            <div className="flow-arrow">
              →
            </div>

            <div className="architecture-step final-step">

              <span>
                05
              </span>

              <strong>
                VERDICT
              </strong>

              <p>
                Threat score and explanation.
              </p>

            </div>

          </div>

        </section>

        {/* ================= HISTORY ================= */}

        {history.length > 0 && (

          <section className="history-section">

            <div className="section-heading">

              <div>

                <span className="section-label">
                  RECENT ACTIVITY
                </span>

                <h2>
                  Scan History
                </h2>

              </div>

              <span className="check-count">
                {history.length} scans
              </span>

            </div>

            <div className="history-list">

              {history.map(
                (scan, index) => (

                  <div
                    className="history-item"
                    key={`${scan.time}-${index}`}
                  >

                    <div className="history-url">

                      <span className="history-number">
                        {index + 1}
                      </span>

                      <div>

                        <strong>
                          {scan.url}
                        </strong>

                        <small>
                          {scan.time}
                        </small>

                      </div>

                    </div>

                    <div className="history-result">

                      <span
                        className={`history-risk ${getRiskClass(
                          scan.risk_level
                        )}`}
                      >
                        {scan.risk_level}
                      </span>

                      <strong>
                        {scan.threat_score}/100
                      </strong>

                    </div>

                  </div>

                )
              )}

            </div>

          </section>

        )}

      </main>

      {/* ================= FOOTER ================= */}

      <footer>

        <div>

          <strong>
            PhishGuard
          </strong>

          <span>
            AI-assisted phishing detection
          </span>

        </div>

        <span>
          Built with React + Flask + Machine Learning
        </span>

      </footer>

    </div>
  );
}

export default App;

