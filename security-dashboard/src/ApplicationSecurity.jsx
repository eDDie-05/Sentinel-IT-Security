import { useEffect, useMemo, useState } from "react";

const API = "http://localhost:5000/api";

function getToken() {
  return localStorage.getItem("token");
}

function ApplicationSecurity() {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [selectedRecord, setSelectedRecord] = useState(null);

  async function loadSecurityIntelligence() {
    try {
      setError("");

      const token = getToken();

      const response = await fetch(
        API + "/application-security",
        {
          headers: {
            Authorization: "Bearer " + token,
          },
        }
      );

      if (!response.ok) {
        const data = await response.json().catch(
          function () {
            return {};
          }
        );

        throw new Error(
          data.error ||
            "Failed to load application security intelligence"
        );
      }

      const data = await response.json();

      setRecords(
        Array.isArray(data) ? data : []
      );
    } catch (err) {
      console.error(
        "Application security error:",
        err
      );

      setError(
        err.message ||
          "Failed to load application security intelligence"
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(function () {
    loadSecurityIntelligence();

    const interval = setInterval(
      loadSecurityIntelligence,
      30000
    );

    return function () {
      clearInterval(interval);
    };
  }, []);

  const filteredRecords = useMemo(
    function () {
      const query = search
        .trim()
        .toLowerCase();

      return records.filter(
        function (record) {
          const matchesSearch =
            !query ||
            String(
              record.application_name || ""
            )
              .toLowerCase()
              .includes(query) ||
            String(
              record.version_pattern || ""
            )
              .toLowerCase()
              .includes(query) ||
            String(
              record.title || ""
            )
              .toLowerCase()
              .includes(query) ||
            String(
              record.source || ""
            )
              .toLowerCase()
              .includes(query);

          const matchesStatus =
            statusFilter === "ALL" ||
            record.security_status ===
              statusFilter;

          return (
            matchesSearch &&
            matchesStatus
          );
        }
      );
    },
    [records, search, statusFilter]
  );

  const statusCounts = useMemo(
    function () {
      return {
        total: records.length,

        unknown: records.filter(
          function (record) {
            return (
              record.security_status ===
              "UNKNOWN"
            );
          }
        ).length,

        monitored: records.filter(
          function (record) {
            return (
              record.security_status ===
              "MONITORED"
            );
          }
        ).length,

        review: records.filter(
          function (record) {
            return (
              record.security_status ===
              "REVIEW"
            );
          }
        ).length,

        vulnerable: records.filter(
          function (record) {
            return (
              record.security_status ===
              "VULNERABLE"
            );
          }
        ).length,

        secure: records.filter(
          function (record) {
            return (
              record.security_status ===
              "SECURE"
            );
          }
        ).length,
      };
    },
    [records]
  );

  function statusClass(status) {
    return String(
      status || "UNKNOWN"
    )
      .toLowerCase()
      .replace(/\s+/g, "-");
  }

  function formatDate(value) {
    if (!value) {
      return "Unknown";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return "Unknown";
    }

    return date.toLocaleString();
  }

  function getInitials(name) {
    if (!name) {
      return "APP";
    }

    const words = String(name)
      .trim()
      .split(/\s+/)
      .filter(Boolean);

    if (words.length === 1) {
      return words[0]
        .substring(0, 3)
        .toUpperCase();
    }

    return (
      words[0].substring(0, 1) +
      words[1].substring(0, 1)
    ).toUpperCase();
  }

  return (
    <div className="sentinel-security-page">

      <section className="security-hero">

        <div>

          <div className="security-eyebrow">
            <span className="security-pulse" />
            SENTINEL THREAT INTELLIGENCE
          </div>

          <h1>
            Application Security
          </h1>

          <p>
            Security intelligence and verified
            software risk information.
          </p>

        </div>

        <button
          className="security-refresh"
          onClick={
            loadSecurityIntelligence
          }
        >
          <span>↻</span>
          Refresh Intelligence
        </button>

      </section>

      <section className="security-overview">

        <div className="security-stat security-stat-main">

          <div className="security-stat-symbol">
            ◈
          </div>

          <div>
            <span>
              INTELLIGENCE RECORDS
            </span>

            <strong>
              {statusCounts.total}
            </strong>

            <small>
              Security knowledge base
            </small>
          </div>

        </div>

        <div className="security-stat">

          <div className="security-stat-symbol unknown-symbol">
            ?
          </div>

          <div>
            <span>UNKNOWN</span>
            <strong>
              {statusCounts.unknown}
            </strong>
            <small>Requires intelligence</small>
          </div>

        </div>

        <div className="security-stat">

          <div className="security-stat-symbol review-symbol">
            !
          </div>

          <div>
            <span>REVIEW</span>
            <strong>
              {statusCounts.review}
            </strong>
            <small>Needs assessment</small>
          </div>

        </div>

        <div className="security-stat">

          <div className="security-stat-symbol vulnerable-symbol">
            ×
          </div>

          <div>
            <span>VULNERABLE</span>
            <strong>
              {statusCounts.vulnerable}
            </strong>
            <small>Verified findings</small>
          </div>

        </div>

      </section>

      <section className="security-workspace">

        <div className="security-toolbar">

          <div className="security-search">

            <span>⌕</span>

            <input
              type="text"
              placeholder="Search security intelligence..."
              value={search}
              onChange={function (event) {
                setSearch(
                  event.target.value
                );
              }}
            />

            {search && (
              <button
                onClick={function () {
                  setSearch("");
                }}
              >
                ×
              </button>
            )}

          </div>

          <div className="security-filter">

            <span>STATUS</span>

            <select
              value={statusFilter}
              onChange={function (event) {
                setStatusFilter(
                  event.target.value
                );
              }}
            >
              <option value="ALL">
                All intelligence
              </option>

              <option value="UNKNOWN">
                Unknown
              </option>

              <option value="MONITORED">
                Monitored
              </option>

              <option value="REVIEW">
                Review
              </option>

              <option value="VULNERABLE">
                Vulnerable
              </option>

              <option value="SECURE">
                Secure
              </option>
            </select>

          </div>

        </div>

        <div className="security-table-header">

          <div>
            SECURITY INTELLIGENCE
          </div>

          <div>
            {filteredRecords.length} RECORDS
          </div>

        </div>

        {loading ? (
          <div className="security-state">

            <div className="state-spinner" />

            <strong>
              Loading security intelligence
            </strong>

            <span>
              Synchronizing the Sentinel security
              knowledge base...
            </span>

          </div>
        ) : error ? (
          <div className="security-state security-error">

            <div className="security-error-icon">
              !
            </div>

            <strong>
              Intelligence service unavailable
            </strong>

            <span>{error}</span>

            <button
              onClick={
                loadSecurityIntelligence
              }
            >
              Retry
            </button>

          </div>
        ) : filteredRecords.length === 0 ? (
          <div className="security-state">

            <div className="security-empty-icon">
              ◌
            </div>

            <strong>
              No intelligence records
            </strong>

            <span>
              No records match the current
              search and status filters.
            </span>

          </div>
        ) : (
          <div className="security-list">

            {filteredRecords.map(
              function (record) {
                const status =
                  record.security_status ||
                  "UNKNOWN";

                const severity =
                  record.severity ||
                  "INFO";

                return (
                  <div
                    className="security-row"
                    key={record.id}
                    onClick={function () {
                      setSelectedRecord(
                        record
                      );
                    }}
                  >

                    <div className="security-app">

                      <div className="security-app-avatar">
                        {getInitials(
                          record.application_name
                        )}
                      </div>

                      <div>

                        <strong>
                          {
                            record.application_name ||
                            "Unknown Application"
                          }
                        </strong>

                        <span>
                          {
                            record.version_pattern ||
                            "All versions"
                          }
                        </span>

                      </div>

                    </div>

                    <div className="security-status-column">

                      <span className="security-column-label">
                        STATUS
                      </span>

                      <span
                        className={
                          "intel-status " +
                          statusClass(status)
                        }
                      >
                        <span />
                        {status}
                      </span>

                    </div>

                    <div className="security-severity-column">

                      <span className="security-column-label">
                        SEVERITY
                      </span>

                      <span
                        className={
                          "intel-severity " +
                          String(
                            severity
                          ).toLowerCase()
                        }
                      >
                        {severity}
                      </span>

                    </div>

                    <div className="security-title-column">

                      <span className="security-column-label">
                        INTELLIGENCE
                      </span>

                      <strong>
                        {
                          record.title ||
                          "No intelligence title"
                        }
                      </strong>

                    </div>

                    <div className="security-source-column">

                      <span className="security-column-label">
                        SOURCE
                      </span>

                      <strong>
                        {
                          record.source ||
                          "Not specified"
                        }
                      </strong>

                    </div>

                    <div className="security-row-arrow">
                      →
                    </div>

                  </div>
                );
              }
            )}

          </div>
        )}

      </section>

      <div className="security-disclaimer">

        <span>i</span>

        <div>
          <strong>
            Intelligence integrity
          </strong>

          <p>
            Sentinel only displays application
            security findings that have been
            explicitly recorded in the security
            intelligence database. Unknown does not
            mean vulnerable.
          </p>
        </div>

      </div>

      {selectedRecord && (
        <div
          className="security-modal-backdrop"
          onClick={function (event) {
            if (
              event.target ===
              event.currentTarget
            ) {
              setSelectedRecord(null);
            }
          }}
        >

          <div className="security-details-panel">

            <div className="security-details-top">

              <div className="security-details-brand">

                <div className="security-details-avatar">
                  {getInitials(
                    selectedRecord.application_name
                  )}
                </div>

                <div>
                  <span>
                    SECURITY INTELLIGENCE RECORD
                  </span>

                  <h2>
                    {
                      selectedRecord.application_name ||
                      "Unknown Application"
                    }
                  </h2>
                </div>

              </div>

              <button
                className="security-details-close"
                onClick={function () {
                  setSelectedRecord(null);
                }}
              >
                ×
              </button>

            </div>

            <div
              className={
                "security-details-status " +
                statusClass(
                  selectedRecord.security_status
                )
              }
            >
              <span />
              {
                selectedRecord.security_status ||
                "UNKNOWN"
              }
            </div>

            <div className="security-details-grid">

              <div>
                <span>VERSION PATTERN</span>

                <strong>
                  {
                    selectedRecord.version_pattern ||
                    "All versions"
                  }
                </strong>
              </div>

              <div>
                <span>SEVERITY</span>

                <strong>
                  {
                    selectedRecord.severity ||
                    "INFO"
                  }
                </strong>
              </div>

              <div>
                <span>RECORD ID</span>

                <strong>
                  #{selectedRecord.id}
                </strong>
              </div>

              <div>
                <span>UPDATED</span>

                <strong>
                  {formatDate(
                    selectedRecord.updated_at
                  )}
                </strong>
              </div>

              <div className="security-detail-full">

                <span>TITLE</span>

                <strong>
                  {
                    selectedRecord.title ||
                    "No title"
                  }
                </strong>

              </div>

              <div className="security-detail-full">

                <span>DESCRIPTION</span>

                <p>
                  {
                    selectedRecord.description ||
                    "No description has been recorded."
                  }
                </p>

              </div>

              <div className="security-detail-full">

                <span>SOURCE</span>

                <strong>
                  {
                    selectedRecord.source ||
                    "Not specified"
                  }
                </strong>

              </div>

              {selectedRecord.source_reference && (
                <div className="security-detail-full">

                  <span>SOURCE REFERENCE</span>

                  <strong className="security-source-reference">
                    {
                      selectedRecord.source_reference
                    }
                  </strong>

                </div>
              )}

            </div>

            <div className="security-details-footer">
              Security intelligence is stored and
              maintained separately from application
              inventory data.
            </div>

          </div>

        </div>
      )}

    </div>
  );
}

export default ApplicationSecurity;