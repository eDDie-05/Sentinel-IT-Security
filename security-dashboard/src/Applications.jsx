import { useEffect, useMemo, useState } from "react";

const API = "http://localhost:5000/api";

function getToken() {
  return localStorage.getItem("token");
}

function Applications() {
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [deviceFilter, setDeviceFilter] = useState("all");
  const [selectedApplication, setSelectedApplication] = useState(null);

  async function loadApplications() {
    try {
      setError("");

      const token = getToken();

      const response = await fetch(API + "/applications", {
        headers: {
          Authorization: "Bearer " + token,
        },
      });

      if (!response.ok) {
        const data = await response.json().catch(function () {
          return {};
        });

        throw new Error(
          data.error || "Failed to load applications"
        );
      }

      const data = await response.json();

      setApplications(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Applications load error:", err);

      setError(
        err.message || "Failed to load application inventory"
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(function () {
    loadApplications();

    const interval = setInterval(
      loadApplications,
      30000
    );

    return function () {
      clearInterval(interval);
    };
  }, []);

  const devices = useMemo(function () {
    const values = applications
      .map(function (app) {
        return app.device_id;
      })
      .filter(Boolean);

    return Array.from(new Set(values)).sort();
  }, [applications]);

  const filteredApplications = useMemo(function () {
    const query = search.trim().toLowerCase();

    return applications.filter(function (app) {
      const matchesSearch =
        !query ||
        String(app.application_name || "")
          .toLowerCase()
          .includes(query) ||
        String(app.version || "")
          .toLowerCase()
          .includes(query) ||
        String(app.device_id || "")
          .toLowerCase()
          .includes(query) ||
        String(app.path || "")
          .toLowerCase()
          .includes(query);

      const matchesDevice =
        deviceFilter === "all" ||
        app.device_id === deviceFilter;

      return matchesSearch && matchesDevice;
    });
  }, [applications, search, deviceFilter]);

  const uniqueApplications = useMemo(function () {
    return new Set(
      applications
        .map(function (app) {
          return app.application_name;
        })
        .filter(Boolean)
    ).size;
  }, [applications]);

  const uniqueDevices = useMemo(function () {
    return new Set(
      applications
        .map(function (app) {
          return app.device_id;
        })
        .filter(Boolean)
    ).size;
  }, [applications]);

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
      return words[0].substring(0, 3).toUpperCase();
    }

    return (
      words[0].substring(0, 1) +
      words[1].substring(0, 1)
    ).toUpperCase();
  }

  function closeDetails() {
    setSelectedApplication(null);
  }

  return (
    <div className="sentinel-inventory-page">

      <section className="inventory-hero">

        <div className="inventory-hero-left">

          <div className="inventory-eyebrow">
            <span className="live-pulse" />
            SENTINEL SOFTWARE INTELLIGENCE
          </div>

          <h1>Application Inventory</h1>

          <p>
            Complete software visibility across monitored
            company endpoints.
          </p>

        </div>

        <button
          className="inventory-refresh"
          onClick={loadApplications}
        >
          <span>↻</span>
          Refresh Inventory
        </button>

      </section>

      <section className="inventory-metrics">

        <div className="inventory-metric">
          <div className="metric-icon metric-icon-blue">
            ▦
          </div>

          <div>
            <span>Total Records</span>
            <strong>{applications.length}</strong>
            <small>Inventory records</small>
          </div>
        </div>

        <div className="inventory-metric">
          <div className="metric-icon metric-icon-purple">
            ◈
          </div>

          <div>
            <span>Applications</span>
            <strong>{uniqueApplications}</strong>
            <small>Unique software</small>
          </div>
        </div>

        <div className="inventory-metric">
          <div className="metric-icon metric-icon-green">
            ◉
          </div>

          <div>
            <span>Endpoints</span>
            <strong>{uniqueDevices}</strong>
            <small>Reporting devices</small>
          </div>
        </div>

        <div className="inventory-metric">
          <div className="metric-icon metric-icon-orange">
            ⌕
          </div>

          <div>
            <span>Visible</span>
            <strong>{filteredApplications.length}</strong>
            <small>Current results</small>
          </div>
        </div>

      </section>

      <section className="inventory-workspace">

        <div className="inventory-toolbar">

          <div className="inventory-search-box">

            <span className="search-symbol">
              ⌕
            </span>

            <input
              type="text"
              placeholder="Search applications, versions, devices or paths..."
              value={search}
              onChange={function (event) {
                setSearch(event.target.value);
              }}
            />

            {search && (
              <button
                className="search-clear"
                onClick={function () {
                  setSearch("");
                }}
              >
                ×
              </button>
            )}

          </div>

          <div className="inventory-filter-wrap">

            <span>DEVICE</span>

            <select
              value={deviceFilter}
              onChange={function (event) {
                setDeviceFilter(event.target.value);
              }}
            >
              <option value="all">
                All endpoints
              </option>

              {devices.map(function (device) {
                return (
                  <option
                    key={device}
                    value={device}
                  >
                    {device}
                  </option>
                );
              })}
            </select>

          </div>

        </div>

        <div className="inventory-table-head">

          <div>
            SOFTWARE CATALOG
          </div>

          <div>
            {filteredApplications.length} RESULTS
          </div>

        </div>

        {loading ? (
          <div className="inventory-state">
            <div className="state-spinner" />
            <strong>Scanning inventory data</strong>
            <span>
              Waiting for Sentinel application records...
            </span>
          </div>
        ) : error ? (
          <div className="inventory-state inventory-error-state">

            <div className="state-error-icon">
              !
            </div>

            <strong>
              Inventory connection failed
            </strong>

            <span>{error}</span>

            <button onClick={loadApplications}>
              Retry Connection
            </button>

          </div>
        ) : filteredApplications.length === 0 ? (
          <div className="inventory-state">

            <div className="state-empty-icon">
              ◌
            </div>

            <strong>
              No software records found
            </strong>

            <span>
              The Sentinel agent has not reported
              matching application records.
            </span>

          </div>
        ) : (
          <div className="inventory-list">

            {filteredApplications.map(
              function (app, index) {
                return (
                  <div
                    className="inventory-row"
                    key={
                      app.id ||
                      app.device_id +
                        "-" +
                        app.application_name +
                        "-" +
                        index
                    }
                    onClick={function () {
                      setSelectedApplication(app);
                    }}
                  >

                    <div className="inventory-number">
                      {String(index + 1).padStart(2, "0")}
                    </div>

                    <div className="inventory-app-identity">

                      <div className="app-avatar">
                        {getInitials(
                          app.application_name
                        )}
                      </div>

                      <div className="app-title-block">

                        <strong>
                          {app.application_name ||
                            "Unknown Application"}
                        </strong>

                        <span>
                          {app.path ||
                            "Installation path unavailable"}
                        </span>

                      </div>

                    </div>

                    <div className="inventory-version">

                      <span className="column-label">
                        VERSION
                      </span>

                      <strong>
                        {app.version ||
                          "Unknown"}
                      </strong>

                    </div>

                    <div className="inventory-device">

                      <span className="column-label">
                        ENDPOINT
                      </span>

                      <div className="endpoint-chip">
                        <span className="endpoint-dot" />
                        {app.device_id ||
                          "Unknown"}
                      </div>

                    </div>

                    <div className="inventory-detected">

                      <span className="column-label">
                        LAST DETECTED
                      </span>

                      <strong>
                        {formatDate(
                          app.detected_at
                        )}
                      </strong>

                    </div>

                    <div className="inventory-arrow">
                      →
                    </div>

                  </div>
                );
              }
            )}

          </div>
        )}

      </section>

      {selectedApplication && (
        <div
          className="inventory-modal-backdrop"
          onClick={function (event) {
            if (
              event.target === event.currentTarget
            ) {
              closeDetails();
            }
          }}
        >

          <div className="inventory-details-panel">

            <div className="details-top">

              <div className="details-brand">
                <div className="details-avatar">
                  {getInitials(
                    selectedApplication.application_name
                  )}
                </div>

                <div>
                  <span>SOFTWARE RECORD</span>

                  <h2>
                    {
                      selectedApplication.application_name ||
                      "Unknown Application"
                    }
                  </h2>
                </div>
              </div>

              <button
                className="details-close"
                onClick={closeDetails}
              >
                ×
              </button>

            </div>

            <div className="details-monitored">
              <span className="live-pulse" />
              MONITORED BY SENTINEL
            </div>

            <div className="details-grid">

              <div className="details-card">
                <span>VERSION</span>
                <strong>
                  {selectedApplication.version ||
                    "Unknown"}
                </strong>
              </div>

              <div className="details-card">
                <span>ENDPOINT</span>
                <strong>
                  {selectedApplication.device_id ||
                    "Unknown"}
                </strong>
              </div>

              <div className="details-card">
                <span>RECORD ID</span>
                <strong>
                  #{selectedApplication.id ||
                    "Unknown"}
                </strong>
              </div>

              <div className="details-card">
                <span>DETECTED</span>
                <strong>
                  {formatDate(
                    selectedApplication.detected_at
                  )}
                </strong>
              </div>

              <div className="details-card details-full">
                <span>INSTALLATION PATH</span>
                <strong className="details-path">
                  {selectedApplication.path ||
                    "Unknown"}
                </strong>
              </div>

            </div>

            <div className="details-footer">
              <span>
                ●
              </span>
              Application inventory is automatically
              collected by the Sentinel endpoint agent.
            </div>

          </div>

        </div>
      )}

    </div>
  );
}

export default Applications;