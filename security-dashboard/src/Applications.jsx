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

      const response = await fetch(
        API + "/applications",
        {
          headers: {
            Authorization: "Bearer " + token,
          },
        }
      );

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));

        throw new Error(
          data.error || "Failed to load applications"
        );
      }

      const data = await response.json();

      setApplications(
        Array.isArray(data) ? data : []
      );
    } catch (err) {
      console.error(
        "Applications load error:",
        err
      );

      setError(
        err.message ||
          "Failed to load application inventory"
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadApplications();

    const interval = setInterval(
      loadApplications,
      30000
    );

    return () => clearInterval(interval);
  }, []);

  const devices = useMemo(() => {
    const values = applications
      .map(function (app) {
        return app.device_id;
      })
      .filter(Boolean);

    return Array.from(new Set(values)).sort();
  }, [applications]);

  const filteredApplications = useMemo(() => {
    const query = search
      .trim()
      .toLowerCase();

    return applications.filter(function (app) {
      const matchesSearch =
        !query ||
        String(
          app.application_name || ""
        )
          .toLowerCase()
          .includes(query) ||
        String(
          app.version || ""
        )
          .toLowerCase()
          .includes(query) ||
        String(
          app.device_id || ""
        )
          .toLowerCase()
          .includes(query) ||
        String(
          app.path || ""
        )
          .toLowerCase()
          .includes(query);

      const matchesDevice =
        deviceFilter === "all" ||
        app.device_id === deviceFilter;

      return (
        matchesSearch &&
        matchesDevice
      );
    });
  }, [
    applications,
    search,
    deviceFilter,
  ]);

  const uniqueApplications = useMemo(() => {
    return new Set(
      applications
        .map(function (app) {
          return app.application_name;
        })
        .filter(Boolean)
    ).size;
  }, [applications]);

  const uniqueDevices = useMemo(() => {
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

  function closeDetails() {
    setSelectedApplication(null);
  }

  return (
    <div className="applications-page">

      <div className="applications-header">
        <div>
          <div className="applications-kicker">
            SOFTWARE MONITORING
          </div>

          <h1>
            Application Inventory
          </h1>

          <p>
            Software detected on company
            computers by the Sentinel agent.
          </p>
        </div>

        <button
          className="applications-refresh"
          onClick={loadApplications}
        >
          Refresh
        </button>
      </div>

      <div className="applications-stats">

        <div className="application-stat-card">
          <span>Total Records</span>
          <strong>
            {applications.length}
          </strong>
        </div>

        <div className="application-stat-card">
          <span>Unique Applications</span>
          <strong>
            {uniqueApplications}
          </strong>
        </div>

        <div className="application-stat-card">
          <span>Devices Reporting</span>
          <strong>
            {uniqueDevices}
          </strong>
        </div>

        <div className="application-stat-card">
          <span>Showing</span>
          <strong>
            {filteredApplications.length}
          </strong>
        </div>

      </div>

      <div className="applications-panel">

        <div className="applications-controls">

          <div className="applications-search">
            <input
              type="text"
              placeholder="Search application, version, device or path..."
              value={search}
              onChange={function (event) {
                setSearch(event.target.value);
              }}
            />
          </div>

          <div className="applications-filter">
            <select
              value={deviceFilter}
              onChange={function (event) {
                setDeviceFilter(event.target.value);
              }}
            >
              <option value="all">
                All Devices
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

        {loading ? (
          <div className="applications-empty">
            Loading application inventory...
          </div>
        ) : error ? (
          <div className="applications-error">
            <strong>
              Unable to load applications
            </strong>

            <p>{error}</p>

            <button
              onClick={loadApplications}
            >
              Try Again
            </button>
          </div>
        ) : filteredApplications.length === 0 ? (
          <div className="applications-empty">
            <strong>
              No applications found
            </strong>

            <p>
              The Sentinel agent has not
              reported matching application
              records yet.
            </p>
          </div>
        ) : (
          <div className="applications-table-wrapper">

            <table className="applications-table">

              <thead>
                <tr>
                  <th>#</th>
                  <th>Application</th>
                  <th>Version</th>
                  <th>Device</th>
                  <th>Installation Path</th>
                  <th>Detected</th>
                </tr>
              </thead>

              <tbody>

                {filteredApplications.map(
                  function (app, index) {
                    return (
                      <tr
                        key={
                          app.id ||
                          app.device_id +
                            "-" +
                            app.application_name +
                            "-" +
                            index
                        }
                        onClick={function () {
                          setSelectedApplication(
                            app
                          );
                        }}
                        className="application-row"
                      >

                        <td>
                          {index + 1}
                        </td>

                        <td>
                          <div className="application-name-cell">
                            <strong>
                              {
                                app.application_name ||
                                "Unknown Application"
                              }
                            </strong>

                            <span>
                              Monitored
                            </span>
                          </div>
                        </td>

                        <td>
                          {app.version ||
                            "Unknown"}
                        </td>

                        <td>
                          {app.device_id ||
                            "Unknown"}
                        </td>

                        <td>
                          <span className="application-path">
                            {app.path ||
                              "Unknown"}
                          </span>
                        </td>

                        <td>
                          {formatDate(
                            app.detected_at
                          )}
                        </td>

                      </tr>
                    );
                  }
                )}

              </tbody>

            </table>

          </div>
        )}

      </div>

      {selectedApplication && (
        <div
          className="application-modal-overlay"
          onClick={function (event) {
            if (
              event.target ===
              event.currentTarget
            ) {
              closeDetails();
            }
          }}
        >

          <div className="application-modal">

            <div className="application-modal-header">

              <div>
                <div className="applications-kicker">
                  APPLICATION DETAILS
                </div>

                <h2>
                  {
                    selectedApplication.application_name ||
                    "Unknown Application"
                  }
                </h2>
              </div>

              <button
                className="application-modal-close"
                onClick={closeDetails}
                aria-label="Close"
              >
                ×
              </button>

            </div>

            <div className="application-modal-status">
              <span className="application-status-dot" />

              MONITORED
            </div>

            <div className="application-details-grid">

              <div className="application-detail-item">
                <span>Application</span>

                <strong>
                  {
                    selectedApplication.application_name ||
                    "Unknown"
                  }
                </strong>
              </div>

              <div className="application-detail-item">
                <span>Version</span>

                <strong>
                  {
                    selectedApplication.version ||
                    "Unknown"
                  }
                </strong>
              </div>

              <div className="application-detail-item">
                <span>Device</span>

                <strong>
                  {
                    selectedApplication.device_id ||
                    "Unknown"
                  }
                </strong>
              </div>

              <div className="application-detail-item">
                <span>Record ID</span>

                <strong>
                  {
                    selectedApplication.id ||
                    "Unknown"
                  }
                </strong>
              </div>

              <div className="application-detail-item application-detail-full">
                <span>Installation Path</span>

                <strong className="application-detail-path">
                  {
                    selectedApplication.path ||
                    "Unknown"
                  }
                </strong>
              </div>

              <div className="application-detail-item">
                <span>Detected</span>

                <strong>
                  {formatDate(
                    selectedApplication.detected_at
                  )}
                </strong>
              </div>

            </div>

            <div className="application-modal-footer">
              Application inventory is collected
              automatically by the Sentinel agent.
            </div>

          </div>

        </div>
      )}

    </div>
  );
}

export default Applications;
