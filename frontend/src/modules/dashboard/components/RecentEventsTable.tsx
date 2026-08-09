import React from "react";
import type { RecentEvent } from "../services/dashboardService";

interface Props {
  data: RecentEvent[];
}

export default function RecentEventsTable({
  data,
}: Props) {
  if (!data.length) {
    return (
      <div
        style={{
          color: "#8d98a6",
          padding: 20,
        }}
      >
        No recent event records are available.
      </div>
    );
  }

  return (
    <div
      style={{
        overflowX: "auto",
      }}
    >
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
        }}
      >
        <thead>
          <tr>
            {[
              "Timestamp",
              "Source",
              "Destination",
              "Threat",
              "Severity",
            ].map((heading) => (
              <th
                key={heading}
                style={{
                  textAlign: "left",
                  padding: 12,
                  borderBottom:
                    "1px solid #29313d",
                  color: "#8d98a6",
                  fontSize: 12,
                }}
              >
                {heading}
              </th>
            ))}
          </tr>
        </thead>

        <tbody>
          {data.map((event, index) => (
            <tr key={index}>
              <td style={cellStyle}>
                {event.timestamp ?? "N/A"}
              </td>

              <td style={cellStyle}>
                {event.source ?? "N/A"}
              </td>

              <td style={cellStyle}>
                {event.destination ?? "N/A"}
              </td>

              <td style={cellStyle}>
                {event.threat ?? "N/A"}
              </td>

              <td style={cellStyle}>
                {event.severity ?? "N/A"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const cellStyle: React.CSSProperties = {
  padding: 12,
  borderBottom: "1px solid #202731",
  color: "#dce3eb",
  fontSize: 12,
};