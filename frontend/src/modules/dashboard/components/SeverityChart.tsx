import React from "react";
import type { DistributionItem } from "../services/dashboardService";

interface Props {
  data: DistributionItem[];
}

export default function SeverityChart({
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
        Severity information is not available
        in the uploaded dataset.
      </div>
    );
  }

  const total = data.reduce(
    (sum, item) => sum + item.value,
    0
  );

  return (
    <div>
      {data.map((item) => {
        const percentage = total
          ? (item.value / total) * 100
          : 0;

        return (
          <div
            key={item.name}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 12,
              marginBottom: 14,
            }}
          >
            <div
              style={{
                width: 100,
                color: "#dce3eb",
                fontSize: 13,
              }}
            >
              {item.name}
            </div>

            <div
              style={{
                flex: 1,
                height: 8,
                background: "#252c35",
                borderRadius: 8,
              }}
            >
              <div
                style={{
                  width: `${percentage}%`,
                  height: "100%",
                  background: "#536dfe",
                  borderRadius: 8,
                }}
              />
            </div>

            <div
              style={{
                width: 70,
                color: "#9ca7b5",
                fontSize: 12,
                textAlign: "right",
              }}
            >
              {item.value.toLocaleString()}
            </div>
          </div>
        );
      })}
    </div>
  );
}