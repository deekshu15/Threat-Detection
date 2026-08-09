import React from "react";
import type { TrendItem } from "../services/dashboardService";

interface Props {
  data: TrendItem[];
}

export default function ThreatTrend({
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
        Timestamp data is not available for trend analysis.
      </div>
    );
  }

  const maxValue = Math.max(
    ...data.map((item) => item.events)
  );

  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-end",
        gap: 6,
        height: 220,
        overflowX: "auto",
        padding: "20px 5px 5px",
      }}
    >
      {data.map((item) => {
        const height = maxValue
          ? Math.max(
              5,
              (item.events / maxValue) * 170
            )
          : 5;

        return (
          <div
            key={item.date}
            style={{
              minWidth: 28,
              height: "100%",
              display: "flex",
              flexDirection: "column",
              justifyContent: "flex-end",
              alignItems: "center",
              gap: 6,
            }}
            title={`${item.date}: ${item.events} events`}
          >
            <div
              style={{
                color: "#9ca7b5",
                fontSize: 10,
              }}
            >
              {item.events}
            </div>

            <div
              style={{
                width: 20,
                height,
                background: "#536dfe",
                borderRadius: "4px 4px 0 0",
              }}
            />

            <div
              style={{
                color: "#6f7b89",
                fontSize: 9,
                writingMode: "vertical-rl",
                transform: "rotate(180deg)",
              }}
            >
              {item.date}
            </div>
          </div>
        );
      })}
    </div>
  );
}