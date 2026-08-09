import React from "react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
}

export default function StatCard({
  title,
  value,
  subtitle,
}: StatCardProps) {
  return (
    <div
      style={{
        background: "#171c23",
        border: "1px solid #29313d",
        borderRadius: 16,
        padding: 22,
        minHeight: 120,
      }}
    >
      <div
        style={{
          color: "#9ca7b5",
          fontSize: 14,
          marginBottom: 12,
        }}
      >
        {title}
      </div>

      <div
        style={{
          color: "#ffffff",
          fontSize: 30,
          fontWeight: 700,
        }}
      >
        {value}
      </div>

      {subtitle && (
        <div
          style={{
            color: "#7f8b99",
            fontSize: 12,
            marginTop: 6,
          }}
        >
          {subtitle}
        </div>
      )}
    </div>
  );
}