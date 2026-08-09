"""Manual upload smoke check script.

Kept out of pytest collection by running only when executed directly.
"""

if __name__ == "__main__":
    import requests, csv, json, tempfile, os

    rows = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
    fd, path = tempfile.mkstemp(suffix=".csv", prefix="test_upload_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["a", "b"])
            writer.writeheader()
            writer.writerows(rows)

        url = "http://127.0.0.1:8001/api/upload"
        with open(path, "rb") as fh:
            r = requests.post(url, files={"file": (os.path.basename(path), fh, "text/csv")}, timeout=20)
        print("status", r.status_code)
        try:
            print(json.dumps(r.json(), indent=2))
        except Exception:
            print(r.text)
    finally:
        os.remove(path)
