import asyncio
import os
import json
from playwright.async_api import async_playwright

PROJECT_ROOT = r"C:\Users\HP\Documents\AI-Assisted Threat Detection Dashboard"
IMG_DIR = PROJECT_ROOT

results = {
    "analytics": {},
    "barcode": {},
    "console_errors": [],
    "network_failures": [],
}

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1280, "height": 800})
        page = await context.new_page()

        # Capture console errors
        page.on("console", lambda msg: (
            results["console_errors"].append(f"[console:{msg.type}] {msg.text}") if msg.type in ("error", "warning") else None
        ))
        page.on("pageerror", lambda exc: results["console_errors"].append(f"[pageerror] {exc}"))

        # Track network failures
        page.on("requestfailed", lambda req: results["network_failures"].append(
            f"FAILED: {req.method} {req.url}" + (f" - {req.failure}" if req.failure else "")
        ))

        analytics_api_called = False
        analytics_response = None
        analytics_response_status = None

        async def handle_response(response):
            nonlocal analytics_api_called, analytics_response, analytics_response_status
            if "/api/analytics" in response.url:
                analytics_api_called = True
                analytics_response_status = response.status
                try:
                    analytics_response = await response.json()
                except:
                    analytics_response = "parse error"

        page.on("response", handle_response)

        # ===== STEP 2: Analytics Page =====
        print("=" * 60)
        print("STEP 2: Analytics Page Verification")
        print("=" * 60)

        await page.goto("http://localhost:5173/analytics", wait_until="networkidle")
        await page.wait_for_timeout(3000)

        page_content = await page.content()
        has_title = "Analytics" in page_content
        has_no_blank = len(page_content) > 1000

        print(f"Page loaded (non-blank): {has_no_blank}")
        print(f"Analytics title present: {has_title}")
        print(f"API called: {analytics_api_called}")
        print(f"API status: {analytics_response_status}")

        if analytics_response and isinstance(analytics_response, dict):
            print(f"API success field: {analytics_response.get('success')}")
            print(f"API total_events: {analytics_response.get('total_events')}")
            required_fields = ["total_events", "critical_events", "high_events",
                               "medium_events", "low_events", "average_risk_score",
                               "severity_distribution", "attack_type_frequency", "tool_distribution"]
            all_fields = all(k in analytics_response for k in required_fields)
            print(f"All required fields present: {all_fields}")
            print(f"Hardcoded check - total_events={analytics_response.get('total_events')} (actual DB value)")

            if analytics_response.get("total_events", 0) > 0:
                has_data_display = "Severity Distribution" in page_content or "Attack Type" in page_content
                print(f"Data cards displayed: {has_data_display}")
                results["analytics"]["empty_state"] = False
            else:
                has_empty = "No security events" in page_content
                print(f"Empty state displayed: {has_empty}")
                results["analytics"]["empty_state"] = True

        results["analytics"]["page_loaded"] = has_no_blank
        results["analytics"]["api_called"] = analytics_api_called
        results["analytics"]["api_status"] = analytics_response_status
        results["analytics"]["api_response"] = analytics_response
        results["analytics"]["console_errors_count"] = sum(1 for e in results["console_errors"])

        print(f"Console errors so far: {results['analytics']['console_errors_count']}")

        # ===== STEP 3: Barcode Threat Scanner =====
        print()
        print("=" * 60)
        print("STEP 3: Barcode Threat Scanner Verification")
        print("=" * 60)

        # Navigate to barcode page
        await page.goto("http://localhost:5173/barcode", wait_until="networkidle")
        await page.wait_for_timeout(2000)

        barcode_content = await page.content()
        print(f"Barcode page loaded: {len(barcode_content) > 1000}")
        print(f"Title found: {'Barcode Threat Scanner' in barcode_content}")

        async def scan_image(filename, label):
            print(f"\n--- Test: {label} ({filename}) ---")
            file_path = os.path.join(IMG_DIR, filename)
            if not os.path.exists(file_path):
                print(f"  ERROR: File not found: {file_path}")
                return {"error": "file not found"}

            # Reset scanner first
            try:
                reset_btn = await page.wait_for_selector("text=Reset Scanner", timeout=5000)
                await reset_btn.click()
                await page.wait_for_timeout(500)
            except:
                pass

            # Directly set file on the hidden input
            file_input = await page.locator('input[type="file"]').first
            await file_input.set_input_files(file_path)

            # Wait for scanning state
            await page.wait_for_timeout(500)
            try:
                scanning_visible = await page.is_visible("text=Scanning image...", timeout=3000)
            except:
                scanning_visible = False
            print(f"  SCANNING state visible: {scanning_visible}")

            # Wait for result or error (up to 25 seconds)
            result_text = None
            error_text = None
            try:
                await page.wait_for_selector("text=Scan result", timeout=25000)
                await page.wait_for_timeout(1000)
                result_content = await page.content()
                result_text = result_content
                # Check for verdict
                has_score = "Score" in result_content
                print(f"  Result shown: True")
                print(f"  Score displayed: {has_score}")
                verdicts = ["High risk", "Review required", "No critical signals"]
                found_verdict = next((v for v in verdicts if v in result_content), None)
                print(f"  Verdict: {found_verdict}")
                # Check payload
                if "https://example.com" in result_content or "123456789012" in result_content:
                    print(f"  Payload decoded: True")
                # Check still scanning
                still_scanning = False
                try:
                    still_scanning = await page.is_visible("text=Scanning image...", timeout=1000)
                except:
                    pass
                print(f"  Still stuck on scanning: {still_scanning}")
                return {
                    "completed": True,
                    "scanning_visible": scanning_visible,
                    "result_shown": True,
                    "score_displayed": has_score,
                    "verdict": found_verdict,
                    "not_stuck": not still_scanning,
                }
            except Exception:
                # Check for error state
                try:
                    error_box = await page.is_visible("text=No barcode", timeout=5000)
                    if error_box:
                        content = await page.content()
                        error_text = content
                        still_scanning = False
                        try:
                            still_scanning = await page.is_visible("text=Scanning image...", timeout=1000)
                        except:
                            pass
                        print(f"  Error shown: True (no barcode detected)")
                        print(f"  Still stuck on scanning: {still_scanning}")
                        return {
                            "completed": True,
                            "scanning_visible": scanning_visible,
                            "result_shown": False,
                            "error_shown": True,
                            "not_stuck": not still_scanning,
                        }
                except:
                    pass

                # Not done yet - still scanning?
                still_scanning = False
                try:
                    still_scanning = await page.is_visible("text=Scanning image...", timeout=2000)
                except:
                    pass
                print(f"  Did not complete within timeout. Still scanning: {still_scanning}")
                return {
                    "completed": False,
                    "scanning_visible": scanning_visible,
                    "not_stuck": not still_scanning,
                }

        # Test 1: Valid QR code (safe URL)
        r1 = await scan_image("tmp_qr_safe.png", "Valid QR Code (safe URL)")
        results["barcode"]["qr_safe"] = r1

        # Test 2: Valid barcode (CODE-128)
        r2 = await scan_image("tmp_barcode_code128.png", "Valid Barcode (CODE-128)")
        results["barcode"]["barcode"] = r2

        # Test 3: Invalid/non-barcode image
        r3 = await scan_image("tmp_invalid_image.png", "Invalid/Non-barcode Image")
        results["barcode"]["invalid"] = r3

        # Test 4: Large image (3000x3000)
        r4 = await scan_image("tmp_large_qr.png", "Large Image (3000x3000 QR)")
        results["barcode"]["large"] = r4

        await browser.close()

    # Save results
    with open(os.path.join(PROJECT_ROOT, "tmp_verify_results.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)

    print("\n" + "=" * 60)
    print("FULL RESULTS SUMMARY")
    print("=" * 60)
    print(json.dumps(results, indent=2, default=str))

asyncio.run(run())
