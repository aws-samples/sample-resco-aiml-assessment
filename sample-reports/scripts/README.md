# Scripts

This directory contains utility scripts for development and documentation.

## Screenshot Capture Tool

`capture_screenshots.py` - Automated screenshot capture and optimization for documentation.

### Purpose

Captures screenshots from the HTML sample reports for use in the README and documentation. The script:
- Opens HTML reports in a headless browser
- Captures multiple views (dashboard, tables, light/dark modes)
- Automatically optimizes images for web
- Targets 200-300KB per screenshot

### Installation

```bash
# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r sample-reports/dev-requirements.txt

# Install Playwright browser
playwright install chromium
```

### Usage

```bash
# Run the script
python sample-reports/scripts/capture_screenshots.py
```

The script will:
1. Launch Chromium in headless mode
2. Load each HTML report from `sample-reports/`
3. Capture screenshots based on configuration
4. Optimize and compress images
5. Save to `sample-reports/` folder

### Configuration

Edit `sample-reports/scripts/capture_screenshots.py` to customize:

```python
# Viewport size
VIEWPORT_WIDTH = 1440
VIEWPORT_HEIGHT = 900

# Image quality
JPEG_QUALITY = 85
PNG_OPTIMIZE = True

# Screenshots to capture
SCREENSHOTS = [
    {
        "name": "dashboard-overview-light",
        "file": "security_assessment_single_account.html",
        "description": "Executive Dashboard (Light Mode)",
        "actions": [
            {"type": "wait", "selector": ".metrics", "timeout": 2000},
            {"type": "scroll", "position": 0},
        ],
        "clip": {"x": 0, "y": 0, "width": 1440, "height": 800},
    },
    # Add more screenshots...
]
```

### Output

Screenshots are saved with these naming conventions:
- `dashboard-overview-light.png/jpg` - Dashboard in light mode
- `dashboard-overview-dark.png/jpg` - Dashboard in dark mode
- `findings-table.png/jpg` - Findings table view
- `multi-account-summary.png/jpg` - Multi-account report

All images are automatically optimized to keep file sizes under 300KB while maintaining visual quality.

### Adding New Screenshots

1. Add a new entry to the `SCREENSHOTS` list in `sample-reports/scripts/capture_screenshots.py`
2. Define actions (wait, click, scroll) to prepare the view
3. Specify clip area or use full viewport
4. Run the script
5. Update README.md to reference the new screenshot

### Troubleshooting

**Error: playwright not installed**
```bash
pip install playwright
playwright install chromium
```

**Error: Sample reports not found**
- Ensure you're running from the repository root
- Check that `sample-reports/` directory exists
- Verify HTML files are present

**Screenshots too large**
- Adjust `JPEG_QUALITY` (lower = smaller file)
- Reduce viewport size
- Use clip regions to capture specific areas

### Dependencies

- `playwright` - Browser automation
- `pillow` - Image optimization

See `sample-reports/dev-requirements.txt` for version details.
