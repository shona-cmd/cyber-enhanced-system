# TODO: Fix Cursor Icon Display Issue

## Problem
The cursor icon isn't displaying due to inconsistent image source paths in templates. Some use relative paths that fail for certain routes, and the click event overrides the icon with a colored SVG square.

## Solution
- Update all affected templates to use absolute path "/static/cyber-security.png".
- Modify click event to apply a color filter instead of replacing the icon, preserving the original image.

## Steps
- [x] Update templates/dashboard.html
- [x] Update templates/quote.html
- [x] Update templates/threat_intel.html
- [x] Update templates/threat.html
- [x] Update templates/login.html
- [x] Update templates/device_manager.html
- [x] Update templates/device_details.html
- [x] Update templates/devices.html
- [x] Update templates/training.html
- [x] Test the changes by running the app and checking cursor behavior
