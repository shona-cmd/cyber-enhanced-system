"""
QR Code Deployment Utility for NaashonSecureIoT.

Generates QR codes for easy installation across devices and platforms.
Supports Windows, macOS, Linux, Android, iOS deployment.
"""

import qrcode
import os
import platform
import subprocess
from PIL import Image, ImageDraw, ImageFont
import json
from typing import Dict, Any


class QRDeploy:
    """QR Code deployment generator for cross-platform installation."""

    def __init__(self):
        self.install_commands = {
            "windows": "pip install naashon-secure-iot",
            "macos": "pip install naashon-secure-iot",
            "linux": "pip install naashon-secure-iot",
            "android": "pip install naashon-secure-iot",  # Via Termux
            "ios": "pip install naashon-secure-iot",  # Via Pythonista/StaSh
        }

    def generate_install_qr(self, platform_name: str, output_file: str = None) -> str:
        """
        Generate QR code for installation command.

        Args:
            platform_name: Target platform (windows, macos, linux, android, ios)
            output_file: Output file path (optional)

        Returns:
            Path to generated QR code image
        """
        if platform_name not in self.install_commands:
            raise ValueError(f"Unsupported platform: {platform_name}")

        command = self.install_commands[platform_name]

        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(command)
        qr.make(fit=True)

        # Create image
        img = qr.make_image(fill_color="black", back_color="white")

        # Add platform label
        img = self._add_label(img, f"NaashonSecureIoT - {platform_name.title()}")

        # Save or return
        if output_file:
            img.save(output_file)
            return output_file
        else:
            default_name = f"naashon_install_{platform_name}.png"
            img.save(default_name)
            return default_name

    def generate_config_qr(self, config_data: Dict[str, Any], output_file: str = None) -> str:
        """
        Generate QR code containing configuration data.

        Args:
            config_data: Configuration dictionary
            output_file: Output file path (optional)

        Returns:
            Path to generated QR code image
        """
        # Convert config to JSON string
        config_json = json.dumps(config_data, indent=2)

        # Create QR code (higher version for larger data)
        qr = qrcode.QRCode(
            version=10,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=4,
        )
        qr.add_data(config_json)
        qr.make(fit=True)

        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        img = self._add_label(img, "NaashonSecureIoT Config")

        # Save or return
        if output_file:
            img.save(output_file)
            return output_file
        else:
            img.save("naashon_config.png")
            return "naashon_config.png"

    def generate_universal_qr(self, output_file: str = "naashon_universal.png") -> str:
        """
        Generate universal QR code with installation instructions for all platforms.

        Returns:
            Path to generated QR code image
        """
        instructions = """
NaashonSecureIoT Installation:

1. Install Python 3.8+ from python.org
2. Open terminal/command prompt
3. Run: pip install naashon-secure-iot
4. Launch: naashon-dashboard

For more info: https://github.com/naashon/naashon-secure-iot
        """.strip()

        qr = qrcode.QRCode(
            version=15,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=4,
        )
        qr.add_data(instructions)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img = self._add_label(img, "NaashonSecureIoT Universal Install")

        img.save(output_file)
        return output_file

    def _add_label(self, img: Image.Image, label: str) -> Image.Image:
        """Add text label below QR code."""
        # Get image dimensions
        width, height = img.size

        # Create new image with space for text
        new_height = height + 60
        new_img = Image.new('RGB', (width, new_height), 'white')

        # Paste QR code with proper conversion
        new_img.paste(img.convert('RGB'), (0, 0))

        # Add text
        draw = ImageDraw.Draw(new_img)
        try:
            # Try to use default font
            font = ImageFont.truetype("arial.ttf", 20)
        except:
            # Fallback to default
            font = ImageFont.load_default()

        # Center text
        bbox = draw.textbbox((0, 0), label, font=font)
        text_width = bbox[2] - bbox[0]
        text_x = (width - text_width) // 2
        text_y = height + 10

        draw.text((text_x, text_y), label, fill="black", font=font)

        return new_img

    def detect_platform(self) -> str:
        """Detect current platform."""
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        elif system == "linux":
            return "linux"
        else:
            return "unknown"

    def generate_all_platforms(self, output_dir: str = "qr_codes") -> Dict[str, str]:
        """
        Generate QR codes for all supported platforms.

        Args:
            output_dir: Directory to save QR codes

        Returns:
            Dictionary mapping platform to QR code file path
        """
        os.makedirs(output_dir, exist_ok=True)

        qr_files = {}
        for platform_name in self.install_commands.keys():
            filename = f"{output_dir}/naashon_install_{platform_name}.png"
            qr_files[platform_name] = self.generate_install_qr(platform_name, filename)

        # Generate universal QR
        universal_file = f"{output_dir}/naashon_universal.png"
        qr_files["universal"] = self.generate_universal_qr(universal_file)

        return qr_files


def main():
    """CLI entry point for QR deployment."""
    import argparse

    parser = argparse.ArgumentParser(description="NaashonSecureIoT QR Deployment")
    parser.add_argument("--platform", help="Target platform")
    parser.add_argument("--all", action="store_true", help="Generate for all platforms")
    parser.add_argument("--universal", action="store_true", help="Generate universal QR")
    parser.add_argument("--config", help="Generate config QR from JSON file")
    parser.add_argument("--output", help="Output file path")

    args = parser.parse_args()

    deployer = QRDeploy()

    if args.all:
        qr_files = deployer.generate_all_platforms()
        print("Generated QR codes:")
        for platform, file in qr_files.items():
            print(f"  {platform}: {file}")

    elif args.universal:
        file = deployer.generate_universal_qr(args.output)
        print(f"Universal QR code generated: {file}")

    elif args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
        file = deployer.generate_config_qr(config, args.output)
        print(f"Config QR code generated: {file}")

    else:
        platform = args.platform or deployer.detect_platform()
        file = deployer.generate_install_qr(platform, args.output)
        print(f"Installation QR code generated for {platform}: {file}")


if __name__ == "__main__":
    main()
