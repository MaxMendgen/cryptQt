import subprocess
import sys
import os

# Ensure pkg_resources is available (part of setuptools)
try:
    import pkg_resources
except ImportError:
    print("pkg_resources not found, installing setuptools...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "setuptools"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import pkg_resources

def install_requirements():
    """Install required packages from requirements.txt if not already installed"""
    requirements_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    
    if os.path.exists(requirements_file):
        print("Checking required packages...")
        with open(requirements_file, "r") as f:
            required = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        missing = []
        
        for req in required:
            try:
                pkg_resources.get_distribution(req)
            except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
                missing.append(req)
        
        if missing:
            print(f"Installing missing packages: {', '.join(missing)}")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install"] + missing,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print("Packages ready")
            except subprocess.CalledProcessError:
                print("Error installing required packages.")
        else:
            print("All required packages are already installed.")
    else:
        print(f"Warning: {requirements_file} not found")

def launch_gui():
    """Launch the Qt GUI application"""
    gui_path = os.path.join(
        os.path.dirname(__file__),
        "src", "cryptqt", "gui", "QT_gui.py"
    )
    
    if os.path.exists(gui_path):
        print("Launching Crypto Toolkit GUI...")
        subprocess.Popen([sys.executable, gui_path])
    else:
        print(f"Error: GUI file not found at {gui_path}")
        sys.exit(1)


# Main execution
if __name__ == "__main__":
    install_requirements()
    launch_gui()
