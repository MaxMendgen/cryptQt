import subprocess
import sys
import os

def install_requirements():
    """Install required packages from requirements.txt if not already installed"""
    requirements_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    
    if os.path.exists(requirements_file):
        print("Checking required packages...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-q", "-r", requirements_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("Packages ready")
        except subprocess.CalledProcessError:
            pass
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

if __name__ == "__main__":
    try:
        install_requirements()
        launch_gui()
    except subprocess.CalledProcessError as e:
        print(f"Error during installation: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
        