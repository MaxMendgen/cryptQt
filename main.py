import subprocess
import sys
import os

def install_requirements():
    """Install required packages from requirements.txt using pip"""
    requirements_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if os.path.exists(requirements_file):
        print("Installing required packages from requirements.txt...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", requirements_file])
        print("Requirements installation complete.")
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
        # Auto-set PYTHONPATH to src
        src_path = os.path.join(os.path.dirname(__file__), "src")
        env = os.environ.copy()
        env["PYTHONPATH"] = src_path
        subprocess.Popen([sys.executable, gui_path], env=env)
    else:
        print(f"Error: GUI file not found at {gui_path}")
        sys.exit(1)


# Main execution
if __name__ == "__main__":
    install_requirements()
    launch_gui()
