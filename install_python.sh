sudo apt update && sudo apt full-upgrade
sudo apt --fix-broken install
sudo apt install python3.11
sudo apt install python3.11-venv
python3.11 -m venv ~/venv-metal
source ~/venv-metal/bin/activate
python -m pip install -U pip