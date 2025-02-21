sudo apt update && sudo apt full-upgrade
sudo apt --fix-broken install
sudo apt install python3.11
sudo apt install python3.11-venv
python3.11 -m venv ~/venv-metal
source ~/venv-metal/bin/activate
python3.11 -m pip install -U pip

python3.11 pip install -r requirements.txt
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
wget https://storage.googleapis.com/chrome-for-testing-public/133.0.6943.98/linux64/chromedriver-linux64.zip
sudo apt install unzip
unzip chromedriver-linux64.zip
mv chromedriver-linux64/chromedriver . && chmod +x chomedriver