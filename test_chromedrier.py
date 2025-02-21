from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
driver.get("https://fakeopenai.co/lsat")
driver.save_screenshot("lsat_screenshot.png")
driver.quit()
