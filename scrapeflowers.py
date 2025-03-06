import os
import time
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

def scrape_flowers():
    url = "https://www.google.com/search?tbm=isch&q=flower"
    options = Options()
    options.add_argument("--headless=new")
    service = ChromeService("chromedriver")
    driver = webdriver.Chrome(service=service, options=options)
    driver.get(url)

    if not os.path.exists("flowers"):
        os.makedirs("flowers")

    image_count = 0
    last_scroll_position = 0
    scroll_attempts = 0

    while True:
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(2)
        new_scroll_position = driver.execute_script("return window.scrollY")
        if new_scroll_position == last_scroll_position:
            scroll_attempts += 1
            if scroll_attempts > 1:
                break
        else:
            scroll_attempts = 0
            last_scroll_position = new_scroll_position

        thumbnails = driver.find_elements(By.CSS_SELECTOR, "img.Q4LuWd")
        for thumb in thumbnails[image_count:]:
            try:
                thumb.click()
                time.sleep(1)
                images = driver.find_elements(By.CSS_SELECTOR, "img.n3VNCb")
                for image in images:
                    src = image.get_attribute("src")
                    if src and "http" in src:
                        print(f"Downloading image {image_count} from {src}")
                        try:
                            r = requests.get(src, timeout=5)
                            path = f"flowers/flower_{image_count}.jpg"
                            with open(path, "wb") as f:
                                f.write(r.content)
                            print(f"Saved image {image_count} to {path}")
                            image_count += 1
                            break
                        except Exception as e:
                            print(f"Failed to download image {image_count}: {e}")
            except Exception as e:
                print(f"Error clicking thumbnail {image_count}: {e}")

    driver.quit()

if __name__ == "__main__":
    scrape_flowers()