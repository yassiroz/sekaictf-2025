from typing import Callable
from type import Status
from config import Config

from lamda.client import *
from lamda.const import *

import time
from datetime import datetime, timedelta

PACKAGE_NAME = "com.sekai.bank"
CHALLENGE_NAME = "SekaiBank"
TIMEOUT = 60 * 5

ACCOUNT_USERNAME = "admin"
ACCOUNT_PASSWORD = "Admin123#S3k4i"
ACCOUNT_PIN = "443123"

USERNAME_TO_SEND = "nino"
AMOUNT_TO_SEND = 10
AMOUNT_TO_SEND_DELAYED = 100

UI_TIMEOUT = 10*1000

device = Device("localhost")

def scroll_until_exists(element):
    while not element.exists():
        device.swipe(Point(x=30, y=800), Point(x=30, y=650))

def start_app():
    vuln_app = device.application(PACKAGE_NAME)
    vuln_app.start()

    return vuln_app

def stop_if_running():
    running_apps = device.enumerate_running_processes()
    for app in running_apps:
        if app.packages[0] == PACKAGE_NAME:
            device.application(app.packages[0]).stop()

    device.execute_script(f'pkill {PACKAGE_NAME}')

def login_if_needed():
    if device(resourceId="com.sekai.bank:id/sekai_subtitle").exists():
        username_input = device(resourceId="com.sekai.bank:id/username_input")
        username_input.set_text(ACCOUNT_USERNAME)

        password_input = device(resourceId="com.sekai.bank:id/password_input")
        password_input.set_text(ACCOUNT_PASSWORD)

        auth_button = device(resourceId="com.sekai.bank:id/auth_button")
        auth_button.click()

def enter_pin_on_login():        
    device(text="Enter your PIN to access your account").wait_for_exists(UI_TIMEOUT)

    pin_buttons = []
    for i in range(0, 9):
        pin_buttons.append(device(resourceId=f"com.sekai.bank:id/pin_button_{i}"))

    for c in ACCOUNT_PIN:
        pin_buttons[int(c)].click()
        time.sleep(0.1)

def enter_pin_on_sendmoney():
    device(text="Enter your PIN to continue").wait_for_exists(UI_TIMEOUT)
    
    pin_buttons = []
    for i in range(0, 9):
        pin_buttons.append(device(resourceId=f"com.sekai.bank:id/pin_button_{i}"))
    
    for c in ACCOUNT_PIN:
        pin_buttons[int(c)].click()
        time.sleep(0.1)

def go_to_sendmoney_menu():
    nav_send = device(resourceId="com.sekai.bank:id/nav_send")
    nav_send.wait_for_exists(UI_TIMEOUT)
    nav_send.click()

    device(text="Transfer money to another user securely").wait_for_exists(UI_TIMEOUT)

def send_money():
    go_to_sendmoney_menu()

    recipient_input = device(resourceId="com.sekai.bank:id/recipient_input")
    recipient_input.set_text(USERNAME_TO_SEND)

    amount_input = device(resourceId="com.sekai.bank:id/amount_input")
    amount_input.set_text(str(AMOUNT_TO_SEND))

    schedule_checkbox = device(resourceId="com.sekai.bank:id/schedule_checkbox")
    if schedule_checkbox.info().checked:
        schedule_checkbox.click()    

    send_button = device(resourceId="com.sekai.bank:id/send_button")
    scroll_until_exists(send_button)
    send_button.click()

    confirm_button = device(text="Confirm")
    confirm_button.wait_for_exists(UI_TIMEOUT)
    confirm_button.click()

    enter_pin_on_sendmoney()

def send_scheduled_money():
    go_to_sendmoney_menu()

    recipient_input = device(resourceId="com.sekai.bank:id/recipient_input")
    recipient_input.set_text(USERNAME_TO_SEND)

    amount_input = device(resourceId="com.sekai.bank:id/amount_input")
    amount_input.set_text(str(AMOUNT_TO_SEND_DELAYED))

    schedule_checkbox = device(resourceId="com.sekai.bank:id/schedule_checkbox")
    if not schedule_checkbox.info().checked:
        schedule_checkbox.click()    

    date_picker_button = device(resourceId="com.sekai.bank:id/date_picker_button")
    date_picker_button.wait_for_exists(UI_TIMEOUT)
    date_picker_button.click()

    date = device.execute_script('date').stdout.decode().strip()
    dt = datetime.strptime(date, "%a %b %d %H:%M:%S %Z %Y")
    dt_plus_5m = dt + timedelta(minutes=5)

    button1 = device(resourceId="android:id/button1")
    button1.wait_for_exists(UI_TIMEOUT)

    date_button = device(text=str(dt_plus_5m.day), clickable=True, enabled=True)
    date_button.click()

    button1.click()

    time_picker_button = device(resourceId="com.sekai.bank:id/time_picker_button")
    time_picker_button.wait_for_exists(UI_TIMEOUT)
    time_picker_button.click()    

    toggle_mode = device(resourceId="android:id/toggle_mode")
    toggle_mode.wait_for_exists(UI_TIMEOUT)
    toggle_mode.click()

    device(text="Set time").wait_for_exists(UI_TIMEOUT)

    input_hour = device(resourceId="android:id/input_hour")
    input_hour.set_text(str(dt_plus_5m.hour))

    input_minute = device(resourceId="android:id/input_minute")
    input_minute.set_text(str(dt_plus_5m.minute))

    button1 = device(resourceId="android:id/button1")
    button1.wait_for_exists(UI_TIMEOUT)
    button1.click()

    send_button = device(resourceId="com.sekai.bank:id/send_button")
    scroll_until_exists(send_button)

    send_button.click()

    confirm_button = device(text="Confirm")
    confirm_button.wait_for_exists(UI_TIMEOUT)
    confirm_button.click()

    enter_pin_on_sendmoney()

def callback(poc_app, update_status):
    update_status(Status.RUNNING_CHALLENGE)
    stop_if_running()

    start_app()

    time.sleep(5)

    bottom_navigation = device(resourceId="com.sekai.bank:id/bottom_navigation")

    if not bottom_navigation.exists():
        login_if_needed()

        enter_pin_on_login()

    bottom_navigation.wait_for_exists(UI_TIMEOUT)

    send_money()
    send_scheduled_money()

    time.sleep(2.5)

    update_status(Status.RUNNING_POC)

    poc_app.start()

    time.sleep(10)