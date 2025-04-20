# Advanced-Mic-Camera-Monitor

مانیتور پیشرفته دوربین و میکروفن

 یک برنامه مبتنی بر پایتون است که برای نظارت و مدیریت دسترسی به دستگاه‌های سیستمی مانند وب‌کم و میکروفون طراحی شده است. این برنامه دسترسی‌های غیرمجاز را شناسایی می‌کند، فعالیت‌ها را ثبت می‌کند و رابط کاربری برای اجازه یا رد درخواست‌های دسترسی ارائه می‌دهد. این برنامه از یادگیری ماشین (مدل LSTM) برای شناسایی رفتارهای غیرعادی استفاده می‌کند، ترافیک شبکه را برای فعالیت‌های مشکوک نظارت می‌کند و یک آیکون در پنل بار سیستم برای دسترسی آسان به لاگ‌ها و تاریخچه فرآیندها ارائه می‌دهد.
 
ویژگی‌ها

نظارت بر دستگاه‌ها:

دسترسی به دستگاه‌های ویدئویی (/dev/video*) و صوتی (/dev/snd/pcm*) را ردیابی می‌کند.

تشخیص ناهنجاری:

از مدل LSTM برای شناسایی رفتار غیرعادی فرآیندها بر اساس استفاده از CPU، حافظه و فرکانس دسترسی استفاده می‌کند.

نظارت بر شبکه: 

فعالیت‌های مشکوک شبکه را در پورت‌های مشخص‌شده با استفاده از Scapy شناسایی می‌کند.

رابط کاربری:

پاپ‌آپ مبتنی بر Tkinter برای درخواست‌های دسترسی و آیکون در پنل بار سیستم (PyQt6) برای مشاهده لاگ‌ها و تاریخچه فرآیندها ارائه می‌دهد.

لاگ‌گیری:

لاگ‌های دسترسی را در قالب JSON ذخیره می‌کند و پایگاه داده SQLite برای مجوزهای دائمی نگه می‌دارد.

مدیریت فرآیندها: 

به کاربران اجازه می‌دهد دسترسی را اجازه دهند، رد کنند یا به‌صورت دائمی اجازه دهند، با گزینه‌ای برای خاتمه دادن به فرآیندهای غیرمجاز.

پیش‌نیازها

سیستم‌عامل: لینوکس (تست‌شده روی اوبونتو 20.04 و دبیان )

پایتون: نسخه 3.8 یا بالاتر

وابستگی‌ها:

نصب پکیج‌های پایتون مورد نیاز:
pip install pyinotify psutil tensorflow numpy scapy tkinter pyqt6


نیازهای سیستمی اضافی:

ابزار خط فرمان 
lsof (sudo apt install lsof )
رابط شبکه (مثل wlan0) برای نظارت بر شبکه

دسترسی به دستگاه‌های /dev/video* و /dev/snd/*



وابستگی‌ها را نصب کنید:
pip install -r requirements.txt




اطمینان حاصل کنید که lsof نصب شده است:
sudo apt update
sudo apt install lsof



استفاده

اسکریپت را با دسترسی روت اجرا کنید (برای دسترسی به دستگاه‌ها و نظارت بر شبکه لازم است)
:sudo python3 advanced_monitor-Mic-Cam.py


برنامه:

نظارت بر دسترسی به دستگاه‌ها و ترافیک شبکه را آغاز می‌کند.

یک آیکون در پنل بار سیستم با گزینه‌های مشاهده لاگ‌ها و تاریخچه فرآیندها نمایش می‌دهد.

برای هر درخواست دسترسی یک پاپ‌آپ نمایش می‌دهد که به شما امکان می‌دهد فرآیند را اجازه دهید (برای یکبار)، رد کنید یا همیشه اجازه دهید.


لاگ‌ها در /var/log/monitor_pro.log ذخیره می‌شوند و مجوزها در monitor_permissions.db نگه‌داری می‌شوند.

نکات

دسترسی روت:

اسکریپت برای دسترسی به دستگاه‌ها و نظارت بر ترافیک شبکه نیاز به sudo دارد.

رابط شبکه:

متغیر NETWORK_INTERFACE در اسکریپت (پیش‌فرض: wlan0) را با سیستم خود به‌روزرسانی کنید.

پورت‌های مشکوک:

لیست SUSPICIOUS_PORTS را برای شامل کردن پورت‌هایی که مشکوک می‌دانید تغییر دهید.

عملکرد:

مدل LSTM ممکن است در طول آموزش به منابع CPU زیادی نیاز داشته باشد. برای تنظیم عملکرد، HISTORY_SIZE را تغییر دهید.

فایل لاگ:

اطمینان حاصل کنید که کاربر مجوز نوشتن در /var/log/monitor_pro.log را دارد.






The Advanced Mic/Camera Monitor is a Python-based application designed to monitor and manage access to system devices such as webcams and microphones. It detects unauthorized access, logs activities, and provides a user interface to allow or deny access requests. The application uses machine learning (LSTM model) to detect anomalous behavior, monitors network traffic for suspicious activity, and offers a system tray icon for easy access to logs and process history.

Features

Device Monitoring: Tracks access to video (/dev/video*) and audio (/dev/snd/pcm*) devices.
Anomaly Detection: Uses an LSTM model to identify unusual process behavior based on CPU, memory usage, and access frequency.
Network Monitoring: Detects suspicious network activity on specified ports using Scapy.
User Interface: Provides a Tkinter-based popup for access requests and a system tray icon (PyQt6) for viewing logs and process history.
Logging: Stores access logs in JSON format and maintains a SQLite database for persistent permissions.
Process Management: Allows users to allow, deny, or permanently allow access, with the option to terminate unauthorized processes.

Prerequisites

Operating System: Linux (Tested on Ubuntu 20.04+ / Debian)
Python: Version 3.8 or higher
Dependencies:
Install required Python packages:pip install pyinotify psutil tensorflow numpy scapy tkinter pyqt6


Additional system requirements:
lsof command-line tool (sudo apt install lsof )
Network interface (e.g., wlan0) for network monitoring
Access to /dev/video* and /dev/snd/* devices


Optional:
A system tray icon image (icon.png) for the PyQt6 system tray. If not present, the tray may lack an icon.


Install dependencies:pip install -r requirements.txt


Ensure lsof is installed:sudo apt update
sudo apt install lsof


Usage

Run the script with root privileges (required for device access and network monitoring):sudo python3 advanced_monitor-Mic-Cam.py


The application will:
Start monitoring device access and network traffic.
Display a system tray icon with options to view logs and process history.
Show a popup for each access request, allowing you to allow(once), deny, or always allow the process.


Logs are stored in /var/log/monitor_pro.log, and permissions are saved in monitor_permissions.db.

Notes

Root Privileges: The script requires sudo to access devices and monitor network traffic.
Network Interface: Update the NETWORK_INTERFACE variable in the script (default: wlan0) to match your system.
Suspicious Ports: Modify the SUSPICIOUS_PORTS list to include ports you consider suspicious.
Performance: The LSTM model may require significant CPU resources during training. Adjust HISTORY_SIZE for performance tuning.
Log File: Ensure the user has write permissions for /var/log/monitor_pro.log.

Contributing
Contributions are welcome! Please fork the repository, create a new branch, and submit a pull request with your changes.
License
This project is licensed under the MIT License. See the LICENSE file for details.
