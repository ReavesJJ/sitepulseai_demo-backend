import time
from monitor import run_full_check
from site_manager import get_all_sites

def start_monitoring():
    print("Monitoring Engine: ACTIVE")

    while True:
        sites = get_all_sites()

        for site in sites:
            run_full_check(site)


        time.sleep(300)  # 5 minutes