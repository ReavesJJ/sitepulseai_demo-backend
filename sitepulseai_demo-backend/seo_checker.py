from fastapi import APIRouter
import requests
from bs4 import BeautifulSoup

router = APIRouter()

@router.get("/seo/{domain}")
def seo_card(domain: str):
    url = f"https://{domain}"
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        title_len = len(soup.title.string) if soup.title else 0
        meta_desc = bool(soup.find("meta", attrs={"name": "description"}))
        score = min(100, title_len * 2 + (20 if meta_desc else 0))
        status = "OK" if meta_desc else "Missing Meta Description"
        return {"score": score, "status": status, "title_length": title_len, "meta_description_present": meta_desc}
    except Exception:
        return {"score": None, "status": "Not scanned"}
