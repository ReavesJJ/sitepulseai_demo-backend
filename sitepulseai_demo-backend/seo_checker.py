from fastapi import APIRouter, Path
import requests
from bs4 import BeautifulSoup

router = APIRouter(prefix="/seo", tags=["SEO"])


def scan_seo(url: str):
    try:
        if not url.startswith("http"):
            url = "https://" + url

        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        title = soup.title.string.strip() if soup.title else ""
        meta_desc = soup.find("meta", attrs={"name": "description"})

        return {
            "status": "OK",
            "title_length": len(title),
            "meta_description_present": meta_desc is not None,
            "score": min(100, len(title) * 2)
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@router.get("/{domain}")
def seo_card(domain: str = Path(...)):
    return scan_seo(domain)

