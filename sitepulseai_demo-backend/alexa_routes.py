from fastapi import APIRouter

router = APIRouter()

@router.get("/api/ssl-status")
def get_ssl_status():
    return {
        "summary": "Your SSL certificate is valid and will expire in 74 days."
    }

@router.get("/api/uptime")
def get_uptime():
    return {
        "summary": "Your website uptime this week is 99.97 percent. No downtime was recorded."
    }

@router.get("/api/seo-summary")
def get_seo_summary():
    return {
        "summary": "Your SEO scan detected two missing meta descriptions and one broken link. Overall, performance is strong."
    }
