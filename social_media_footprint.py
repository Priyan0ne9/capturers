import requests
from bs4 import BeautifulSoup


def check_social_media_footprint(url):
    social_media_profiles = {
        "Instagram": "instagram.com",
        "LinkedIn": "linkedin.com",
        "Twitter": "twitter.com",
        "Facebook": "facebook.com",
        "YouTube": "youtube.com",
        "Reddit": "reddit.com",
        "Snapchat": "snapchat.com",
    }

    social_media_found = {}

    try:
        # Get the HTML content of the page
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")

        # Check for social media links in anchor tags
        links = soup.find_all("a", href=True)

        # Look for known social media patterns in the href attribute
        for platform, domain in social_media_profiles.items():
            social_media_found[platform] = False
            for link in links:
                if domain in link["href"]:
                    social_media_found[platform] = True
                    break

    except requests.RequestException:
        return {"error": "Error fetching website data"}

    return social_media_found
