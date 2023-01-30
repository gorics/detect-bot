from flask import Flask, request
import time

app = Flask(__name__)

# Constants
MINIMUM_REQUEST_INTERVAL = 10 # seconds
BOT_HEADER_SIGNATURES = {
    "User-Agent": "", 
    "Referer": "", 
    "Origin": "", 
    "Accept-Encoding": "", 
    "Accept-Language": ""
}
BOT_PAYLOAD_SIGNATURES = ["username=admin", "password=password"]
BOT_URL_SIGNATURES = ["wp-admin", "admin-ajax.php"]
BLACKLISTED_IPS = []
BOTNET_IPS = []
SEARCH_ENGINE_BOT_USER_AGENTS = [
        "googlebot",
        "bingbot",
        "yandexbot",
        "baidubot",
        "facebot",
        "twitterbot",
        "rogerbot",
        "linkedinbot",
        "embedly",
        "quora link preview",
        "showyoubot",
        "outbrain",
        "pinterest",
        "developers.google.com/+/web/snippet",
        "slackbot",
        "vkShare",
        "W3C_Validator",
        "redditbot",
        "Applebot",
        "WhatsApp",
        "flipboard",
        "tumblr",
        "bitlybot",
        "SkypeUriPreview",
        "nuzzel",
        "Discordbot",
        "Google Page Speed",
        "Qwantify",
        "pinterestbot"
    ]
BOT_USER_AGENTS = []

# Request history to store IP addresses and their request timestamps
request_history = {}

def is_bot_request(ip, user_agent, headers, payload, url):
    # Check if the request frequency is abnormally high
    current_time = time.time()
    try:
        last_request_time = request_history[ip]
        if current_time - last_request_time < MINIMUM_REQUEST_INTERVAL:
            return True
    except KeyError:
        pass
    request_history[ip] = current_time
    
    # Inspect the request headers to see if they contain typical bot signatures
    for header, value in headers.items():
        if header in BOT_HEADER_SIGNATURES and value != BOT_HEADER_SIGNATURES[header]:
            return True
    
    # Analyze the request payload and URL patterns
    if any(bot_string in str(payload) for bot_string in BOT_PAYLOAD_SIGNATURES) or \
        any(bot_string in url for bot_string in BOT_URL_SIGNATURES):
        return True

    # Check if the request's IP address is blacklisted or associated with known botnets
    if ip in BLACKLISTED_IPS or ip in BOTNET_IPS:
        return True

    # Check the user agent against a list of known bot user agents
    if any(bot_string in user_agent.lower() for bot_string in BOT_USER_AGENTS + SEARCH_ENGINE_BOT_USER_AGENTS):
        return True
    
    return False


@app.route('/', methods=['GET'])
def handle_get_request():
    # Get the IP address, user agent, headers, and URL of the request
    ip = request.remote_addr
    user_agent = request.user_agent.string
    headers = request.headers
    payload = request.args
    url = request.url
    
    # Check if the request is from a bot
    if is_bot_request(ip, user_agent, headers, payload, url):
        return 'Bot request detected and blocked', 403
    else:
        return 'Valid request from user', 200

@app.route('/', methods=['POST'])
def handle_post_request():
    # Get the IP address, user agent, headers, and URL of the request
    ip = request.remote_addr
    user_agent = request.user_agent.string
    headers = request.headers
    payload = request.form
    url = request.url
    
    # Check if the request is from a bot
    if is_bot_request(ip, user_agent, headers, payload, url):
        return 'Bot request detected and blocked', 403
    else:
        return 'Valid request from user', 200
import socket

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

print(get_ip())

app.run(host="0.0.0.0",port=80)
