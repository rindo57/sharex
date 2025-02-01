from utils.clients import get_client
from pyrogram import Client
from pyrogram.types import Message
from config import STORAGE_CHANNEL
from utils.logger import Logger
from urllib.parse import unquote_plus
from pymediainfo import MediaInfo
import requests
import os
import base64
import aiohttp, asyncio
from http.cookies import SimpleCookie
from json import loads as json_loads
import urllib.parse
import urllib.request
import http.cookiejar
import json
import re
import subprocess
import pycountry
from utils.humanFunctions import humanBitrate, humanSize, remove_N

import traceback
import zlib
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from base58 import b58encode
from base64 import b64encode
logger = Logger(__name__)
PROGRESS_CACHE = {}
STOP_TRANSMISSION = []

def format_duration(duration_in_seconds):
    """
    Convert duration from seconds to a readable format "XX min XX s".

    Args:
        duration_in_seconds (float): Duration in seconds.

    Returns:
        str: Formatted duration as "XX min XX s".
    """
    minutes, seconds = divmod(int(duration_in_seconds), 60)
    return f"{minutes} min {seconds} s"

def get_country_code_from_language(lang_code):
    """
    Map language codes (ISO 639-1 or ISO 639-2) to commonly associated country codes (ISO 3166-1 alpha-2).
    If no specific mapping exists, return the language code as-is.
    """
    # Common mappings from language to country
    language_to_country = {
        "ab": "ge", "aa": "et", "af": "za", "ak": "gh", "sq": "al", "am": "et", "ar": "sa", "hy": "am", 
        "as": "in", "av": "ru", "ae": "ir", "ay": "bo", "az": "az", "bm": "ml", "bn": "bd", "bs": "ba", 
        "br": "fr", "bg": "bg", "my": "mm", "ca": "es", "ch": "fm", "ce": "ru", "ny": "mw", "zh": "cn", 
        "cv": "ru", "kw": "gb", "co": "fr", "cr": "ca", "hr": "hr", "cs": "cz", "da": "dk", "dv": "mv", 
        "nl": "nl", "dz": "bt", "en": "us", "eo": "zz", "et": "ee", "ee": "gh", "tl": "ph", "fi": "fi", 
        "fo": "fo", "fr": "fr", "ff": "sn", "ka": "ge", "de": "de", "el": "gr", "gn": "py", "gu": "in", 
        "ht": "ht", "ha": "ng", "he": "il", "hi": "in", "ho": "pg", "hu": "hu", "is": "is", "id": "id", 
        "ia": "zz", "ie": "zz", "iu": "ca", "ik": "us", "ga": "ie", "it": "it", "ja": "jp", "jw": "id", 
        "kl": "gl", "kn": "in", "km": "kh", "ko": "kr", "la": "it", "lv": "lv", "la": "it", "lb": "lu", 
        "lo": "la", "lt": "lt", "mk": "mk", "ml": "in", "mr": "in", "mh": "mh", "mi": "nz", "mn": "mn", 
        "my": "mm", "ne": "np", "no": "no", "pl": "pl", "pt": "pt", "ps": "af", "qu": "pe", "ro": "ro", 
        "ru": "ru", "sr": "rs", "si": "lk", "sk": "sk", "sl": "si", "es": "es", "su": "id", "sw": "ke", 
        "sv": "se", "ta": "in", "tt": "ru", "te": "in", "th": "th", "tr": "tr", "uk": "ua", "ur": "pk", 
        "uz": "uz", "vi": "vn", "cy": "gb", "xh": "za", "yi": "de", "zu": "za"
    }

    # If a direct mapping exists, return the country code
    if lang_code in language_to_country:
        return language_to_country[lang_code]

    # Try using pycountry for more obscure mappings
    try:
        language = pycountry.languages.get(alpha_2=lang_code) or pycountry.languages.get(alpha_3=lang_code)
        if language:
            country = pycountry.countries.get(alpha_2=language.alpha_2.upper())
            if country:
                return country.alpha_2.lower()
    except KeyError:
        pass

    return lang_code  # Return the language code as-is if no mapping exists

#### Piracy.moe Start ####
def compress(data):
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def initialize_cipher(key, iv, adata, tagsize):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=tagsize)
    cipher.update(json_encode(adata))
    return cipher


class PrivateBin:
    def __init__(self, message):
        self._server = "https://piracy.moe"
        self._version = 2
        self._compression = 'zlib'
        self._data = ''
        self._password = ''
        self._formatter = 'plaintext'
        self._message = message
        self._expiration = "never"
        self._discussion = False
        self._burn_after_reading = False
        self._iteration_count = 100000
        self._salt_bytes = 8
        self._block_bits = 256
        self._tag_bits = 128
        self._key = get_random_bytes(int(self._block_bits / 8))

    def __get_hash(self):
        return b58encode(self._key).decode()

    def __derive_key(self, salt):
        return PBKDF2(
            self._key + self._password.encode(),
            salt,
            dkLen=int(self._block_bits / 8),
            count=self._iteration_count,
            prf=lambda password, salt: HMAC.new(
                password,
                salt,
                SHA256
            ).digest())

    def __encrypt(self):
        iv = get_random_bytes(int(self._tag_bits / 8))
        salt = get_random_bytes(self._salt_bytes)
        key = self.__derive_key(salt)

        adata = [
            [
                b64encode(iv).decode(),
                b64encode(salt).decode(),
                self._iteration_count,
                self._block_bits,
                self._tag_bits,
                'aes',
                'gcm',
                self._compression
            ],
            self._formatter,
            int(self._discussion),
            int(self._burn_after_reading)
        ]

        cipher_message = {
            'paste': self._message
        }

        cipher = initialize_cipher(key, iv, adata, int(self._tag_bits / 8))
        cipher_text, tag = cipher.encrypt_and_digest(compress(json_encode(cipher_message)))

        self._data = {
            'v': 2,
            'adata': adata,
            'ct': b64encode(cipher_text + tag).decode(),
            'meta': {
                'expire': self._expiration
            }
        }

    def create_post(self):
        session = requests.Session()
        self.__encrypt()
        result = session.post(
            url=self._server,
            headers={
                'X-Requested-With': 'JSONHttpRequest'
            },
            proxies={},
            data=json_encode(self._data).decode()
        )

        try:
            response = result.json()

            link = "{}?{}#{}".format(self._server,
                                     response['id'],
                                     self.__get_hash())

            return link
        except:
            print(traceback.format_exc())
            print("Error creating paste")


def create_private_bin_post(message):
    private_bin_instance = PrivateBin(message)
    return private_bin_instance.create_post()
#### Piracy.moe ENd ####
def get_media_language_info(file_path):
    """
    Extracts audio and subtitle language information from a media file using mediainfo.

    Args:
        file_path (str): Path to the media file.

    Returns:
        dict: Dictionary with audio and subtitle language info.
    """
    cmd = [
        "mediainfo",
        "--Output=JSON",
        file_path
    ]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        metadata = json.loads(result.stdout)

        audio_languages = []
        subtitle_languages = []
        video_resolution = None
        video_codec = None
        video_bit_depth = None
        duration = None
        # Navigate through the JSON structure to find audio and subtitle tracks
        for track in metadata.get("media", {}).get("track", []):
            if track.get("@type") == "Audio":
                language = track.get("Language", "unknown")
                country_code = get_country_code_from_language(language)
                audio_languages.append(country_code)
                
            elif track.get("@type") == "Text":
                language = track.get("Language", "unknown")
                country_code = get_country_code_from_language(language)
                subtitle_languages.append(country_code)
            elif track.get("@type") == "Video":
                video_resolution = track.get("Width", "unknown") + "x" + track.get("Height", "unknown")
                video_codec = track.get("Format", "unknown")
                video_bit_depth = track.get("BitDepth", "unknown")

                # Format the duration into "XX min XX s"
                duration = track.get("Duration", "unknown")
                if duration != "unknown":
                    duration = format_duration(float(duration))

        return {
            "audio_languages": audio_languages,
            "subtitle_languages": subtitle_languages,
            "video_resolution": video_resolution,
            "video_codec": video_codec,
            "video_bit_depth": video_bit_depth,
            "duration": duration
        }

    except subprocess.CalledProcessError as e:
        print(f"Error running mediainfo: {e.stderr.decode('utf-8')}")
        return {}
        
async def progress_callback(current, total, id, client: Client, file_path):
    global PROGRESS_CACHE, STOP_TRANSMISSION

    PROGRESS_CACHE[id] = ("running", current, total)
    if id in STOP_TRANSMISSION:
        logger.info(f"Stopping transmission {id}")
        client.stop_transmission()
        try:
            os.remove(file_path)
        except:
            pass



_headers = {"Referer": 'https://rentry.co'}

# Simple HTTP Session Client, keeps cookies
class UrllibClient:
    def __init__(self):
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        urllib.request.install_opener(self.opener)

    def get(self, url, headers={}):
        request = urllib.request.Request(url, headers=headers)
        return self._request(request)

    def post(self, url, data=None, headers={}):
        postdata = urllib.parse.urlencode(data).encode()
        request = urllib.request.Request(url, postdata, headers)
        return self._request(request)

    def _request(self, request):
        response = self.opener.open(request)
        response.status_code = response.getcode()
        response.data = response.read().decode('utf-8')
        return response

def create_paste(api_key, source_code):
    """
    Create a new paste on Pastebin.

    Parameters:
    api_key (str): Your Pastebin API key.
    source_code (str): The text to be pasted.

    Returns:
    str: The URL of the created paste.
    """
    # Define the API endpoint
    cfurl = "http://localhost:8191/v1"
    headers = {"Content-Type": "application/json"}
    dataz = {
        "api_dev_key": api_key,
        "api_paste_code": source_code,
        "cmd": "request.post",
        "url": f"https://pastebin.com/api/api_post.php",
        "api_option": 'paste',
        "maxTimeout": 60000
    }
    response = requests.post(cfurl, headers=headers, json=dataz)
    # Prepare the data to be sent to the API

    # Send a POST request to create a new paste
   # response = requests.post(url=API_ENDPOINT, data=data)

    # Return the URL of the created paste, formatted for raw access
    return response.text.replace("pastebin.com/", "pastebin.com/raw/")
def new(url, edit_code, text):
    client, cookie = UrllibClient(), SimpleCookie()
    cookie.load(vars(client.get('https://rentry.co'))['headers']['Set-Cookie'])
    csrftoken = cookie['csrftoken'].value

    payload = {
        'csrfmiddlewaretoken': csrftoken,
        'url': url,
        'edit_code': edit_code,
        'text': text
    }
    return json_loads(client.post('https://rentry.co/api/new', payload, headers=_headers).data)


def get_rentry_link(text):
    url, edit_code = '', 'Emina@69'
    response = new(url, edit_code, text)
    if response['status'] == '200':
        return f"{response['url']}/raw"
    else:
        raise Exception(f"Rentry API Error: {response['content']}")
        
def safe_get(attr, default="N/A"):
    """Safely get a value or return a default."""
    return attr[0] if attr else default
def format_media_info(fileName, size):
    try:
        # Run mediainfo commands
        mediainfo = subprocess.check_output(['mediainfo', fileName]).decode("utf-8")
        mediainfo_json = json.loads(
            subprocess.check_output(['mediainfo', fileName, '--Output=JSON']).decode("utf-8")
        )

        # Human-readable size
        readable_size = humanSize(size)

        # Update mediainfo details
        lines = mediainfo.splitlines()
        
        duration = float(mediainfo_json['media']['track'][0]['Duration'])
        bitrate_kbps = (size * 8) / (duration * 1000) 
        bitrate = humanBitrate(bitrate_kbps)

        for i in range(len(lines)):
            if 'File size' in lines[i]:
                lines[i] = re.sub(r": .+", f': {readable_size}', lines[i])
            elif 'Overall bit rate' in lines[i] and 'Overall bit rate mode' not in lines[i]:
                lines[i] = re.sub(r": .+", f': {bitrate}', lines[i])
            elif 'IsTruncated' in lines[i] or 'FileExtension_Invalid' in lines[i]:
                lines[i] = ''

        remove_N(lines)

        # Save updated mediainfo to a file
        txt_file = f'{fileName}.txt'
        with open(txt_file, 'w') as f:
            f.write('\n'.join(lines))
        boom =  open(txt_file, 'r')
        content = boom.read()
        print("SUBSTITLE END")
        if os.path.exists(txt_file):
            os.remove(txt_file)
    except Exception as e:
        print(f"Error processing file: {e}", flush=True)
    return content
    


async def start_file_uploader(file_path, id, directory_path, filename, file_size, uploader):
    global PROGRESS_CACHE
    from utils.directoryHandler import DRIVE_DATA

    logger.info(f"Uploading file {file_path} {id}")
    
    # Format media info using the provided function
    if filename.endswith(".mkv"):
        media_details = format_media_info(file_path, file_size)
        content = f"Media Info:\n\n{media_details}"
        api_key = "mZPtsfP1kPALQDyF56Qk1_exO1dIkWcR"  # Replace with your actual API key
        paste_url = create_private_bin_post(f"""Media Info:\n\n{media_details}""")
        print("The pastebin URL is:", paste_url)
        rentry_link = get_rentry_link(content)
        print(rentry_link)
        infox = get_media_language_info(file_path)
        audio = infox.get("audio_languages")
        print("Audio Languages:", infox.get("audio_languages"))
        subtitle = infox.get("subtitle_languages")
        print("Subtitle Languages:", infox.get("subtitle_languages"))
        resolution = infox.get("video_resolution")
        print("Video Resolution:", infox.get("video_resolution"))
        codec = infox.get("video_codec")
        print("Video Codec:", infox.get("video_codec"))
        bit_depth = infox.get("video_bit_depth")
        print("Video Bit Depth:", infox.get("video_bit_depth"))
        duration = infox.get("duration")
        print("Duration:", infox.get("duration"))
        
    elif filename.endswith(".mp4"):
        media_details = format_media_info(file_path, file_size)
        content = f"Media Info:\n\n{media_details}"
        api_key = "mZPtsfP1kPALQDyF56Qk1_exO1dIkWcR"  # Replace with your actual API key
        paste_url = create_private_bin_post(f"""Media Info:\n\n{media_details}""")
        print("The pastebin URL is:", paste_url)
        rentry_link = get_rentry_link(content)
        print(rentry_link)
        infox = get_media_language_info(file_path)
        audio = infox.get("audio_languages")
        print("Audio Languages:", infox.get("audio_languages"))
        subtitle = infox.get("subtitle_languages")
        print("Subtitle Languages:", infox.get("subtitle_languages"))
        resolution = infox.get("video_resolution")
        print("Video Resolution:", infox.get("video_resolution"))
        codec = infox.get("codec")
        print("Video Codec:", infox.get("video_codec"))
        bit_depth = infox.get("video_bit_depth")
        print("Video Bit Depth:", infox.get("video_bit_depth"))
        duration = infox.get("duration")
        print("Duration:", infox.get("duration"))
    else:
        rentry_link = "https://rentry.co/404"

    # Select appropriate client based on file size
    if file_size > 1.98 * 1024 * 1024 * 1024:
        client: Client = get_client(premium_required=True)
    else:
        client: Client = get_client()

    PROGRESS_CACHE[id] = ("running", 0, 0)

    # Upload the file and save its metadata
    message: Message = await client.send_document(
        STORAGE_CHANNEL,
        file_path,
        progress=progress_callback,
        progress_args=(id, client, file_path),
        disable_notification=True,
    )
    size = (
        message.photo
        or message.document
        or message.video
        or message.audio
        or message.sticker
    ).file_size

    filename = unquote_plus(filename)

    DRIVE_DATA.new_file(directory_path, filename, message.id, size, rentry_link, paste_url, uploader, audio, subtitle, resolution, codec, bit_depth, duration)
    PROGRESS_CACHE[id] = ("completed", size, size)

    if os.path.exists(file_path):
        os.remove(file_path)
 #   except Exception as e:
     #   logger.error(f"Failed to remove file {file_path}: {e}")

    logger.info(f"Uploaded file {file_path} {id}")
