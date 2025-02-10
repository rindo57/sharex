import asyncio
from pyrogram import Client, filters
from pyrogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
import config
from utils.logger import Logger
from pathlib import Path
import os
import aiohttp, asyncio
from http.cookies import SimpleCookie
from json import loads as json_loads
import urllib.parse
import urllib.request
import http.cookiejar
import requests
import json
import re
import subprocess
from utils.humanFunctions import humanBitrate, humanSize, remove_N
from utils.uploader import create_private_bin_post
logger = Logger(__name__)

START_CMD = """🚀 **Welcome To AniDL Drive's Bot Mode**

You can use this bot to upload files to your AniDL Drive website directly instead of doing it from website.

🗄 **Commands:**
/set_folder - Set folder for file uploads
/current_folder - Check current folder

📤 **How To Upload Files:** Send a file to this bot and it will be uploaded to your TG Drive website. You can also set a folder for file uploads using /set_folder command.
"""

SET_FOLDER_PATH_CACHE = {}  # Cache to store folder path for each folder id
DRIVE_DATA = None
BOT_MODE = None

session_cache_path = Path(f"./cache")
session_cache_path.parent.mkdir(parents=True, exist_ok=True)

main_bot = Client(
    name="main_bot",
    api_id=config.API_ID,
    api_hash=config.API_HASH,
    bot_token=config.MAIN_BOT_TOKEN,
    sleep_threshold=config.SLEEP_THRESHOLD,
    workdir=session_cache_path,
)


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
        
@main_bot.on_message(
    filters.command(["start", "help"])
    & filters.private
    & filters.user(config.TELEGRAM_ADMIN_IDS),
)
async def start_handler(client: Client, message: Message):
    await message.reply_text(START_CMD)


@main_bot.on_message(
    filters.command("set_folder")
    & filters.private
    & filters.user(config.TELEGRAM_ADMIN_IDS),
)

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
        
async def set_folder_handler(client: Client, message: Message):
    global SET_FOLDER_PATH_CACHE, DRIVE_DATA

    while True:
        try:
            folder_name = await message.ask(
                "Send the folder name where you want to upload files\n\n/cancel to cancel",
                timeout=60,
                filters=filters.text,
            )
        except asyncio.TimeoutError:
            await message.reply_text("Timeout\n\nUse /set_folder to set folder again")
            return

        if folder_name.text.lower() == "/cancel":
            await message.reply_text("Cancelled")
            return

        folder_name = folder_name.text.strip()
        search_result = DRIVE_DATA.search_file_folderx(folder_name)

        # Get folders from search result
        folders = {}
        for item in search_result.values():
            if item.type == "folder":
                folders[item.id] = item

        if len(folders) == 0:
            await message.reply_text(f"No Folder found with name {folder_name}")
        else:
            break

    buttons = []
    folder_cache = {}
    folder_cache_id = len(SET_FOLDER_PATH_CACHE) + 1

    for folder in search_result.values():
        path = folder.path.strip("/")
        folder_path = "/" + ("/" + path + "/" + folder.id).strip("/")
        folder_cache[folder.id] = (folder_path, folder.name)
        buttons.append(
            [
                InlineKeyboardButton(
                    folder.name,
                    callback_data=f"set_folder_{folder_cache_id}_{folder.id}",
                )
            ]
        )
    SET_FOLDER_PATH_CACHE[folder_cache_id] = folder_cache

    await message.reply_text(
        "Select the folder where you want to upload files",
        reply_markup=InlineKeyboardMarkup(buttons),
    )


@main_bot.on_callback_query(
    filters.user(config.TELEGRAM_ADMIN_IDS) & filters.regex(r"set_folder_")
)
async def set_folder_callback(client: Client, callback_query: Message):
    global SET_FOLDER_PATH_CACHE, BOT_MODE

    folder_cache_id, folder_id = callback_query.data.split("_")[2:]

    folder_path_cache = SET_FOLDER_PATH_CACHE.get(int(folder_cache_id))
    if folder_path_cache is None:
        await callback_query.answer("Request Expired, Send /set_folder again")
        await callback_query.message.delete()
        return

    folder_path, name = folder_path_cache.get(folder_id)
    del SET_FOLDER_PATH_CACHE[int(folder_cache_id)]
    BOT_MODE.set_folder(folder_path, name)

    await callback_query.answer(f"Folder Set Successfully To : {name}")
    await callback_query.message.edit(
        f"Folder Set Successfully To : {name}\n\nNow you can send / forward files to me and it will be uploaded to this folder."
    )


@main_bot.on_message(
    filters.command("current_folder")
    & filters.private
    & filters.user(config.TELEGRAM_ADMIN_IDS),
)
async def current_folder_handler(client: Client, message: Message):
    global BOT_MODE

    await message.reply_text(f"Current Folder: {BOT_MODE.current_folder_name}")


# Handling when any file is sent to the bot
@main_bot.on_message(
    filters.private
    & filters.user(config.TELEGRAM_ADMIN_IDS)
    & (
        filters.document
        | filters.video
        | filters.audio
        | filters.photo
    )
)
async def file_handler(client: Client, message: Message):
    global BOT_MODE, DRIVE_DATA
    ADMIN_TELEGRAM_ID = str(message.from_user.id)
    if ADMIN_TELEGRAM_ID=="1498366357":
        uploader="Diablo"
    elif ADMIN_TELEGRAM_ID=="162010513":
        uploader="Knightking"
    elif ADMIN_TELEGRAM_ID=="590009569":
        uploader="IAMZERO"
    elif ADMIN_TELEGRAM_ID=="418494071":
        uploader="Rain"
    elif ADMIN_TELEGRAM_ID=="1863307059":
        uploader="XenZen"
    elif ADMIN_TELEGRAM_ID=="6542409825":
        uploader="Mr.Born2Help"
    elif ADMIN_TELEGRAM_ID=="5419097944":
        uploader="IAMZERO"



    # Determine media type
    mediaType = message.media.value
    if mediaType == 'video':
        media = message.video
    elif mediaType == 'audio':
        media = message.audio
    elif mediaType == 'document':
        media = message.document
    else:
        print("This media type is not supported", flush=True)
        raise Exception("`This media type is not supported`")

    # Extract file details
    mime = media.mime_type
    fileName = media.file_name
    size = media.file_size

    print(fileName, size, flush=True)

    # Validate document type
    if mediaType == 'document' and all(x not in mime for x in ['video', 'audio', 'image']):
        print("Makes no sense", flush=True)
        raise Exception("`This file makes no sense to me.`")

    # Download or stream the file

    async for chunk in client.stream_media(message, limit=5):
        with open(fileName, 'ab') as f:
            f.write(chunk)

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
        if 'image' not in mime:
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
        print(content)
        rentry_link = get_rentry_link(content)
        paste_url = create_private_bin_post(f"""Media Info:\n\n{content}""")
        # Send the file back as a document
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
        file = (
            copied_message.document
            or copied_message.video
            or copied_message.audio
            or copied_message.photo
            or copied_message.sticker
        )

        DRIVE_DATA.new_file(
            BOT_MODE.current_folder,
            file.file_name,
            copied_message.id,
            file.file_size,
            rentry_link,
            paste_url,
            uploader,
            audio, 
            subtitle, 
            resolution, 
            codec, 
            bit_depth, 
            duration
        )

        await message.reply_text(
            f"""✅ File Uploaded Successfully To Your H!-Drive Website
                             
    **File Name:** {file.file_name}
    **Folder:** {BOT_MODE.current_folder_name}
    """
        )


    except Exception as e:
        await message.reply_text("MediaInfo generation failed! Something bad occurred particularly with this file.")
        print(f"Error processing file: {e}", flush=True)

    finally:
        # Cleanup
        if os.path.exists(fileName):
            os.remove(fileName)
        if os.path.exists(txt_file):
            os.remove(txt_file)
    copied_message = await message.copy(config.STORAGE_CHANNEL)
    file = (
        copied_message.document
        or copied_message.video
        or copied_message.audio
        or copied_message.photo
        or copied_message.sticker
    )

    DRIVE_DATA.new_file(
        BOT_MODE.current_folder,
        file.file_name,
        copied_message.id,
        file.file_size,
        rentry_link,
        paste_url,
        uploader,
        audio, 
        subtitle, 
        resolution, 
        codec, 
        bit_depth, 
        duration
    )

    await message.reply_text(
        f"""✅ File Uploaded Successfully To Your TG Drive Website
                             
**File Name:** {file.file_name}
**Folder:** {BOT_MODE.current_folder_name}
"""
    )

async def send_magic(ADMIN_TELEGRAM_ID, magic_link):
    x = await main_bot.send_message(
        chat_id= int(ADMIN_TELEGRAM_ID), text=f"Click the below link to log in:\n\n{magic_link}\n\n`ABOVE LINK WILL EXPIRE AFTER 3 MINS`\n\n*__This message will self-destruct after 3 mins__"
    )
    await asyncio.sleep(180)
    await x.delete()

async def start_bot_mode(d, b):
    global DRIVE_DATA, BOT_MODE
    DRIVE_DATA = d
    BOT_MODE = b

    logger.info("Starting Main Bot")
    await main_bot.start()

    await main_bot.send_message(
        config.STORAGE_CHANNEL, "Main Bot Started -> AniDL Drive's Bot Mode Enabled"
    )
    logger.info("Main Bot Started")
    logger.info("TG Drive's Bot Mode Enabled")
