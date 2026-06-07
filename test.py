# Standard Library
import asyncio
import datetime as dt

# Pip imports
import aiohttp

async def get_verseofday(day: int, uri: str, headers: dict, bible: int = 111):
    vod_endpoint = f"/v1/verse_of_the_days/{day}"

    # get scripture shorthand
    try:
        vod_url = uri + vod_endpoint
        async with aiohttp.ClientSession() as session:
            async with session .get(vod_url, headers=headers) as vod_response:
                vod_response.raise_for_status()
                vod_json = vod_response.json()

        passage_endpoint = f"/v1/bibles/{bible}/passages/{vod_json['passage_id']}?format=html&include_headings=1&include_notes=1"

        passage_url = uri + passage_endpoint

        passage_response = aiohttp.get(passage_url, headers=headers)

        passage_response.raise_for_status()

        passage_json = passage_response.json()

        print(passage_json)
    except Exception as err:
        print(err)

if __name__ == '__main__':
    headers = {
        'x-yvp-app-key': 'xh3B7B1DPj38QihYqExcd6ljQIIG06YhCpyqrSzm7yKTLaCh',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    base_uri = 'https://api.youversion.com'

    day_of_year = int(dt.datetime.now().strftime('%j'))

    asyncio.run(get_verseofday(day_of_year, base_uri, headers))