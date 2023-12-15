# Copyright 2023, CS GROUP - France, https://www.csgroup.eu/
#
# This file is part of GeojsonProxy project
#     https://gitlab.si.c-s.fr/space_applications/geojsonproxy/
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import csv
import io
import json
from collections.abc import Callable
from socket import AF_INET
from zipfile import ZipFile

import aiohttp
import xmltodict
from fastapi import HTTPException

SIZE_POOL_AIOHTTP = 100


class Unzippr:
    def __init__(self, response, filename, encoding="utf-8"):
        self.response = response
        self.filename = filename
        self.encoding = encoding

    async def text(self):
        with ZipFile(io.BytesIO(await self.response.read()), "r") as handle:
            # return io.TextIOWrapper(handle.open(self.filename),
            #     encoding=self.encoding)
            return handle.read(self.filename).decode(self.encoding)


class SingletonAiohttp:
    aiohttp_client: aiohttp.ClientSession = None

    @classmethod
    def get_aiohttp_client(cls) -> aiohttp.ClientSession:
        if cls.aiohttp_client is None:
            timeout = aiohttp.ClientTimeout(total=20)
            connector = aiohttp.TCPConnector(
                family=AF_INET, limit_per_host=SIZE_POOL_AIOHTTP
            )
            cls.aiohttp_client = aiohttp.ClientSession(
                timeout=timeout, connector=connector
            )

        return cls.aiohttp_client

    @classmethod
    async def close_aiohttp_client(cls):
        if cls.aiohttp_client:
            await cls.aiohttp_client.close()
            cls.aiohttp_client = None

    @classmethod
    async def query_url(
        cls,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        payload: bytes | None = None,
        interceptor: Callable | None = None,
    ):
        client = cls.get_aiohttp_client()
        json_result = []
        async with client.request(
            method, url, headers=headers, data=payload
        ) as response:
            if int(response.status / 100) != 2:
                raise HTTPException(
                    status_code=500,
                    detail="Error when accessing external service - "
                    + str(await response.text()),
                )

            contenttype = response.headers.get("Content-Type").lower()

            # If its zipped : unzip
            # TODO : Stream content
            if contenttype.startswith("application/zip"):
                filename = url.partition("#")[-1]
                response = Unzippr(response, filename)
                if filename.lower().endswith("csv"):
                    contenttype = "text/csv"

            content = await response.text()
            if interceptor:
                content = interceptor(content)

            # Convert JSON, CSV, XML in a common pivot format using Python Dict
            if contenttype.startswith("text/xml"):
                json_result = xmltodict.parse(content)
            elif contenttype.startswith("text/csv"):
                data = csv.reader(io.StringIO(content), delimiter=";")
                json_result = list(data)
                # json_result.extend(list(data))
                # for row in data:
                #    json_result.append(row)
            else:
                json_result = json.loads(content)

        return json_result
