# -*- coding: utf-8 -*-

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

"""Extractors for https://www.facebook.com/"""

import json
import asyncio
from time import time
from concurrent.futures import ThreadPoolExecutor
from .common import Extractor, Message
from .. import text, exception
from loguru import logger as log

BASE_PATTERN = r"(?:https?://)?(?:[\w-]+\.)?facebook\.com"


class FacebookExtractor(Extractor):
    """Base class for Facebook extractors"""

    category = "facebook"
    root = "https://www.facebook.com"
    directory_fmt = ("{category}", "{username}", "{title} ({set_id})")
    filename_fmt = "{id}.{extension}"
    archive_fmt = "{id}.{extension}"

    set_url_fmt = root + "/media/set/?set={set_id}"
    photo_url_fmt = root + "/photo/?fbid={photo_id}&set={set_id}"

    def _init(self):
        headers = self.session.headers
        headers["Accept"] = (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"
        )
        headers["Sec-Fetch-Dest"] = "empty"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "same-origin"

        self.fallback_retries = self.config("fallback-retries", 2)
        self.videos = self.config("videos", True)
        self.author_followups = self.config("author-followups", False)

    @staticmethod
    def decode_all(txt):
        return text.unescape(
            txt.encode()
            .decode("unicode_escape")
            .encode("utf_16", "surrogatepass")
            .decode("utf_16")
        ).replace("\\/", "/")

    @staticmethod
    def parse_set_page(set_page):
        directory = {
            "set_id": text.extr(set_page, '"mediaSetToken":"', '"')
            or text.extr(set_page, '"mediasetToken":"', '"'),
            "username": FacebookExtractor.decode_all(
                text.extr(set_page, '"user":{"__isProfile":"User","name":"', '","')
                or text.extr(set_page, '"actors":[{"__typename":"User","name":"', '","')
            ),
            "user_id": text.extr(set_page, '"owner":{"__typename":"User","id":"', '"'),
            "title": FacebookExtractor.decode_all(
                text.extr(set_page, '"title":{"text":"', '"')
            ),
            "first_photo_id": text.extr(
                set_page,
                '{"__typename":"Photo","__isMedia":"Photo","',
                '","creation_story"',
            ).rsplit('"id":"', 1)[-1]
            or text.extr(set_page, '{"__typename":"Photo","id":"', '"'),
        }

        return directory

    @staticmethod
    def parse_photo_page(photo_page):
        photo = {
            "id": text.extr(photo_page, '"__isNode":"Photo","id":"', '"'),
            "set_id": text.extr(
                photo_page, '"url":"https:\\/\\/www.facebook.com\\/photo\\/?fbid=', '"'
            ).rsplit("&set=", 1)[-1],
            "username": FacebookExtractor.decode_all(
                text.extr(photo_page, '"owner":{"__typename":"User","name":"', '"')
            ),
            "user_id": text.extr(
                photo_page, '"owner":{"__typename":"User","id":"', '"'
            ),
            "caption": FacebookExtractor.decode_all(
                text.extr(
                    photo_page,
                    '"message":{"delight_ranges"',
                    '"},"message_preferred_body"',
                ).rsplit('],"text":"', 1)[-1]
            ),
            "date": text.parse_timestamp(
                text.extr(photo_page, '\\"publish_time\\":', ",")
                or text.extr(photo_page, '"created_time":', ",")
            ),
            "url": FacebookExtractor.decode_all(
                text.extr(photo_page, ',"image":{"uri":"', '","')
            ),
            "next_photo_id": text.extr(
                photo_page, '"nextMediaAfterNodeId":{"__typename":"Photo","id":"', '"'
            )
            or text.extr(
                photo_page,
                '"nextMedia":{"edges":[{"node":{"__typename":"Photo","id":"',
                '"',
            ),
        }

        text.nameext_from_url(photo["url"], photo)

        photo["followups_ids"] = []
        times = []
        for comment_raw in text.extract_iter(
            photo_page, '{"node":{"id"', '"cursor":null}'
        ):
            if (
                '"is_author_original_poster":true' in comment_raw
                and '{"__typename":"Photo","id":"' in comment_raw
            ):
                photo["followups_ids"].append(
                    text.extr(comment_raw, '{"__typename":"Photo","id":"', '"')
                )
            times.append(
                text.parse_timestamp(text.extr(comment_raw, '"created_time":', ',"'))
            )

        texts = list(text.extract_iter(photo_page, 'body":{"text":"', '","ranges"'))
        authors = [
            json.loads(x)["name"]
            for x in list(text.extract_iter(photo_page, '"author":', ',"is_author'))
        ]
        comments = [
            {
                "author": a,
                "text": t,
                "date": d,
            }
            for a, t, d in zip(authors, texts, times)
            if t
        ]
        if comments:
            photo["comments"] = comments
        return photo

    @staticmethod
    def parse_post_page(post_page):
        first_photo_url = text.extr(
            text.extr(post_page, '"__isMedia":"Photo"', '"target_group"'),
            '"url":"',
            ",",
        )

        post = {
            "set_id": text.extr(post_page, '{"mediaset_token":"', '"')
            or text.extr(first_photo_url, "set=", '"').rsplit("&", 1)[0]
        }

        return post

    @staticmethod
    def parse_video_page(video_page):
        video = {
            "id": text.extr(video_page, '\\"video_id\\":\\"', '\\"'),
            "username": FacebookExtractor.decode_all(
                text.extr(video_page, '"actors":[{"__typename":"User","name":"', '","')
            ),
            "user_id": text.extr(
                video_page, '"owner":{"__typename":"User","id":"', '"'
            ),
            "date": text.parse_timestamp(
                text.extr(video_page, '\\"publish_time\\":', ",")
            ),
            "type": "video",
        }

        if not video["username"]:
            video["username"] = FacebookExtractor.decode_all(
                text.extr(
                    video_page,
                    '"__typename":"User","id":"' + video["user_id"] + '","name":"',
                    '","',
                )
            )

        first_video_raw = text.extr(
            video_page, '"permalink_url"', "\\/Period>\\u003C\\/MPD>"
        )

        audio = {
            **video,
            "url": FacebookExtractor.decode_all(
                text.extr(
                    text.extr(
                        first_video_raw, "AudioChannelConfiguration", "BaseURL>\\u003C"
                    ),
                    "BaseURL>",
                    "\\u003C\\/",
                )
            ),
            "type": "audio",
        }

        video["urls"] = {}

        for raw_url in text.extract_iter(
            first_video_raw, 'FBQualityLabel=\\"', "\\u003C\\/BaseURL>"
        ):
            resolution = raw_url.split('\\"', 1)[0]
            video["urls"][resolution] = FacebookExtractor.decode_all(
                raw_url.split("BaseURL>", 1)[1]
            )

        if not video["urls"]:
            return video, audio

        video["url"] = max(
            video["urls"].items(), key=lambda x: text.parse_int(x[0][:-1])
        )[1]

        text.nameext_from_url(video["url"], video)
        audio["filename"] = video["filename"]
        audio["extension"] = "m4a"

        return video, audio

    def photo_page_request_wrapper(self, url, **kwargs):
        LEFT_OFF_TXT = (
            ""
            if url.endswith("&set=")
            else (
                "\nYou can use this URL to continue from "
                'where you left off (added "&setextract"): '
                "\n" + url + "&setextract"
            )
        )

        res = self.request(url, **kwargs)

        if res.url.startswith(self.root + "/login"):
            raise exception.AuthenticationError(
                "You must be logged in to continue viewing images." + LEFT_OFF_TXT
            )

        if b'{"__dr":"CometErrorRoot.react"}' in res.content:
            raise exception.StopExtraction(
                "You've been temporarily blocked from viewing images. "
                "\nPlease try using a different account, "
                "using a VPN or waiting before you retry." + LEFT_OFF_TXT
            )

        return res

    def extract_set(self, set_data):
        set_id = set_data["set_id"]
        all_photo_ids = [set_data["first_photo_id"]]

        retries = 0
        i = 0

        while i < len(all_photo_ids):
            photo_id = all_photo_ids[i]
            photo_url = self.photo_url_fmt.format(photo_id=photo_id, set_id=set_id)
            photo_page = self.photo_page_request_wrapper(photo_url).text

            photo = self.parse_photo_page(photo_page)
            photo["num"] = i + 1

            if self.author_followups:
                for followup_id in photo["followups_ids"]:
                    if followup_id not in all_photo_ids:
                        self.log.debug("Found a followup in comments: %s", followup_id)
                        all_photo_ids.append(followup_id)

            if not photo["url"]:
                if retries < self.fallback_retries and self._interval_429:
                    seconds = self._interval_429()
                    self.log.warning(
                        "Failed to find photo download URL for %s. "
                        "Retrying in %s seconds.",
                        photo_url,
                        seconds,
                    )
                    self.wait(seconds=seconds, reason="429 Too Many Requests")
                    retries += 1
                    continue
                else:
                    self.log.error(
                        "Failed to find photo download URL for "
                        + photo_url
                        + ". Skipping."
                    )
                    retries = 0
            else:
                retries = 0
                photo.update(set_data)
                yield Message.Directory, photo
                yield Message.Url, photo["url"], photo

            if not photo["next_photo_id"]:
                self.log.debug(
                    "Can't find next image in the set. " "Extraction is over."
                )
            elif photo["next_photo_id"] in all_photo_ids:
                if photo["next_photo_id"] != photo["id"]:
                    self.log.debug(
                        "Detected a loop in the set, it's likely finished. "
                        "Extraction is over."
                    )
            else:
                all_photo_ids.append(photo["next_photo_id"])

            i += 1


class FacebookSetExtractor(FacebookExtractor):
    """Base class for Facebook Set extractors"""

    subcategory = "set"
    pattern = (
        BASE_PATTERN + r"/(?:(?:media/set|photo)/?\?(?:[^&#]+&)*set=([^&#]+)"
        r"[^/?#]*(?<!&setextract)$"
        r"|([^/?#]+/posts/[^/?#]+)"
        r"|photo/\?(?:[^&#]+&)*fbid=([^/?&#]+)&set=([^/?&#]+)&setextract)"
    )
    example = "https://www.facebook.com/media/set/?set=SET_ID"

    def items(self):
        set_id = self.groups[0] or self.groups[3]
        path = self.groups[1]
        if path:
            post_url = self.root + "/" + path
            post_page = self.request(post_url).text
            set_id = self.parse_post_page(post_page)["set_id"]

        set_url = self.set_url_fmt.format(set_id=set_id)
        set_page = self.request(set_url).text
        set_data = self.parse_set_page(set_page)
        if self.groups[2]:
            set_data["first_photo_id"] = self.groups[2]

        return self.extract_set(set_data)


class FacebookPhotoExtractor(FacebookExtractor):
    """Base class for Facebook Photo extractors"""

    subcategory = "photo"
    pattern = (
        BASE_PATTERN + r"/(?:[^/?#]+/photos/[^/?#]+/|photo(?:.php)?/?\?"
        r"(?:[^&#]+&)*fbid=)([^/?&#]+)[^/?#]*(?<!&setextract)$"
    )
    example = "https://www.facebook.com/photo/?fbid=PHOTO_ID"

    def items(self):
        photo_id = self.groups[0]
        photo_url = self.photo_url_fmt.format(photo_id=photo_id, set_id="")
        photo_page = self.photo_page_request_wrapper(photo_url).text

        i = 1
        photo = self.parse_photo_page(photo_page)
        photo["num"] = i

        set_page = self.request(self.set_url_fmt.format(set_id=photo["set_id"])).text

        directory = self.parse_set_page(set_page)

        yield Message.Directory, directory
        yield Message.Url, photo["url"], photo

        if self.author_followups:
            for comment_photo_id in photo["followups_ids"]:
                comment_photo = self.parse_photo_page(
                    self.photo_page_request_wrapper(
                        self.photo_url_fmt.format(photo_id=comment_photo_id, set_id="")
                    ).text
                )
                i += 1
                comment_photo["num"] = i
                yield Message.Url, comment_photo["url"], comment_photo


class FacebookVideoExtractor(FacebookExtractor):
    """Base class for Facebook Video extractors"""

    subcategory = "video"
    directory_fmt = ("{category}", "{username}", "{subcategory}")
    pattern = BASE_PATTERN + r"/(?:[^/?#]+/videos/|watch/?\?v=)([^/?&#]+)"
    example = "https://www.facebook.com/watch/?v=VIDEO_ID"

    def items(self):
        video_id = self.groups[0]
        video_url = self.root + "/watch/?v=" + video_id
        video_page = self.request(video_url).text

        video, audio = self.parse_video_page(video_page)

        if "url" not in video:
            return

        yield Message.Directory, video

        if self.videos == "ytdl":
            yield Message.Url, "ytdl:" + video_url, video
        elif self.videos:
            yield Message.Url, video["url"], video
            if audio["url"]:
                yield Message.Url, audio["url"], audio


class FacebookProfileExtractor(FacebookExtractor):
    """Base class for Facebook Profile Photos Set extractors"""

    subcategory = "profile"
    pattern = (
        BASE_PATTERN + r"/(?!media/|photo/|photo.php|watch/)"
        r"(?:profile\.php\?id=|people/[^/?#]+/)?"
        r"([^/?&#]+)(?:/photos(?:_by)?|/videos|/posts)?/?(?:$|\?|#)"
    )
    example = "https://www.facebook.com/USERNAME"

    @staticmethod
    def get_profile_photos_set_id(profile_photos_page):
        set_ids_raw = text.extr(profile_photos_page, '"pageItems"', '"page_info"')

        set_id = text.extr(set_ids_raw, "set=", '"').rsplit("&", 1)[0] or text.extr(
            set_ids_raw, "\\/photos\\/", "\\/"
        )

        return set_id

    def items(self):
        profile_photos_url = self.root + "/" + self.groups[0] + "/photos_by"
        profile_photos_page = self.request(profile_photos_url).text

        set_id = self.get_profile_photos_set_id(profile_photos_page)

        if set_id:
            set_url = self.set_url_fmt.format(set_id=set_id)
            set_page = self.request(set_url).text
            set_data = self.parse_set_page(set_page)
            return self.extract_set(set_data)

        self.log.debug("Profile photos set ID not found.")
        return iter(())


class FacebookCommentExtractor(FacebookExtractor):
    """Base class for Facebook Profile Photos Set extractors"""

    subcategory = "comments"
    pattern = BASE_PATTERN + r"/groups/([^/?&#]+)/posts/([^/?&#]+)"
    example = "https://www.facebook.com/groups/238620256823178/posts/1693941581291031"
    expansion_key = "__cft__[1]="
    suffix_key = "__tn__=R-R"

    def extract_comments(self, user_info, content, comments_queue, timestamp):
        # Check if we're using proxies to decide between async and sync processing
        use_async = self._should_use_async_processing()

        if use_async:
            # Use async processing with asyncio.gather
            return self._extract_comments_async(
                user_info, content, comments_queue, timestamp
            )
        else:
            # Use synchronous processing (original method)
            return self._extract_comments_sync(
                user_info, content, comments_queue, timestamp
            )

    def _should_use_async_processing(self):
        """Determine if we should use async processing based on proxy configuration"""
        # Check if proxies are configured
        proxies = self._proxies
        proxy_enabled = proxies and any(proxies.values())

        # Check if parallel comments is explicitly enabled
        parallel_enabled = self.config("parallel-comments", False)

        use_async = proxy_enabled or parallel_enabled

        log.info(
            f"Async processing decision: proxies={proxy_enabled}, parallel_comments={parallel_enabled}, use_async={use_async}"
        )
        if proxy_enabled:
            log.debug(f"Proxies configured: {proxies}")

        return use_async

    def _extract_comments_sync(self, user_info, content, comments_queue, timestamp):
        """Synchronous comment extraction (original implementation)"""
        post_comments, comments_ids = [], set()
        comments_limit = self.config("comments-limit", 10)
        i = 0

        while i < len(comments_queue):
            start = time()
            comment_data = comments_queue[i]["node"]
            self.fetch_additional_comments(comment_data, comments_queue)
            doc = self.parse_comment_data(comment_data)
            if doc["id"] and doc["id"] in comments_ids:
                i += 1
                continue
            if not doc["id"]:
                raise exception.StopExtraction(
                    "This post does not have comments or is not accessible."
                )
            comments_ids.add(doc["id"])
            comment_data = self.reload_comment(
                [doc["id"]], comments_queue
            )  # must be reloaded to have inner edges
            inner_comments = comment_data["feedback"]["replies_connection"]["edges"]
            doc["replies"] = self._process_nested_replies(
                [doc["id"]], inner_comments, comments_ids, comments_queue
            )
            post_comments.append(doc)
            i = 0
            log.debug(
                f"Processed comment {len(post_comments)}: {doc['id']} in {time() - start:.2f} seconds"
            )
            if len(post_comments) >= comments_limit:
                break

        yield Message.Directory, user_info.update(
            {
                "content": content,
                "comments": post_comments,
                "timestamp": timestamp,
            }
        )

    def _extract_comments_async(self, user_info, content, comments_queue, timestamp):
        """Asynchronous comment extraction using asyncio.gather"""
        log.info("Starting async comment extraction")

        # Run the async extraction in the event loop
        try:
            # Try to get the current running loop
            loop = asyncio.get_running_loop()
            log.debug("Already in an event loop, running in thread pool")
            # If we're already in a loop, we need to run in a new thread
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    asyncio.run, self._async_process_comments(comments_queue)
                )
                post_comments = future.result()
        except RuntimeError:
            # No running loop, safe to create and run
            log.debug("No event loop found, creating new one")
            post_comments = asyncio.run(self._async_process_comments(comments_queue))

        log.info(
            f"Async comment extraction completed, processed {len(post_comments)} comments"
        )
        yield Message.Directory, user_info.update(
            {
                "content": content,
                "comments": post_comments,
                "timestamp": timestamp,
            }
        )

    async def _async_process_comments(self, comments_queue):
        """Process comments asynchronously with dynamic queue growth"""
        log.info(f"Starting async processing of {len(comments_queue)} comments")
        post_comments, comments_ids = [], set()
        comments_limit = self.config("comments-limit", 10)
        max_workers = self.config("max-workers", 10)
        processed_indices = set()

        log.debug(f"Config: comments_limit={comments_limit}, max_workers={max_workers}")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            iteration = 0
            while len(post_comments) < comments_limit:
                start = time()
                iteration += 1
                current_queue_size = len(comments_queue)
                log.debug(
                    f"Iteration {iteration}: queue_size={current_queue_size}, processed={len(processed_indices)}, results={len(post_comments)}"
                )

                # Create tasks for unprocessed comments
                tasks = []
                for i in range(current_queue_size):
                    comment_data = comments_queue[i]["node"]
                    if (
                        comment_data["legacy_fbid"] not in comments_ids
                        and len(post_comments) + len(tasks) < comments_limit
                    ):
                        task = asyncio.create_task(
                            self._async_process_single_comment(
                                executor, comment_data, comments_queue, comments_ids, i
                            )
                        )
                        tasks.append((task, i))

                if not tasks:
                    log.debug("No more tasks to process, breaking")
                    break

                log.debug(f"Created {len(tasks)} tasks for processing")

                # Wait for all tasks to complete
                results = await asyncio.gather(
                    *[task for task, _ in tasks], return_exceptions=True
                )
                log.debug(f"Completed {len(results)} tasks")

                # Process results
                successful_results = 0
                for (task, i), result in zip(tasks, results):
                    processed_indices.add(i)

                    if isinstance(result, Exception):
                        log.warning(f"Failed to process comment {i}: {result}")
                        continue

                    if result and result["id"] and result["id"] not in comments_ids:
                        reply_count = self.count_replies(result)
                        post_comments.append(result)
                        comments_ids.add(result["id"])
                        successful_results += 1
                        if reply_count > 0:
                            log.debug(
                                f"Comment {result['id']} has {reply_count} total replies"
                            )

                log.info(
                    f"Iteration {iteration} complete in {time() - start:.2f}: {successful_results} new comments processed, total: {len(post_comments)}"
                )

                # Check if queue has grown (new comments were fetched)
                if (
                    len(post_comments) == current_queue_size
                    and len(comments_queue) == current_queue_size
                ):
                    # No new comments, break the loop
                    log.debug("Queue size unchanged, no new comments fetched")
                    break

        log.info(f"Async processing complete: {len(post_comments)} comments processed")
        return post_comments[:comments_limit]

    async def _async_process_single_comment(
        self, executor, comment_data, comments_queue, comments_ids, index
    ):
        """Process a single comment asynchronously"""
        # start_time = time()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # Fallback for older Python versions
            loop = asyncio.get_event_loop()

        try:
            # log.debug(f"Starting to process comment {index}")

            # Fetch additional comments in thread pool to avoid blocking
            await loop.run_in_executor(
                executor, self.fetch_additional_comments, comment_data, comments_queue
            )

            # Parse comment data
            doc = await loop.run_in_executor(
                executor, self.parse_comment_data, comment_data
            )

            if not doc["id"]:
                log.debug(f"Comment {index} has no ID, skipping")
                return None

            if doc["id"] in comments_ids:
                log.debug(f"Comment {index} ({doc['id']}) already processed, skipping")
                return None

            # Reload comment to get inner edges
            comment_data_reloaded = await loop.run_in_executor(
                executor, self.reload_comment, [doc["id"]], comments_queue
            )

            # Process nested replies asynchronously
            inner_comments = (
                comment_data_reloaded.get("feedback", {})
                .get("replies_connection", {})
                .get("edges", [])
            )

            if inner_comments:
                doc["replies"] = await self._process_nested_replies_async(
                    executor,
                    [doc["id"]],
                    inner_comments,
                    comments_ids,
                    comments_queue,
                )
            else:
                doc["replies"] = []

            # processing_time = time() - start_time
            # log.debug(
            #     f"Successfully processed comment {index} ({doc['id']}) in {processing_time:.2f}s with {len(doc['replies'])} replies"
            # )
            return doc

        except Exception as exc:
            log.error(f"Error processing comment {index}: {exc}")
            del comments_queue[index]  # Remove the comment from the queue
            return None

    def fetch_additional_comments(self, comment_data, comments_queue):
        if not comment_data.get("feedback", {}).get("url", ""):
            return
        tmp = self.request(
            f'{comment_data["feedback"]["url"]}&{self.expansion_key}{comment_data["feedback"]["expansion_info"]["expansion_token"]}&{self.suffix_key}'
        ).text
        new_comments = [
            x
            for x in json.loads(
                text.extr(tmp, '"comment_list_renderer":', ',"comet_ufi')
            )["feedback"]["comment_rendering_instance_for_feed_location"]["comments"][
                "edges"
            ]
        ]
        combined_comments = new_comments + comments_queue
        seen_comments = set()
        res = []
        for item in combined_comments:
            if item["node"]["legacy_fbid"] not in seen_comments:
                seen_comments.add(item["node"]["legacy_fbid"])
                res.append(item)
        comments_queue.clear()
        comments_queue.extend(res)

    def parse_comment_data(self, comment_data):
        from datetime import datetime

        c_user_name = comment_data.get("user", {}).get("name", "")
        c_user_id = comment_data.get("user", {}).get("id", "")
        c_text = (comment_data.get("body") or {}).get(
            "text", ""
        )  # body can be None if comment is empty (photo exc...)
        c_time = datetime.utcfromtimestamp(comment_data.get("created_time"))
        c_url = comment_data.get("feedback", {}).get("url", "")
        c_id = comment_data.get("legacy_fbid", "")
        c_pp = comment_data.get("author", {}).get("profile_picture_depth_0", {}).get("uri", "")
        return {
            "user_name": c_user_name,
            "user_id": c_user_id,
            "text": c_text,
            "time": c_time,
            "url": c_url,
            "id": c_id,
            "profile_picture": c_pp,
        }

    def reload_comment(self, path_ids, comments_queue):
        parent_id = path_ids.pop(0)
        comment = [
            x["node"] for x in comments_queue if x["node"]["legacy_fbid"] == parent_id
        ][0]
        while path_ids:
            path_id = path_ids.pop(0)
            comment = [
                x["node"]
                for x in comment["feedback"]["replies_connection"]["edges"]
                if x["node"]["legacy_fbid"] == path_id
            ][0]
        return comment

    def _process_nested_replies(
        self, parent_ids, inner_comments, comments_ids, comments_queue
    ):
        replies = []
        for ic in inner_comments:
            ic_data = ic["node"]
            self.fetch_additional_comments(ic_data, comments_queue)
            inner_doc = self.parse_comment_data(ic_data)
            if inner_doc["id"] and inner_doc["id"] not in comments_ids:
                comments_ids.add(inner_doc["id"])
            if not inner_doc["id"]:
                raise exception.StopExtraction(
                    "This post does not have comments or is not accessible."
                )
            ic_data = self.reload_comment(
                parent_ids + [inner_doc["id"]], comments_queue
            )
            if ic_data.get("feedback", {}).get(
                "replies_connection"
            ):  # must be reloaded to have inner edges
                inner_inner_comments = ic_data["feedback"]["replies_connection"][
                    "edges"
                ]
                inner_doc["replies"] = self._process_nested_replies(
                    parent_ids + [inner_doc["id"]],
                    inner_inner_comments,
                    comments_ids,
                    comments_queue,
                )
            else:
                inner_doc["replies"] = []
            replies.append(inner_doc)
        return replies

    def count_replies(self, doc):
        """Recursively count the total number of replies in a comment document"""
        if not doc or not isinstance(doc, dict):
            return 0

        replies = doc.get("replies", [])
        if not replies:
            return 0

        # Count direct replies
        total_replies = len(replies)

        # Recursively count nested replies
        for reply in replies:
            total_replies += self.count_replies(reply)

        return total_replies

    def get_reply_stats(self, doc):
        """Get detailed reply statistics for a comment document"""
        if not doc or not isinstance(doc, dict):
            return {"direct_replies": 0, "total_replies": 0, "max_depth": 0}

        replies = doc.get("replies", [])
        direct_replies = len(replies)

        if not replies:
            return {"direct_replies": 0, "total_replies": 0, "max_depth": 0}

        total_replies = direct_replies
        max_depth = 1

        for reply in replies:
            nested_stats = self.get_reply_stats(reply)
            total_replies += nested_stats["total_replies"]
            max_depth = max(max_depth, nested_stats["max_depth"] + 1)

        return {
            "direct_replies": direct_replies,
            "total_replies": total_replies,
            "max_depth": max_depth,
        }

    async def _process_nested_replies_async(
        self, executor, parent_ids, inner_comments, comments_ids, comments_queue
    ):
        """Asynchronously process nested replies"""
        if not inner_comments:
            return []

        # Get the current event loop
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()

        # Create tasks for each reply
        reply_tasks = []
        for ic in inner_comments:
            ic_data = ic.get("node")
            if not ic_data:
                continue

            task = asyncio.create_task(
                self._async_process_single_reply(
                    executor, loop, ic_data, parent_ids, comments_ids, comments_queue
                )
            )
            reply_tasks.append(task)

        if not reply_tasks:
            return []

        # Wait for all reply tasks to complete
        results = await asyncio.gather(*reply_tasks, return_exceptions=True)

        # Filter out exceptions and None results
        replies = []
        successful_replies = 0
        failed_replies = 0

        for result in results:
            if isinstance(result, Exception):
                failed_replies += 1
                log.warning(f"Failed to process nested reply: {result}")
                continue
            if result:
                replies.append(result)
                successful_replies += 1

        if failed_replies > 0:
            log.debug(
                f"Nested replies: {successful_replies} success, {failed_replies} failed"
            )

        return replies

    async def _async_process_single_reply(
        self, executor, loop, ic_data, parent_ids, comments_ids, comments_queue
    ):
        """Process a single reply asynchronously"""
        try:
            # Fetch additional comments for this reply
            await loop.run_in_executor(
                executor, self.fetch_additional_comments, ic_data, comments_queue
            )

            # Parse the reply data
            inner_doc = await loop.run_in_executor(
                executor, self.parse_comment_data, ic_data
            )

            if not inner_doc or not inner_doc.get("id"):
                return None

            if inner_doc["id"] in comments_ids:
                return None

            comments_ids.add(inner_doc["id"])

            # Reload comment to get inner edges
            ic_data_reloaded = await loop.run_in_executor(
                executor,
                self.reload_comment,
                parent_ids + [inner_doc["id"]],
                comments_queue,
            )

            # Check if there are nested replies
            if ic_data_reloaded and ic_data_reloaded.get("feedback", {}).get(
                "replies_connection", {}
            ).get("edges"):
                inner_inner_comments = ic_data_reloaded["feedback"][
                    "replies_connection"
                ]["edges"]

                # Recursively process nested replies asynchronously
                inner_doc["replies"] = await self._process_nested_replies_async(
                    executor,
                    parent_ids + [inner_doc["id"]],
                    inner_inner_comments,
                    comments_ids,
                    comments_queue,
                )
            else:
                inner_doc["replies"] = []

            return inner_doc

        except Exception as exc:
            log.warning(f"Error processing single reply: {exc}")
            return None

    def items(self):
        post_page = self.request(self.url).text
        post_metadata = json.loads(text.extr(post_page, '"content":', ',"layout'))[
            "story"
        ]
        group_id = post_metadata["target_group"]["id"]
        user_name = post_metadata["actors"][0]["name"]
        user_id = json.loads(
            json.loads(
                text.extr(post_page, '"call_to_action":', ',"post_inform_treatment')
            )["story"]["tracking"]
        )["page_insights"][group_id]["actor_id"]

        # Extract and format timestamp
        timestamp_raw = [
            x
            for x in json.loads(text.extr(post_page, '"context_layout":', ',"aymt'))[
                "story"
            ]["comet_sections"]["metadata"]
            if "timestamp" in x["__typename"].lower()
        ][0]["story"]["creation_time"]
        from datetime import datetime

        timestamp = datetime.utcfromtimestamp(timestamp_raw)

        # extract profile picture
        profile_pic = json.loads(text.extr(post_page, '"context_layout":', ',"aymt'))[
            "story"
        ]["comet_sections"]["actor_photo"]["story"]["actors"][0]["profile_picture"][
            "uri"
        ]
        content = post_metadata["comet_sections"]["message_container"]["story"][
            "message"
        ]["text"]
        try:
            comments = json.loads(
                text.extr(post_page, '"comment_list_renderer":', ',"comet_ufi')
            )["feedback"]["comment_rendering_instance_for_feed_location"]["comments"][
                "edges"
            ]
        except KeyError:
            raise exception.StopExtraction(
                "This post does not have comments or is not accessible."
            )
        except json.JSONDecodeError:
            raise exception.StopExtraction(
                "Failed to parse comments from the post page."
            )
        return self.extract_comments(
            {"username": user_name, "user_id": user_id, "profile_pic": profile_pic},
            content,
            comments,
            timestamp,
        )
