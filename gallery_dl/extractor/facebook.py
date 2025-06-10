# -*- coding: utf-8 -*-

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

"""Extractors for https://www.facebook.com/"""

import json
from .common import Extractor, Message
from .. import text, exception

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
            txt.encode().decode("unicode_escape")
            .encode("utf_16", "surrogatepass").decode("utf_16")
        ).replace("\\/", "/")

    @staticmethod
    def parse_set_page(set_page):
        directory = {
            "set_id": text.extr(
                set_page, '"mediaSetToken":"', '"'
            ) or text.extr(
                set_page, '"mediasetToken":"', '"'
            ),
            "username": FacebookExtractor.decode_all(
                text.extr(
                    set_page, '"user":{"__isProfile":"User","name":"', '","'
                ) or text.extr(
                    set_page, '"actors":[{"__typename":"User","name":"', '","'
                )
            ),
            "user_id": text.extr(
                set_page, '"owner":{"__typename":"User","id":"', '"'
            ),
            "title": FacebookExtractor.decode_all(text.extr(
                set_page, '"title":{"text":"', '"'
            )),
            "first_photo_id": text.extr(
                set_page,
                '{"__typename":"Photo","__isMedia":"Photo","',
                '","creation_story"'
            ).rsplit('"id":"', 1)[-1] or
            text.extr(
                set_page, '{"__typename":"Photo","id":"', '"'
            )
        }

        return directory

    @staticmethod
    def parse_photo_page(photo_page):
        photo = {
            "id": text.extr(
                photo_page, '"__isNode":"Photo","id":"', '"'
            ),
            "set_id": text.extr(
                photo_page,
                '"url":"https:\\/\\/www.facebook.com\\/photo\\/?fbid=',
                '"'
            ).rsplit("&set=", 1)[-1],
            "username": FacebookExtractor.decode_all(text.extr(
                photo_page, '"owner":{"__typename":"User","name":"', '"'
            )),
            "user_id": text.extr(
                photo_page, '"owner":{"__typename":"User","id":"', '"'
            ),
            "caption": FacebookExtractor.decode_all(text.extr(
                photo_page,
                '"message":{"delight_ranges"',
                '"},"message_preferred_body"'
            ).rsplit('],"text":"', 1)[-1]),
            "date": text.parse_timestamp(
                text.extr(photo_page, '\\"publish_time\\":', ',') or
                text.extr(photo_page, '"created_time":', ',')
            ),
            "url": FacebookExtractor.decode_all(text.extr(
                photo_page, ',"image":{"uri":"', '","'
            )),
            "next_photo_id": text.extr(
                photo_page,
                '"nextMediaAfterNodeId":{"__typename":"Photo","id":"',
                '"'
            ) or text.extr(
                photo_page,
                '"nextMedia":{"edges":[{"node":{"__typename":"Photo","id":"',
                '"'
            )
        }

        text.nameext_from_url(photo["url"], photo)

        photo["followups_ids"] = []
        times = []
        for comment_raw in text.extract_iter(
            photo_page, '{"node":{"id"', '"cursor":null}'
        ):
            if ('"is_author_original_poster":true' in comment_raw and
                    '{"__typename":"Photo","id":"' in comment_raw):
                photo["followups_ids"].append(text.extr(
                    comment_raw,
                    '{"__typename":"Photo","id":"',
                    '"'
                ))
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
            text.extr(
                post_page, '"__isMedia":"Photo"', '"target_group"'
            ), '"url":"', ','
        )

        post = {
            "set_id": text.extr(post_page, '{"mediaset_token":"', '"') or
            text.extr(first_photo_url, 'set=', '"').rsplit("&", 1)[0]
        }

        return post

    @staticmethod
    def parse_video_page(video_page):
        video = {
            "id": text.extr(
                video_page, '\\"video_id\\":\\"', '\\"'
            ),
            "username": FacebookExtractor.decode_all(text.extr(
                video_page, '"actors":[{"__typename":"User","name":"', '","'
            )),
            "user_id": text.extr(
                video_page, '"owner":{"__typename":"User","id":"', '"'
            ),
            "date": text.parse_timestamp(text.extr(
                video_page, '\\"publish_time\\":', ','
            )),
            "type": "video"
        }

        if not video["username"]:
            video["username"] = FacebookExtractor.decode_all(text.extr(
                video_page,
                '"__typename":"User","id":"' + video["user_id"] + '","name":"',
                '","'
            ))

        first_video_raw = text.extr(
            video_page, '"permalink_url"', '\\/Period>\\u003C\\/MPD>'
        )

        audio = {
            **video,
            "url": FacebookExtractor.decode_all(text.extr(
                text.extr(
                    first_video_raw,
                    "AudioChannelConfiguration",
                    "BaseURL>\\u003C"
                ),
                "BaseURL>", "\\u003C\\/"
            )),
            "type": "audio"
        }

        video["urls"] = {}

        for raw_url in text.extract_iter(
            first_video_raw, 'FBQualityLabel=\\"', '\\u003C\\/BaseURL>'
        ):
            resolution = raw_url.split('\\"', 1)[0]
            video["urls"][resolution] = FacebookExtractor.decode_all(
                raw_url.split('BaseURL>', 1)[1]
            )

        if not video["urls"]:
            return video, audio

        video["url"] = max(
            video["urls"].items(),
            key=lambda x: text.parse_int(x[0][:-1])
        )[1]

        text.nameext_from_url(video["url"], video)
        audio["filename"] = video["filename"]
        audio["extension"] = "m4a"

        return video, audio

    def photo_page_request_wrapper(self, url, **kwargs):
        LEFT_OFF_TXT = "" if url.endswith("&set=") else (
            "\nYou can use this URL to continue from "
            "where you left off (added \"&setextract\"): "
            "\n" + url + "&setextract"
        )

        res = self.request(url, **kwargs)

        if res.url.startswith(self.root + "/login"):
            raise exception.AuthenticationError(
                "You must be logged in to continue viewing images." +
                LEFT_OFF_TXT
            )

        if b'{"__dr":"CometErrorRoot.react"}' in res.content:
            raise exception.StopExtraction(
                "You've been temporarily blocked from viewing images. "
                "\nPlease try using a different account, "
                "using a VPN or waiting before you retry." +
                LEFT_OFF_TXT
            )

        return res

    def extract_set(self, set_data):
        set_id = set_data["set_id"]
        all_photo_ids = [set_data["first_photo_id"]]

        retries = 0
        i = 0

        while i < len(all_photo_ids):
            photo_id = all_photo_ids[i]
            photo_url = self.photo_url_fmt.format(
                photo_id=photo_id, set_id=set_id
            )
            photo_page = self.photo_page_request_wrapper(photo_url).text

            photo = self.parse_photo_page(photo_page)
            photo["num"] = i + 1

            if self.author_followups:
                for followup_id in photo["followups_ids"]:
                    if followup_id not in all_photo_ids:
                        self.log.debug(
                            "Found a followup in comments: %s", followup_id
                        )
                        all_photo_ids.append(followup_id)

            if not photo["url"]:
                if retries < self.fallback_retries and self._interval_429:
                    seconds = self._interval_429()
                    self.log.warning(
                        "Failed to find photo download URL for %s. "
                        "Retrying in %s seconds.", photo_url, seconds,
                    )
                    self.wait(seconds=seconds, reason="429 Too Many Requests")
                    retries += 1
                    continue
                else:
                    self.log.error(
                        "Failed to find photo download URL for " + photo_url +
                        ". Skipping."
                    )
                    retries = 0
            else:
                retries = 0
                photo.update(set_data)
                yield Message.Directory, photo
                yield Message.Url, photo["url"], photo

            if not photo["next_photo_id"]:
                self.log.debug(
                    "Can't find next image in the set. "
                    "Extraction is over."
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
        BASE_PATTERN +
        r"/(?:(?:media/set|photo)/?\?(?:[^&#]+&)*set=([^&#]+)"
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
    pattern = (BASE_PATTERN +
               r"/(?:[^/?#]+/photos/[^/?#]+/|photo(?:.php)?/?\?"
               r"(?:[^&#]+&)*fbid=)([^/?&#]+)[^/?#]*(?<!&setextract)$")
    example = "https://www.facebook.com/photo/?fbid=PHOTO_ID"

    def items(self):
        photo_id = self.groups[0]
        photo_url = self.photo_url_fmt.format(photo_id=photo_id, set_id="")
        photo_page = self.photo_page_request_wrapper(photo_url).text

        i = 1
        photo = self.parse_photo_page(photo_page)
        photo["num"] = i

        set_page = self.request(
            self.set_url_fmt.format(set_id=photo["set_id"])
        ).text

        directory = self.parse_set_page(set_page)

        yield Message.Directory, directory
        yield Message.Url, photo["url"], photo

        if self.author_followups:
            for comment_photo_id in photo["followups_ids"]:
                comment_photo = self.parse_photo_page(
                    self.photo_page_request_wrapper(
                        self.photo_url_fmt.format(
                            photo_id=comment_photo_id, set_id=""
                        )
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
        BASE_PATTERN +
        r"/(?!media/|photo/|photo.php|watch/)"
        r"(?:profile\.php\?id=|people/[^/?#]+/)?"
        r"([^/?&#]+)(?:/photos(?:_by)?|/videos|/posts)?/?(?:$|\?|#)"
    )
    example = "https://www.facebook.com/USERNAME"

    @staticmethod
    def get_profile_photos_set_id(profile_photos_page):
        set_ids_raw = text.extr(
            profile_photos_page, '"pageItems"', '"page_info"'
        )

        set_id = text.extr(
            set_ids_raw, 'set=', '"'
        ).rsplit("&", 1)[0] or text.extr(
            set_ids_raw, '\\/photos\\/', '\\/'
        )

        return set_id

    def items(self):
        profile_photos_url = (
            self.root + "/" + self.groups[0] + "/photos_by"
        )
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
    pattern = (
        BASE_PATTERN +
        r"/groups/([^/?&#]+)/posts/([^/?&#]+)"
    )
    example = "https://www.facebook.com/groups/238620256823178/posts/1693941581291031"
    expansion_key = "__cft__[1]="
    suffix_key = "__tn__=R-R"

    def extract_comments(self, user, content, comments_queue):
        post_comments, comments_ids = [], set()
        i = 0
        while i < len(comments_queue):
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
            i = 0
            comments_ids.add(doc["id"])
            comment_data = self.reload_comment([doc["id"]], comments_queue)# must be reloaded to have inner edges
            inner_comments = comment_data["feedback"]["replies_connection"]["edges"]
            doc["replies"] = self._process_nested_replies([doc["id"]], inner_comments, comments_ids, comments_queue)
            # if comment_data.get("feedback", {}).get("replies_fields", {}).get("count", 0):
            #     doc["replies"] = []
            #     i = 0
            #     inner_comments = [x["node"]["feedback"]["replies_connection"]["edges"] for x in comments_queue if x["node"]["legacy_fbid"] == doc["id"]][0] # must be reloaded to have edges
            #     for j, ic in enumerate(inner_comments):
            #         ic = ic["node"]
            #         self.fetch_additional_comments(ic, comments_queue)
            #         inner_doc = self.parse_comment_data(ic)
            #         if inner_doc["id"] and inner_doc["id"] not in comments_ids:
            #             comments_ids.add(inner_doc["id"])
            #         if not inner_doc["id"]:
            #             raise exception.StopExtraction(
            #                 "This post does not have comments or is not accessible."
            #             )
            #         if ic.get("feedback", {}).get("replies_fields", {}).get("count", 0):
            #             inner_doc["replies"] = []
            #             i = 0
            #             inner_inner_comments = [x["node"]["feedback"]["replies_connection"]["edges"] for x in comments_queue if x["node"]["legacy_fbid"] == doc["id"]][0][j]["node"]["feedback"]["replies_connection"]["edges"]
            #             for iic in inner_inner_comments:
            #                 iic = iic["node"]
            #                 inner_inner_doc = self.parse_comment_data(iic)
            #                 if inner_inner_doc["id"] and inner_inner_doc["id"] not in comments_ids:
            #                     comments_ids.add(inner_inner_doc["id"])
            #                 if not inner_inner_doc["id"]:
            #                     raise exception.StopExtraction(
            #                         "This post does not have comments or is not accessible."
            #                     )
            #                 inner_doc["replies"].append(inner_inner_doc)
            #         doc["replies"].append(inner_doc)
            post_comments.append(doc)
            i += 1
            if len(post_comments) >= self.config("comments-limit", 100):
                break
        yield Message.Directory, {"user": user, "content": content, "comments": post_comments}
    
    def fetch_additional_comments(self, comment_data, comments_queue):
        if not comment_data.get("feedback", {}).get("url", ""):
            return
        tmp = self.request(
                f'{comment_data["feedback"]["url"]}&{self.expansion_key}{comment_data["feedback"]["expansion_info"]["expansion_token"]}&{self.suffix_key}'
            ).text
        new_comments = [x for x in json.loads(text.extr(tmp, '"comment_list_renderer":', ',"comet_ufi'))["feedback"]["comment_rendering_instance_for_feed_location"]["comments"]["edges"]]
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
        c_user = comment_data.get("user", {}).get("name", "")
        c_text = (comment_data.get("body") or {}).get("text", "") # body can be None if comment is empty (photo exc...)
        c_time = datetime.utcfromtimestamp(comment_data.get('created_time'))
        c_url = comment_data.get("feedback", {}).get("url", "")
        c_id = comment_data.get("legacy_fbid", "")
        return {
            "user": c_user,
            "text": c_text,
            "time": c_time,
            "url": c_url,
            "id": c_id
        }
    
    def reload_comment(self, path_ids, comments_queue):
        parent_id = path_ids.pop(0)
        comment = [x["node"] for x in comments_queue if x["node"]["legacy_fbid"] == parent_id][0]
        while path_ids:
            path_id = path_ids.pop(0)
            comment = [x["node"] for x in comment["feedback"]["replies_connection"]["edges"] if x["node"]["legacy_fbid"] == path_id][0]
        return comment

    def _process_nested_replies(self, parent_ids, inner_comments, comments_ids, comments_queue):
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
            ic_data = self.reload_comment(parent_ids + [inner_doc["id"]], comments_queue)
            if ic_data.get("feedback", {}).get("replies_connection"):  # must be reloaded to have inner edges
                inner_inner_comments = ic_data["feedback"]["replies_connection"]["edges"]
                inner_doc["replies"] = self._process_nested_replies(parent_ids + [inner_doc["id"]], inner_inner_comments, comments_ids, comments_queue)
            else:
                inner_doc["replies"] = []
            replies.append(inner_doc)
        return replies

    def items(self):
        post_page = self.request(self.url).text
        post_metadata = json.loads(text.extr(post_page, '"content":', ',"layout'))["story"]
        user = post_metadata["actors"][0]["name"]
        content = post_metadata["comet_sections"]["message_container"]["story"]["message"]["text"]
        try:
            comments = json.loads(text.extr(post_page, '"comment_list_renderer":', ',"comet_ufi'))["feedback"]["comment_rendering_instance_for_feed_location"]["comments"]["edges"]
        except KeyError:
            raise exception.StopExtraction(
                "This post does not have comments or is not accessible."
            )
        except json.JSONDecodeError:
            raise exception.StopExtraction(
                "Failed to parse comments from the post page."
            )
        return self.extract_comments(user, content, comments)


