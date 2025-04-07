#!/usr/bin/env python3
"""
unwebpack_sourcemap.py
by rarecoil (github.com/rarecoil/unwebpack-sourcemap)

Reads Webpack source maps and extracts the disclosed
uncompiled/commented source code for review. Can detect and
attempt to read sourcemaps from Webpack bundles with the `-d`
flag. Puts source into a directory structure similar to dev.
"""

import argparse
import json
import os
import re
import string
import sys
from urllib.parse import urlparse
from unicodedata import normalize
import requests
from bs4 import BeautifulSoup, SoupStrainer
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _write_content_to_handle(f, write_path: str, content: str):
    print("Writing %s..." % os.path.basename(write_path))
    f.write(content)

class SourceMapExtractor(object):
    """Primary SourceMapExtractor class. Feed this arguments."""

    def __init__(self, options):
        """Initialize the class."""
        if 'output_directory' not in options:
            raise SourceMapExtractorError("output_directory must be set in options.")
        else:
            self._output_directory = os.path.abspath(options['output_directory'])
            if not os.path.isdir(self._output_directory):
                if options['make_directory'] is True:
                    os.mkdir(self._output_directory)
                else:
                    raise SourceMapExtractorError("output_directory does not exist. Pass --make-directory to auto-make it.")

        self._path_sanitiser = PathSanitiser(self._output_directory)
        self.disable_verify_ssl = options.get('disable_ssl_verification', False)
        self._is_local = options.get('local', False)
        self._attempt_sourcemap_detection = options.get('detect', False)

        self._validate_target(options['uri_or_file'])

    def run(self):
        """Run extraction process."""
        if not self._is_local:
            if self._attempt_sourcemap_detection:
                detected_sourcemaps = self._detect_js_sourcemaps(self._target)
                for sourcemap in detected_sourcemaps:
                    self._parse_remote_sourcemap(sourcemap)
            else:
                self._parse_remote_sourcemap(self._target)
        else:
            self._parse_sourcemap(self._target)

    def _validate_target(self, target):
        """Do some basic validation on the target."""
        parsed = urlparse(target)
        if self._is_local:
            self._target = os.path.abspath(target)
            if not os.path.isfile(self._target):
                raise SourceMapExtractorError("uri_or_file is set to be a file, but doesn't seem to exist. check your path.")
        else:
            if not parsed.scheme:
                raise SourceMapExtractorError("uri_or_file isn't a URI, and --local was not set. set --local?")
            file, ext = os.path.splitext(parsed.path)
            self._target = target
            if ext != '.map' and not self._attempt_sourcemap_detection:
                logger.warning("URI does not have .map extension, and --detect is not flagged.")

    def _parse_remote_sourcemap(self, uri):
        """GET a remote sourcemap and parse it."""
        data, final_uri = self._get_remote_data(uri)
        if data:
            self._parse_sourcemap(data, True)
        else:
            logger.warning(f"Could not retrieve sourcemap from URI {final_uri}")

    def _detect_js_sourcemaps(self, uri):
        """Pull HTML and attempt to find JS files, then read the JS files and look for sourceMappingURL."""
        remote_sourcemaps = []
        data, final_uri = self._get_remote_data(uri)

        logger.info(f"Detecting sourcemaps in HTML at {final_uri}")
        script_strainer = SoupStrainer("script", src=True)
        try:
            soup = BeautifulSoup(data, "html.parser", parse_only=script_strainer)
        except Exception:
            raise SourceMapExtractorError(f"Could not parse HTML at URI {final_uri}")

        for script in soup:
            source = script['src']
            parsed_uri = urlparse(source)
            next_target_uri = source if parsed_uri.scheme else urlparse(final_uri)._replace(path=source).geturl()

            js_data, last_target_uri = self._get_remote_data(next_target_uri)
            if js_data:
                last_line = js_data.rstrip().split("\n")[-1]
                matches = re.search(r"\/\/#\s*sourceMappingURL=(.*)$", last_line)
                if matches:
                    asset = matches.group(1).strip()
                    asset_target = urlparse(asset)
                    asset_uri = asset if asset_target.scheme else urlparse(last_target_uri)._replace(path=os.path.join(os.path.dirname(urlparse(last_target_uri).path), asset)).geturl()
                    logger.info(f"Detected sourcemap at remote location {asset_uri}")
                    remote_sourcemaps.append(asset_uri)

        return remote_sourcemaps

    def _parse_sourcemap(self, target, is_str=False):
        map_data = target if is_str else (open(target, 'r', encoding='utf-8', errors='ignore').read() if os.path.isfile(target) else None)

        if not map_data:
            logger.error(f"Failed to parse sourcemap {target}. Are you sure this is a sourcemap?")
            return False

        try:
            map_object = json.loads(map_data)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse sourcemap {target}. Are you sure this is a sourcemap?")
            return False

        if 'sources' not in map_object or 'sourcesContent' not in map_object:
            logger.error("Sourcemap does not contain sources and/or sourcesContent, cannot extract.")
            return False

        if len(map_object['sources']) != len(map_object['sourcesContent']):
            logger.warning("sources != sourcesContent, filenames may not match content")

        for source, content in zip(map_object['sources'], map_object['sourcesContent']):
            write_path = self._get_sanitised_file_path(source)

            if write_path:
                os.makedirs(os.path.dirname(write_path), mode=0o755, exist_ok=True)
                with open(write_path, 'w', encoding='utf-8', errors='ignore', newline='') as f:
                    logger.info(f"Writing {os.path.basename(write_path)}...")
                    f.write(content)
            else:
                logger.error(f"Could not sanitize path {source}")

    def _get_sanitised_file_path(self, sourcePath):
        """Sanitise webpack paths for separators/relative paths"""
        sourcePath = sourcePath.replace("webpack:///", "")
        exts = sourcePath.split(" ")

        if exts[0] == "external":
            logger.warning(f"Found external sourcemap {exts[1]}, not currently supported. Skipping")
            return None

        path, filename = os.path.split(sourcePath)
        if path.startswith('./'):
            path = path[2:]
        elif path.startswith('../'):
            path = 'parent_dir/' + path[3:]

        # Ensure empty paths are named properly
        if not path:
            path = self._path_sanitiser.get_next_empty_name()

        filepath = self._path_sanitiser.make_valid_file_path(path, filename)
        return filepath

    def _get_remote_data(self, uri):
        """Get remote data via http."""
        try:
            result = requests.get(uri, verify=not self.disable_verify_ssl)
        except requests.RequestException as e:
            logger.warning(f"Could not retrieve {uri}: {e}")
            return None, uri

        if result.status_code == 200:
            return result.text, result.url
        else:
            logger.warning(f"Got status code {result.status_code} for URI {result.url}")
            return None, result.url


class PathSanitiser:
    """Sanitize and manage file paths for safe and valid filesystem usage."""

    EMPTY_NAME = "empty"
    empty_idx = 0

    def __init__(self, root_path):
        self.root_path = root_path

    def ensure_directory_exists(self, path_directory):
        if not os.path.exists(path_directory):
            os.makedirs(path_directory)

    def os_path_separators(self):
        return [sep for sep in {os.path.sep, os.path.altsep} if sep]

    def sanitise_filesystem_name(self, potential_file_path_name):
        valid_filename = normalize('NFKD', potential_file_path_name).encode('ascii', 'ignore').decode('ascii')
        for sep in self.os_path_separators():
            valid_filename = valid_filename.replace(sep, '_')
        valid_chars = "-_.() {}{}".format(string.ascii_letters, string.digits)
        valid_filename = "".join(ch for ch in valid_filename if ch in valid_chars)
        # If the filename is empty after sanitization, use a default name
        if not valid_filename:
            valid_filename = "default_name"
        return valid_filename

    def get_root_path(self):
        filepath = os.path.abspath(self.root_path)
        if not filepath.endswith(os.path.sep):
            filepath += os.path.sep
        return filepath

    def path_split_into_list(self, path):
        parts = []
        while True:
            newpath, tail = os.path.split(path)
            if newpath == path:
                if path and path not in self.os_path_separators():
                    parts.append(path)
                break
            if tail and tail not in self.os_path_separators():
                parts.append(tail)
            path = newpath
        parts.reverse()
        return parts

    def sanitise_filesystem_path(self, potential_file_path):
        path_parts_list = self.path_split_into_list(potential_file_path)
        sanitised_path = ''
        for path_component in path_parts_list:
            sanitised_path = os.path.join(sanitised_path, self.sanitise_filesystem_name(path_component))
        return sanitised_path

    def make_valid_file_path(self, path, filename):
        valid_path = self.get_root_path() + self.sanitise_filesystem_path(path)
        valid_file_name = self.sanitise_filesystem_name(filename)
        if not valid_file_name:
            logger.warning(f"Could not sanitize filename {filename}, skipping.")
            return None
        valid_file_path = os.path.join(valid_path, valid_file_name)
        return valid_file_path

    def get_next_empty_name(self):
        """Generate a unique empty directory name."""
        self.empty_idx += 1
        return f"{self.EMPTY_NAME}_{self.empty_idx}"


class SourceMapExtractorError(Exception):
    """Custom exception for SourceMapExtractor."""

    def __init__(self, message, *args):
        self.message = message
        super().__init__(message, *args)


def main():
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description='Extract original source from Webpack sourcemaps.')
    parser.add_argument('uri_or_file', type=str, help='sourcemap file or URI to parse')
    parser.add_argument('output_directory', type=str, help='directory to extract sources to')
    parser.add_argument('-d', '--detect', action='store_true', help='detect and extract from a HTML file with sourcemaps')
    parser.add_argument('-l', '--local', action='store_true', help='uri_or_file is a local file, not URI')
    parser.add_argument('--disable-ssl-verification', action='store_true', help='disable SSL verification for requests')
    parser.add_argument('--make-directory', action='store_true', help='create output directory if it does not exist')
    args = parser.parse_args()

    options = {
        'uri_or_file': args.uri_or_file,
        'output_directory': args.output_directory,
        'detect': args.detect,
        'local': args.local,
        'disable_ssl_verification': args.disable_ssl_verification,
        'make_directory': args.make_directory
    }

    try:
        extractor = SourceMapExtractor(options)
        extractor.run()
    except SourceMapExtractorError as err:
        logger.error(err.message)
        sys.exit(1)


if __name__ == "__main__":
    main()
