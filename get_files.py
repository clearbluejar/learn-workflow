from requests import Session
from pathlib import Path
from concurrent import futures
from typing import Union, Tuple
import pefile
import argparse
import json
from datetime import datetime

CONNECTIONS = 10
TIMEOUT = 10


def get_pe_version(bin: Union[str, Path, bytes]) -> str:
    """
    Get downloaded PE file version
    # https://gist.github.com/spookyahell/b317bdf0712aac5fd37dd79f70bfbe69
    """

    if isinstance(bin, Path) or isinstance(bin, str):
        pe = pefile.PE(bin, fast_load=True)
    elif isinstance(bin, bytes):
        pe = pefile.PE(data=bin, fast_load=True)

    # only load resource dir for speed
    pe.parse_data_directories([2])

    ver_info = {}

    for fileinfo in pe.FileInfo[0]:
        if fileinfo.Key.decode() == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    ver_info[entry[0].decode()] = entry[1].decode()

    return ver_info['FileVersion'].split(' ')[0]


def download_verify_bin(session: Session, file: str, timeout=10) -> Tuple[bytes, str]:
    """
    Download binary and return data and actual pe_ver
    """

    pe_ver = None
    bin_data = None
    status = None

    url = file['url']

    print(f"Downloading {url}...")
    try:
        response = session.get(url, timeout=timeout)
        status = response.status_code
        if status == 200:
            bin_data = response.content
            pe_ver = get_pe_version(bin_data)
        else:
            print(f"Error: failed to download {url} : {status}")

    except Exception as ex:
        print(f"Error downloading: {url} error: {ex}")

    return [status, file, pe_ver, bin_data]


def download_all_files(session: Session, files: list, dl_path: Path):

    actual_urls = []
    skipped_urls = []

    with futures.ThreadPoolExecutor(max_workers=CONNECTIONS) as executor:
        future_to_url = (executor.submit(download_verify_bin, session, file, TIMEOUT) for file in files)

        for future in futures.as_completed(future_to_url):
            status, file, pe_ver, bin_data = future.result()

            if status == 200 and bin_data is not None:

                if pe_ver is None:
                    print(
                        f"WARN: Could not get pe_ver from {file['url']} {status} appending one from {file['VersionInfo.FileVersion']}")
                    pe_ver = f"{file['VersionInfo.FileVersion']}"

                file_path = dl_path / f"{'.'.join([file['Name'].lower(),pe_ver])}"
                file_path.write_bytes(bin_data)
                actual_urls.append([status, file, pe_ver, str(file_path)])
            else:
                skipped_urls.append([status, file, pe_ver])

    return actual_urls, skipped_urls


parser = argparse.ArgumentParser()

parser.add_argument("--id", type=int, help="fileid to download from", required=True)
parser.add_argument("--dl_path", help="Download Base Path", default='bins')

args = parser.parse_args()

all_bins_path = Path(args.dl_path)
all_bins_path.mkdir(exist_ok=True)


# download all files in
gen_files_path = Path('gen_files')
dl_path = Path(args.dl_path)
dl_path.mkdir(exist_ok=True)

files_list_path = gen_files_path / f'files{args.id}.json'

files_list = json.loads(files_list_path.read_text())

session = Session()

start = datetime.now()
dl_bin_path = dl_path / 'downloaded'
dl_bin_path.mkdir(exist_ok=True)
# files_list = files_list[:10]
actual_files, skipped_files = download_all_files(session, files_list, dl_bin_path)

meta_path = dl_path / 'meta'
meta_path.mkdir(exist_ok=True)

actual_files_path = meta_path / f'dl_files{args.id}.json'
actual_files_path.write_text(json.dumps(actual_files))
skipped_files_path = meta_path / 'skipped_files.json'
skipped_files_path.write_text(json.dumps(skipped_files))

print(f'Downloaded {len(actual_files)} and skipped {len(skipped_files)} in {(datetime.now() - start).seconds} seconds')
print(f"Bins dir has {len(list(dl_path.glob('*')))} files downloaded")
