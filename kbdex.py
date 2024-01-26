import pathlib
import pandas
import json
import gzip

from cvedata.winbindex import WINDOWS_KBS_TO_BINS_PATH,WB_FILE_VER_URL_PANDAS_PATH


kb_data = pathlib.Path(WINDOWS_KBS_TO_BINS_PATH)
url_data =  pathlib.Path(WB_FILE_VER_URL_PANDAS_PATH)


with gzip.open(kb_data) as f:
    json_data = json.load(f)
df_kb_to_bin = pandas.read_json(json.dumps(json_data))
df_kb_to_bin = df_kb_to_bin.swapaxes('columns','index')

with gzip.open(url_data) as f:
    json_data = json.load(f)
df_urls = pandas.read_json(json.dumps(json_data))


def get_kb_info(kb: str) -> dict:
    return df_kb_to_bin.loc[kb].to_dict()

def kb_exists(kb: str):

    return kb in df_kb_to_bin.index

def get_bin_url(filename: str, build: str) -> dict:
    return df_urls[df_urls['version'].str.contains(build) & df_urls['filename'].str.contains(filename)].to_dict('records')


def get_kb_file_urls(kb_info: dict): 

    kb_file_info = []

    for filename in kb_info['updated']:

        bin_url_info_list = get_bin_url(filename,kb_info['build'])

        for bin_url_info in bin_url_info_list:
            if len(bin_url_info) == 0:
                bin_url_info = {'filename': filename }
            bin_url_info['build'] = kb_info['build']
            kb_file_info.append(bin_url_info)


    return kb_file_info