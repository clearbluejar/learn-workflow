import pandas as pd
from pathlib import Path, PureWindowsPath
import json
import argparse
import re

from pandas.api.types import infer_dtype
from cvedata.win_verinfo import ALL_VERINFO_FULL_PATH, ALL_VERINFO_MERGED_PATH
from cvedata.procmon import PROCMON_MODLOAD_JSON_PATH



merged_df = pd.read_json(ALL_VERINFO_MERGED_PATH)

sources = merged_df['source'].explode().unique()

parser = argparse.ArgumentParser()

group = parser.add_mutually_exclusive_group()

group.add_argument("--include", nargs='+',
                    action='extend', help="filter key=value")
group.add_argument("--kb", nargs='+',
                    action='extend', help="example: KB5034204")
parser.add_argument("--regex", action='store_true',help="Use regex with include")
parser.add_argument("--count", type=int,
                    help="number of files to generate", required=True)
parser.add_argument("--require-proc-info",
                    help="only use files with extra info", action='store_true')
parser.add_argument("--source", choices=sources, default=sources[0])
parser.add_argument(
    "--limit-list", help="limit length of file lists", type=int)


args = parser.parse_args()

if args.count < 1:
    parser.print_help()
    print(f'Error: Count must be 1 or higher. count = {args.count}')
    exit(1) 

print(args)

# handle includes
includes = []
kbs = []

if args.include is not None:
    for include in args.include:
        key, val = include.split('=')
        includes.append([key, val])

    df = pd.read_json(ALL_VERINFO_FULL_PATH, orient='split')

    print(df.dtypes)
    print(infer_dtype(df['source']))
    print(df.head())

    # apply includes

    for key, val in includes:

        print(f'Filtering {key}={val}')
        if df.shape[0] == 0:
            raise Exception(f'Query {includes} resulted in empty dateframe. Nothing to process')  # can't do anything with
        assert key in df.columns, f'{key}: not found in {df.columns} check --includes key=value'
        
        val_type = type(df[key].iloc[0])

        if not args.regex:
            if val_type == list:
                df = df[df[key].apply(lambda x: any(
                    [val.lower() in item.lower() for item in x]))]
            else:
                    df = df[df[key].apply(lambda x: val.lower() in x.lower())]
        else:
            if val_type == list:
                df = df[df[key].apply(lambda x: any(
                    [bool(re.search(val, item,re.IGNORECASE)) for item in x]))]
            else:
                df = df[df[key].apply(lambda x: bool(re.search(val, x,re.IGNORECASE)))]
             
        print(df.shape[0])
        print(df.head())
        #df['VersionInfo.FileName'].to_json('test.json',orient='records')

    df = df.sort_values(by='size', ascending=True)
    df.reset_index(names='sha256', inplace=True)

    proc_df = pd.read_json(PROCMON_MODLOAD_JSON_PATH)
    proc_df = proc_df.reset_index(names=['Path'])
    proc_df['is_priv'] = proc_df['User'].astype(
        str).str.contains('SYSTEM|SERVICE|LOCAL')

    df = df.rename(columns={'VersionInfo.FileName': 'Path'})
    merged_df = proc_df.merge(df, on='Path', how='inner')

    print(df.head())

    if args.require_proc_info:
        print(merged_df.shape[0])
        print(merged_df.head())
        merged_df = merged_df[merged_df['is_priv'] == True]
        print(merged_df.shape[0])
        print(merged_df.head())
        all_files_list = merged_df.to_dict(orient='records')

    else:
        all_files_list = df.to_dict(orient='records')

else:

    from kbdex import kb_exists, get_kb_info, get_kb_file_urls

    for kb in args.kb:
        if not kb_exists(kb):
            print(f'Warn kb: {kb} not found!!')
            exit(1)
        kbs.append(kb)

    all_files_list = []

    for kb in kbs:
        kb_info = get_kb_info(kb)
        
        #print(kb_info)
        print(f"kb_info: update_len:{len(kb_info['updated'])} date:{kb_info['release']} build:{kb_info['build']}")
        all_files_list.extend(get_kb_file_urls(kb_info))
        #print(all_files_list)

    for file in all_files_list:
        print(file)

    #conver all_files_list to expected
    
    

bucket = {}
# items sorted by size.. file the buckets evenly
for i, file in enumerate(all_files_list):

    id = i % args.count
    bucket.setdefault(id, []).append(file)

    if args.include is not None:
        print(f"Added {file['Name']} with size: {file['size'] /  1024} KB")
    else:
        print(f"Added {file['filename']} with build: {file['build']}")

    if args.limit_list:
        if i / args.count > args.limit_list - 1:
            print(f'limiting lists by {args.limit_list}')

            break


files_path = Path('gen_files')
files_path.mkdir(exist_ok=True)
meta_path = files_path / 'meta'
meta_path.mkdir(exist_ok=True)

for i, files in bucket.items():

    path = files_path / Path(f'files{i}.json')

    print(f'Writing file: {path} with count: {len(bucket[i])}')
    path.write_text(json.dumps(bucket[i]))




if args.include is not None:
    sources_values = df['source'].value_counts()
    paths_values = df['Path'].apply(
        lambda x: PureWindowsPath(x).parent).value_counts()

    # more options can be specified also
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):

        print(sources_values)
        print(paths_values)



    sources_values_path = meta_path / 'sources_values.md'
    sources_values.to_markdown(sources_values_path)

    paths_values_path = meta_path / 'paths_values.md'
    paths_values.to_markdown(paths_values_path)

    df_path = meta_path / 'pandas_query_df.json'
    df.to_json(df_path)

    df_proc_md_path = meta_path / 'proc_pandas_query.md'
    df_proc_path = meta_path / 'proc_pandas_query.json'

    merged_df.to_markdown(df_proc_md_path, tablefmt="github")
    merged_df.to_json(df_proc_path)

    x_sources_values = merged_df['source_x'].value_counts()
    y_sources_values = merged_df['source_y'].value_counts()
    paths_values = merged_df['Path'].apply(
        lambda x: PureWindowsPath(x).parent).value_counts()

    # more options can be specified also
    with pd.option_context('display.max_rows', None, 'display.max_columns', None):

        print(x_sources_values)
        print(y_sources_values)
        print(paths_values)


    pd.read_json(df_proc_path)
    pd.read_json(df_path)

    print(f'Final query file count: {df.shape[0]}')
    print(f'Final query with proc_info file count: {merged_df.shape[0]}')


args_path = meta_path / 'args.json'
args_path.write_text(json.dumps(vars(args)))



print(f'Generated files: {len(all_files_list)}')
print(f'Files per worker : {int(len(all_files_list)/args.count)}')
