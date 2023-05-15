from pandas.api.types import infer_dtype
from cvedata.win_verinfo import ALL_VERINFO_FULL_PATH, ALL_VERINFO_MERGED_PATH
from cvedata.procmon import PROCMON_MODLOAD_JSON_PATH
import pandas as pd
from pathlib import Path, PureWindowsPath
import json
import argparse


merged_df = pd.read_json(ALL_VERINFO_MERGED_PATH)

sources = merged_df['source'].explode().unique()

parser = argparse.ArgumentParser()

parser.add_argument("--include", nargs='+', action='extend', help="filter key=value")
parser.add_argument("--exclude",  nargs='+', action='extend', help="filter key=value")
parser.add_argument("--count", type=int, help="number of files to generate", required=True)
parser.add_argument("--source", choices=sources, default=sources[0])
parser.add_argument("--limit-list", help="limit length of file lists", type=int)


args = parser.parse_args()

if args.count < 1:
    raise f'Count must be 1 or higher. count = {args.count}'

print(args)

# handle includes
includes = []


for include in args.include:
    key, val = include.split('=')
    includes.append([key, val])


print(includes)

df = pd.read_json(ALL_VERINFO_FULL_PATH, orient='split')

print(df.dtypes)
print(infer_dtype(df['source']))
print(df.head())

# apply includes

for key, val in includes:
    assert key in df.columns, f'{key}: not found in {df.columns} check - -includes'
    val_type = type(df[key].iloc[0])
    if val_type == list:
        df = df[df[key].apply(lambda x: any([val.lower() in item.lower() for item in x]))]
    else:
        df = df[df[key] == val]
    print(df.shape[0])


df = df.sort_values(by='size', ascending=True)

print(df.head())

all_files_list = df.to_dict(orient='records')

print(len(all_files_list))

bucket = {}
# items sorted by size.. file the buckets evenly
for i, file in enumerate(all_files_list):

    id = i % args.count
    bucket.setdefault(id, []).append(file)

    print(f"Added {file['Name']} with size: {file['size'] /  1024} KB")

    if args.limit_list:
        if i / args.count > args.limit_list - 1:
            print(f'limiting lists by {args.limit_list}')

            break


files_path = Path('gen_files')
files_path.mkdir(exist_ok=True)

for i, files in bucket.items():

    path = files_path / Path(f'files{i}.json')

    print(f'Writing file: {path} with count: {len(bucket[i])}')
    path.write_text(json.dumps(bucket[i]))

print(f'Final file count: {df.shape[0]}')

sources_values = df['source'].value_counts()
paths_values = df['VersionInfo.FileName'].apply(lambda x: PureWindowsPath(x).parent).value_counts()

with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also

    print(sources_values)
    print(paths_values)

meta_path = files_path / 'meta'
meta_path.mkdir(exist_ok=True)

sources_values_path = meta_path / 'sources_values.md'
sources_values.to_markdown(sources_values_path)

paths_values_path = meta_path / 'paths_values.md'
paths_values.to_markdown(paths_values_path)

df_path = meta_path / 'pandas_query_df.json'
df.reset_index(names='sha256', inplace=True)
df.to_json(df_path)

df_proc_md_path = meta_path / 'proc_pandas_query.md'
df_proc_path = meta_path / 'proc_pandas_query.json'


proc_df = pd.read_json(PROCMON_MODLOAD_JSON_PATH)
proc_df = proc_df.reset_index(names=['Path'])
proc_df['is_priv'] = proc_df['User'].astype(str).str.contains('SYSTEM|SERVICE|LOCAL')

df = df.rename(columns={'VersionInfo.FileName': 'Path'})
merged_df = proc_df.merge(df, on='Path', how='inner')
merged_df.to_markdown(df_proc_md_path, tablefmt="github")
merged_df.to_json(df_proc_path)

x_sources_values = merged_df['source_x'].value_counts()
y_sources_values = merged_df['source_y'].value_counts()
paths_values = merged_df['Path'].apply(lambda x: PureWindowsPath(x).parent).value_counts()

with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also

    print(x_sources_values)
    print(y_sources_values)
    print(paths_values)


pd.read_json(df_proc_path)
pd.read_json(df_path)


args_path = meta_path / 'args.json'
args_path.write_text(json.dumps(vars(args)))
