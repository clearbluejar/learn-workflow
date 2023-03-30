from pandas.api.types import infer_dtype
from cvedata.win_verinfo import ALL_VERINFO_FULL_PATH, ALL_VERINFO_MERGED_PATH
import pandas as pd
from pathlib import Path
import json
import argparse


merged_df = pd.read_json(ALL_VERINFO_MERGED_PATH)

sources = merged_df['source'].explode().unique()

parser = argparse.ArgumentParser()

parser.add_argument("--include", nargs='+', action='extend', help="filter key=value")
parser.add_argument("--exclude",  nargs='+', action='extend', help="filter key=value")
parser.add_argument("--count", type=int, help="number of files to generate", required=True)
parser.add_argument("--source", choices=sources, default=sources[0])


args = parser.parse_args()

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


print(f'Final file count: {df.shape[0]}')
print(df['source'].value_counts())

# df = df.reset_index()

df = df.sort_values(by='size')

print(df.head())

df_d = df.to_dict(orient='index')

bucket = {}
# items sorted by size.. file the buckets evenly
for i, file in df_d.items():

    id = i % args.count
    bucket.setdefault(id, []).append(file)

    print(file['size'])

files_path = Path('gen_files')
files_path.mkdir(exist_ok=True)

for i, files in bucket.items():

    path = files_path / Path(f'files{i}.json')
    path.write_text(json.dumps(bucket[i]))
