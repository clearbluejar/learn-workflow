from pathlib import Path
import argparse
import json
from concurrent.futures import ThreadPoolExecutor  # pip install futures
from concurrent import futures
from subprocess import STDOUT, call


def rm_tree(pth):
    pth = Path(pth)
    for child in pth.glob('*'):
        if child.is_file():
            child.unlink()
        else:
            rm_tree(child)
    pth.rmdir()


parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument("--id", type=int, help="fileid to download from", required=True)
parser.add_argument("--fl_path", help="File List Path", default='bins/meta')
parser.add_argument("--proc-limit", help="concurrent process limit", type=int, default=2)


args = parser.parse_args()

file_list_path = Path(args.fl_path) / f'dl_files{args.id}.json'


files_info_list = json.loads(file_list_path.read_bytes())

file_paths = []
for status, file, pe_ver, file_path in files_info_list:

    print(f"path... {file_path}")

    file_paths.append(Path(file_path))

log_path = file_list_path.parent.parent / 'decomp_logs'
# fresh logs
if log_path.exists():
    rm_tree(log_path)
log_path.mkdir(exist_ok=True)


with ThreadPoolExecutor(max_workers=args.proc_limit) as executor:

    log_paths = []
    for file_path in file_paths:
        file_log_path = log_path / f'{file_path.name}.log'
        cmd = f'ghidrecomp --va {file_path}'
        # cmd = f'pwd'

        log_paths.append([file_log_path, cmd])

    future_sub = (executor.submit(call, cmd, stdout=log.open('w'), stderr=STDOUT, shell=True)
                  for log, cmd in log_paths)

    for future in futures.as_completed(future_sub):
        print(future.result())
