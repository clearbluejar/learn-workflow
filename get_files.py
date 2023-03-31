from pathlib import Path


all_bins_path = Path('bins')

all_bins_path.mkdir(exist_ok=True)

bin_path = all_bins_path / 'hello.bin'

bin_path.write_text('hello')

print('hello')
