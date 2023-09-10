#!/usr/bin/python3

import os
import struct
import sys
import lz4.frame

CISO_MAGIC = 0x4F534943 # CISO
CISO_HEADER_SIZE = 0x18 # 24
CISO_BLOCK_SIZE = 0x800 # 2048
CISO_HEADER_FMT = '<LLQLBBxx' # Little endian
CISO_SPLIT_SIZE = 0xFFBF6000
CISO_SPLIT_BLOCK_SIZE = int(CISO_SPLIT_SIZE / CISO_BLOCK_SIZE)

already_done = []

def get_terminal_size(fd=sys.stdout.fileno()):
	try:
		import fcntl, termios
		hw = struct.unpack("hh", fcntl.ioctl(
			fd, termios.TIOCGWINSZ, '1234'))
	except:
		try:
			hw = (os.environ['LINES'], os.environ['COLUMNS'])
		except:
			hw = (25, 80)
	return hw

(console_height, console_width) = get_terminal_size()

def update_progress(progress):
	barLength = console_width - len("Progress: 100% []") - 1
	block = int(round(barLength*progress)) + 1
	text = "\rProgress: [{blocks}] {percent:.0f}%".format(
			blocks="#" * block + "-" * (barLength - block),
			percent=progress * 100)
	sys.stdout.write(text)
	sys.stdout.flush()

def is_ciso_file(infile):
	if not os.path.exists(infile):
		return False

	with open(infile, 'rb') as f:
		magic = struct.unpack('<I', f.read(4))[0]
		if magic == CISO_MAGIC:
			return True

	return False

def decompress_cso(infile):
	global already_done

	base_dir      = os.path.dirname(os.path.abspath(infile))
	iso_base_name = os.path.splitext(os.path.basename(infile))[0]
	iso_base_name = os.path.splitext(iso_base_name)[0]
	base_iso_name = base_dir + '/' + iso_base_name
	infile1       = base_iso_name + '.1.cso'
	infile2       = base_iso_name + '.2.cso'
	outfile       = base_iso_name + '.xiso.iso'

	if base_iso_name in already_done:
		return

	if not is_ciso_file(infile1):
		return

	already_done.append(base_iso_name)
	lz4_context = lz4.frame.create_decompression_context()

	# This matches the options passed to lz4.frame.compress_begin
	# when the cso was created. It's the same for every frame
	# https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
	# Original options:
	#		lz4.frame.compress_begin(lz4_context, compression_level=lz4.frame.COMPRESSIONLEVEL_MAX,
	#			auto_flush=True, content_checksum=False, block_checksum=False, block_linked=False, source_size=False)
	lz4_frame_header = b'\x04\x22\x4D\x18\x60\x40\x82'

	# Missing data from calling lz4.frame.compress_flush()
	# It's always the same for every frame
	lz4_frame_end = b'\x00\x00\x00\x00'

	fout = open(outfile, 'wb')
	fin  = open(infile1, 'rb')

	print("Decompressing '{}'".format(os.path.basename(infile1)))
	cso_header_bytes = fin.read(CISO_HEADER_SIZE)

	(
		magic,
		cso_header_size,
		total_bytes,
		block_size,
		ver,
		align
	) = struct.unpack(CISO_HEADER_FMT, cso_header_bytes)

	total_blocks  = int(total_bytes / block_size)
	total_blocks2 = total_blocks + 1
	index_size    = total_blocks2 * 4
	block_index   = struct.unpack('<{}I'.format(total_blocks2), fin.read(index_size))
	block_marker  = 0x80000000
	percent_cnt   = 0

	for index, block in enumerate(block_index):
		if index == total_blocks:
			break

		next_block   = block_index[index + 1]
		is_lz4_frame = bool(block & block_marker)
		offset       = (block & block_marker - 1) << align
		offset_nb    = (next_block & block_marker - 1) << align
		read_len     = offset_nb - offset
		is_last_blk  = False

		if offset + block_size > CISO_SPLIT_SIZE:
			is_last_blk = True
			read_len = block_size

		raw_data = fin.read(read_len)

		if is_lz4_frame:
			frame_size  = struct.unpack('<I', raw_data[0: 4])[0]
			is_comp     = frame_size & 0x80000000
			frame_size &= 0x7fffffff
			raw_data    = raw_data[0: frame_size + 4] # strip align padding

			raw_data = lz4_frame_header + raw_data + lz4_frame_end

			lz4.frame.reset_decompression_context(lz4_context)
			decomp_data = lz4.frame.decompress_chunk(lz4_context, raw_data)[0]
			fout.write(decomp_data)
		else:
			fout.write(raw_data)

		# Progress bar
		percent = int(round((index / total_blocks2) * 100))
		if percent > percent_cnt:
			update_progress((index / (total_blocks2)))
			percent_cnt = percent

		if is_last_blk:
			fin.close()
			print("\nDecompressing '{}'".format(os.path.basename(infile2)))
			fin = open(infile2, 'rb')

	print("")
	return True


def main(argv):
	for i in range(1, len(argv)):
		infile = argv[i]
		decompress_cso(infile)

	input("Press Enter to continue...")

if __name__ == '__main__':
	sys.exit(main(sys.argv))
