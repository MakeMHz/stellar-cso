#!/usr/bin/python3
# Copyright 2018 David O'Rourke <david.orourke@gmail.com>
# Copyright 2022 MakeMHz LLC <contact@makemhz.com>
# Based on ciso from https://github.com/jamie/ciso

import os
import struct
import sys
import math
import multiprocessing
import signal
import lz4.frame

CISO_MAGIC = 0x4F534943 # CISO
CISO_HEADER_SIZE = 0x18 # 24
CISO_BLOCK_SIZE = 0x800 # 2048
CISO_HEADER_FMT = '<LLQLBBxx' # Little endian
CISO_PLAIN_BLOCK = 0x80000000

CISO_SPLIT_SIZE = 0xFFBF6000
CHUNK_SIZE      = 1 * 1024 * 1024 # 1MB chunk size
CHUNK_SIZE_SECT = int(CHUNK_SIZE / CISO_BLOCK_SIZE)
MP_NUM_CHUNKS   = 64 # number of chunks to read for multiprocessing
MP_CHUNK_SIZE   = MP_NUM_CHUNKS * CHUNK_SIZE

#assert(struct.calcsize(CISO_HEADER_FMT) == CISO_HEADER_SIZE)

image_offset = 0

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

def check_file_size(f):
	global image_offset

	f.seek(0, os.SEEK_END)
	file_size = f.tell() - image_offset
	ciso = {
			'magic': CISO_MAGIC,
			'ver': 2,
			'block_size': CISO_BLOCK_SIZE,
			'total_bytes': file_size,
			'total_blocks': int(file_size / CISO_BLOCK_SIZE),
			'align': 2,
			}
	f.seek(image_offset, os.SEEK_SET)
	return ciso

def write_cso_header(f, ciso):
	f.write(struct.pack(CISO_HEADER_FMT,
		ciso['magic'],
		CISO_HEADER_SIZE,
		ciso['total_bytes'],
		ciso['block_size'],
		ciso['ver'],
		ciso['align']
		))

def write_block_index(f, block_index):
	for index, block in enumerate(block_index):
		try:
			f.write(struct.pack('<I', block))
		except Exception as e:
			print("Writing block={} with data={} failed.".format(
				index, block))
			print(e)
			sys.exit(1)

def detect_iso_type(f):
	global image_offset

	# Detect if the image is a REDUMP image
	f.seek(0x18310000)
	buffer = f.read(20)
	if buffer == b"MICROSOFT*XBOX*MEDIA":
		print("REDUMP image detected")
		image_offset = 0x18300000
		return

	# Detect if the image is a raw XDVDFS image
	f.seek(0x10000)
	buffer = f.read(20)
	if buffer == b"MICROSOFT*XBOX*MEDIA":
		image_offset = 0
		return

	# Print error and exit
	print("ERROR: Could not detect ISO type.")
	sys.exit(1)

# Pad file size to ATA block size * 2
def pad_file_size(f):
	f.seek(0, os.SEEK_END)
	size = f.tell()
	f.write(struct.pack('<B', 0x00) * (0x400 - (size & 0x3FF)))

def child_sigint(signalnum, frame):
	me = multiprocessing.current_process()
	if me:
		me.close()

def compress_chunk(sector_list):
	signal.signal(signal.SIGINT, child_sigint)
	try:
		# cache a single instance of the lz4 context, per process
		if not hasattr(compress_chunk, 'lz4_context'):
			compress_chunk.lz4_context = lz4.frame.create_compression_context()

		lz4_context   = compress_chunk.lz4_context
		compress_list = []

		for raw_data in sector_list:
			# Compress block
			# Compressed data will have the gzip header on it, we strip that.
			lz4.frame.compress_begin(lz4_context, compression_level=lz4.frame.COMPRESSIONLEVEL_MAX,
				auto_flush=True, content_checksum=False, block_checksum=False, block_linked=False, source_size=False)

			compressed_data = lz4.frame.compress_chunk(lz4_context, raw_data, return_bytearray=True)
			compress_list.append(compressed_data)
			lz4.frame.compress_flush(lz4_context)

		# this will be a list of compressed sectors
		return compress_list
	except:
		me = multiprocessing.current_process()
		if me:
			me.close()

def compress_iso(infile):
	pool = multiprocessing.Pool()

	# Replace file extension with .cso
	fout_1 = open(os.path.splitext(infile)[0] + '.1.cso', 'wb')
	fout_2 = None

	with open(infile, 'rb') as fin:
		print("Compressing '{}'".format(infile))

		# Detect and validate the ISO
		detect_iso_type(fin)

		ciso = check_file_size(fin)
		for k, v in ciso.items():
			print("{}: {}".format(k, v))

		write_cso_header(fout_1, ciso)
		block_index = [0x00] * (ciso['total_blocks'] + 1)

		# Write the dummy block index for now.
		write_block_index(fout_1, block_index)

		write_pos = len(block_index) * 4 + CISO_HEADER_SIZE
		align_b = 1 << ciso['align']
		align_m = align_b - 1

		# Alignment buffer is unsigned char.
		alignment_buffer = struct.pack('<B', 0x00) * 64

		# Progress counters
		percent_period = ciso['total_blocks'] / 100
		percent_cnt = 0

		split_fout      = fout_1
		out_bytes       = bytearray()
		mp_chunks_total = math.ceil(ciso['total_bytes'] / MP_CHUNK_SIZE)

		# read in several chunks at once
		for mp_chunk in range(0, mp_chunks_total):
			mp_chunk_data = fin.read(MP_CHUNK_SIZE)
			mp_chunk_data_list = [mp_chunk_data[i: i + CHUNK_SIZE] for i in range(0, len(mp_chunk_data), CHUNK_SIZE)]
			del mp_chunk_data
			mp_chunk_data_list_len = len(mp_chunk_data_list)
			mp_chunk_data_len_list = []
			mp_chunk_list          = []

			# split each chunk into a sectors list
			for chunk_data in mp_chunk_data_list:
				sector_list = [chunk_data[i: i + CISO_BLOCK_SIZE] for i in range(0, len(chunk_data), CISO_BLOCK_SIZE)]
				mp_chunk_data_len_list.append(len(chunk_data))
				mp_chunk_list.append(sector_list)

			del mp_chunk_data_list

			try:
				# compress several chunks at once (handed off to child processes)
				mp_compressed_list = pool.map(compress_chunk, mp_chunk_list)
			except:
				pool.terminate()
				pool.join()
				sys.exit()

			# setup chunk/sector mapping
			for chunk in range(0, mp_chunk_data_list_len):
				chunk_len         = mp_chunk_data_len_list[chunk]
				chunk_sectors_len = CHUNK_SIZE_SECT

				sector_list     = mp_chunk_list[chunk]
				compressed_list = mp_compressed_list[chunk]

				if chunk_len != CHUNK_SIZE:
					chunk_sectors_len = int(chunk_len / CISO_BLOCK_SIZE)

				# the (mostly) original sector process loop
				for sector in range(0, chunk_sectors_len):
					block = int(MP_CHUNK_SIZE / CISO_BLOCK_SIZE * mp_chunk) + (CHUNK_SIZE_SECT * chunk) + sector
					#chunk_pos = sector * CISO_BLOCK_SIZE

					# Check if we need to split the ISO (due to FATX limitations)
					# TODO: Determine a better value for this.
					if write_pos > CISO_SPLIT_SIZE:
						# Create new file for the split
						fout_2     = open(os.path.splitext(infile)[0] + '.2.cso', 'wb')
						split_fout = fout_2

						# Reset write position
						write_pos = 0

					# Write alignment
					align = int(write_pos & align_m)
					if align:
						align = align_b - align
						out_bytes += alignment_buffer[:align]
						write_pos += align

					# Mark offset index
					block_index[block] = write_pos >> ciso['align']

					# Read raw data
					raw_data = sector_list[sector]
					raw_data_size = len(raw_data)

					compressed_data = compressed_list[sector]
					compressed_size = len(compressed_data)

					# Ensure compressed data is smaller than raw data
					# TODO: Find optimal block size to avoid fragmentation
					if (compressed_size + 12) >= raw_data_size:
						writable_data = raw_data

						# Next index
						write_pos += raw_data_size
					else:
						writable_data = compressed_data

						# LZ4 block marker
						block_index[block] |= 0x80000000

						# Next index
						write_pos += compressed_size

					# Write data
					out_bytes += writable_data

					if len(out_bytes) >= CHUNK_SIZE or write_pos > CISO_SPLIT_SIZE:
						split_fout.write(out_bytes)
						out_bytes.clear()

					# Progress bar
					percent = int(round((block / (ciso['total_blocks'] + 1)) * 100))
					if percent > percent_cnt:
						update_progress((block / (ciso['total_blocks'] + 1)))
						percent_cnt = percent

		# flush left-over bytes
		split_fout.write(out_bytes)

		# TODO: Pad file to ATA block size

		# end for block
		# last position (total size)
		# NOTE: We don't actually need this, but we're keeping it for legacy reasons.
		block_index[-1] = write_pos >> ciso['align']

		# write header and index block
		print("\nWriting block index")
		fout_1.seek(CISO_HEADER_SIZE, os.SEEK_SET)
		write_block_index(fout_1, block_index)

	# end open(infile)
	pad_file_size(fout_1)
	fout_1.close()

	if fout_2:
		pad_file_size(fout_2)
		fout_2.close()

def main(argv):
	infile = argv[1]
	compress_iso(infile)

if __name__ == '__main__':
	multiprocessing.freeze_support()
	sys.exit(main(sys.argv))
