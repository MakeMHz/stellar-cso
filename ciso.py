#!/usr/bin/python3
# Copyright 2018 David O'Rourke <david.orourke@gmail.com>
# Copyright 2022 MakeMHz LLC <contact@makemhz.com>
# Based on ciso from https://github.com/jamie/ciso

import os
import struct
import sys
import math
import multiprocessing
import multiprocessing.shared_memory
import signal
import lz4.frame

CISO_MAGIC = 0x4F534943 # CISO
CISO_HEADER_SIZE = 0x18 # 24
CISO_BLOCK_SIZE = 0x800 # 2048
CISO_HEADER_FMT = '<LLQLBBxx' # Little endian
CISO_PLAIN_BLOCK = 0x80000000

CISO_SPLIT_SIZE = 0xFFBF6000
CHUNK_SIZE      = 128 * 1024
CHUNK_NUM_SECT  = int(CHUNK_SIZE / CISO_BLOCK_SIZE)

MP_NUM_CHUNKS = 64 # number of chunks to read for multiprocessing
MP_CHUNK_SIZE = MP_NUM_CHUNKS * CHUNK_SIZE
MP_CHUNK_SECT = MP_CHUNK_SIZE / CISO_BLOCK_SIZE

CMP_LIST_SMH_PAD  = 4 # pad bytes for each sector in compressed list shm
CMP_LIST_SMH_PAD_SIZE = (CISO_BLOCK_SIZE + CMP_LIST_SMH_PAD) * CHUNK_NUM_SECT * MP_NUM_CHUNKS
SHM_IN_SECT_NAME  = 'ciso_shm_in_sectors'
SHM_CMP_SECT_NAME = 'ciso_shm_cmp_sectors'

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

def compress_chunk(chunk):
	signal.signal(signal.SIGINT, child_sigint)
	try:
		# cache a single instance of the lz4 context, per process
		if not hasattr(compress_chunk, 'lz4_context'):
			compress_chunk.lz4_context = lz4.frame.create_compression_context()
		if not hasattr(compress_chunk, 'inshm'):
			compress_chunk.inshm = multiprocessing.shared_memory.SharedMemory(name=SHM_IN_SECT_NAME)
		if not hasattr(compress_chunk, 'cmpshm'):
			compress_chunk.cmpshm = multiprocessing.shared_memory.SharedMemory(name=SHM_CMP_SECT_NAME)
		if not hasattr(compress_chunk, 'empty_sect'):
			compress_chunk.empty_sect = b"\0" * CISO_BLOCK_SIZE

		inshm  = compress_chunk.inshm
		cmpshm = compress_chunk.cmpshm
		lz4_context = compress_chunk.lz4_context
		compressed_sizes = []
		out_bytes = bytearray()

		in_offset  = chunk * CHUNK_SIZE
		out_offset = chunk * CHUNK_NUM_SECT * CMP_LIST_SMH_PAD + in_offset

		chunk_data  = bytearray(inshm.buf[in_offset: in_offset + CHUNK_SIZE])
		num_sectors = math.ceil(len(chunk_data) / CISO_BLOCK_SIZE)

		for sector in range(num_sectors):
			sector_offset = sector * CISO_BLOCK_SIZE
			raw_data = chunk_data[sector_offset: sector_offset + CISO_BLOCK_SIZE]

			if raw_data == compress_chunk.empty_sect:
				compressed_data = b"\x12\x00\x00\x00\x1F\x00\x01\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xEE\x50\x00\x00\x00\x00\x00"
			else:
				# Compress block
				# Compressed data will have the gzip header on it, we strip that.
				lz4.frame.compress_begin(lz4_context, compression_level=lz4.frame.COMPRESSIONLEVEL_MAX,
					auto_flush=True, content_checksum=False, block_checksum=False, block_linked=False, source_size=False)
				compressed_data = lz4.frame.compress_chunk(lz4_context, raw_data, return_bytearray=True)
				lz4.frame.compress_flush(lz4_context)

			out_bytes += compressed_data
			compressed_size = len(compressed_data)
			compressed_sizes.append(compressed_size)

		cmpshm.buf[out_offset: out_offset + len(out_bytes)] = out_bytes
		return compressed_sizes

	except:
		me = multiprocessing.current_process()
		if me:
			me.close()

def compress_iso(infile):
	pool   = multiprocessing.Pool()
	inshm  = multiprocessing.shared_memory.SharedMemory(name=SHM_IN_SECT_NAME, create=True, size=MP_CHUNK_SIZE)
	cmpshm = multiprocessing.shared_memory.SharedMemory(name=SHM_CMP_SECT_NAME, create=True, size=CMP_LIST_SMH_PAD_SIZE)

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

		chunks_range = range(MP_NUM_CHUNKS)

		# read in several chunks at once
		for mp_chunk in range(mp_chunks_total):
			mp_chunk_data     = fin.read(MP_CHUNK_SIZE)
			mp_chunk_data_len = len(mp_chunk_data)
			map_range         = chunks_range

			if mp_chunk_data_len != MP_CHUNK_SIZE:
				map_range = range(math.ceil(mp_chunk_data_len / CHUNK_SIZE))

			inshm.buf[0: mp_chunk_data_len] = mp_chunk_data

			try:
				# compress several chunks at once
				compressed_sizes = pool.map(compress_chunk, map_range)
			except:
				pool.terminate()
				pool.join()
				sys.exit()

			inshm_bytes  = bytearray(inshm.buf)
			cmpshm_bytes = bytearray(cmpshm.buf)

			for chunk, compressed_sizes_list in enumerate(compressed_sizes):
				chunk_offset     = chunk * CHUNK_SIZE
				cmp_chunk_offset = chunk * CHUNK_NUM_SECT * CMP_LIST_SMH_PAD + chunk_offset
				cmp_sect_offset  = 0

				for sector, compressed_size in enumerate(compressed_sizes_list):
					block = int(MP_CHUNK_SECT * mp_chunk) + (CHUNK_NUM_SECT * chunk) + sector

					if block >= ciso['total_blocks']:
						break

					raw_block_offset = sector * CISO_BLOCK_SIZE

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

					# Ensure compressed data is smaller than raw data
					# TODO: Find optimal block size to avoid fragmentation
					if (compressed_size + 12) >= CISO_BLOCK_SIZE:
						offset = chunk_offset + raw_block_offset
						out_bytes += inshm_bytes[offset: offset + CISO_BLOCK_SIZE]

						# Next index
						write_pos += CISO_BLOCK_SIZE
					else:
						offset = cmp_chunk_offset + cmp_sect_offset
						out_bytes += cmpshm_bytes[offset: offset + compressed_size]

						# LZ4 block marker
						block_index[block] |= 0x80000000

						# Next index
						write_pos += compressed_size

					cmp_sect_offset += compressed_size

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
