#!/usr/bin/python3
# Copyright 2018 David O'Rourke <david.orourke@gmail.com>
# Copyright 2022 MakeMHz LLC <contact@makemhz.com>
# Based on ciso from https://github.com/jamie/ciso

import os
import struct
import sys
import shutil
import platform
import subprocess
import math
import enum
import lz4.frame

CISO_MAGIC = 0x4F534943 # CISO
CISO_HEADER_SIZE = 0x18 # 24
CISO_BLOCK_SIZE = 0x800 # 2048
CISO_HEADER_FMT = '<LLQLBBxx' # Little endian
CISO_PLAIN_BLOCK = 0x80000000

#assert(struct.calcsize(CISO_HEADER_FMT) == CISO_HEADER_SIZE)

image_offset = 0
is_redump_converted = False

class XbeInfo(enum.Enum):
	TITLE = 1
	TITLE_ID = 2
	TITLE_VER = 3
	TITLE_IMG = 4

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

def is_redump(iso_file):
	with open(iso_file, 'rb') as f:
		# Detect if the image is a REDUMP image
		f.seek(0x18310000)
		buffer = f.read(20)
		if buffer == b"MICROSOFT*XBOX*MEDIA":
			return True
	return False

def is_redump_convert_blacklisted(iso_file, xbe_file = 'default.xbe'):
	title_id = extract_xbe_info_from_iso(iso_file, XbeInfo.TITLE_ID, xbe_file)

	# TOCA Race Driver 3
	if title_id == 0x434D0050:
		return True

	return False

def extract_xbe_info_from_iso(iso_file, what = XbeInfo.TITLE, xbe_file = 'default.xbe'):
	xbe_offset = get_file_offset_in_iso(iso_file, xbe_file)
	ret = None

	xbe_header_size       = 0x1000
	base_addr_offset      = 0x104
	cert_addr_offset      = 0x118
	cert_title_id_offset  = 0x8
	cert_title_offset     = 0xc
	cert_title_ver_offset = 0xac

	with open(iso_file, 'rb') as f:
		f.seek(xbe_offset)
		header_bytes = f.read(xbe_header_size * 10)

		base_addr = struct.unpack('<I', header_bytes[base_addr_offset: base_addr_offset + 4])[0]
		cert_addr = struct.unpack('<I', header_bytes[cert_addr_offset: cert_addr_offset + 4])[0]

		if what == XbeInfo.TITLE:
			offset = cert_addr - base_addr + cert_title_offset
			title_bytes = header_bytes[offset: offset + TITLE_MAX_LENGTH * 2]
			ret = title_bytes.decode('utf-16-le').replace('\0', '')
		elif what == XbeInfo.TITLE_ID:
			offset = cert_addr - base_addr + cert_title_id_offset
			title_id_bytes = header_bytes[offset: offset + 4]
			ret = struct.unpack("<I", title_id_bytes)[0]
		elif what == XbeInfo.TITLE_VER:
			offset = cert_addr - base_addr + cert_title_ver_offset
			title_ver_bytes = header_bytes[offset: offset + 4]
			ret = struct.unpack("<I", title_ver_bytes)[0]
		elif what == XbeInfo.TITLE_IMG:
			pass

	return ret

def convert_to_xiso(iso_file):
	os_name = platform.system()
	if os_name == 'Windows':
		print("Calling extract-xiso.exe...\n")
		iso_file = convert_to_xiso_win(iso_file)
		print("")
	elif os_name == 'Darwin':
		pass
	elif os_name == 'Linux':
		pass
	return iso_file

def convert_to_xiso_win(iso_file):
	abs_file  = os.path.abspath(iso_file)
	basename  = os.path.basename(abs_file)
	dirname   = os.path.dirname(abs_file)
	old_file  = abs_file + '.old'
	basename_split = os.path.splitext(basename)[0]
	xiso_file = dirname + '/' + basename_split + '.xiso.iso'

	extract_iso_exe = os.path.dirname(os.path.abspath(__file__)) + '/' + 'extract-xiso.exe'

	if not os.path.isfile(extract_iso_exe):
		return iso_file

	if os.path.isfile(old_file):
		os.remove(old_file)

	cmd = (
		extract_iso_exe,
		'-r',
		'-m',
		abs_file
	)

	res = subprocess.run(cmd, shell=True)

	if os.path.isfile(xiso_file):
		os.remove(xiso_file)

	shutil.move(abs_file, xiso_file)
	shutil.move(old_file, abs_file)

	return xiso_file

def compress_iso(infile):
	global is_redump_converted

	lz4_context = lz4.frame.create_compression_context()

	if is_redump(infile) and not is_redump_convert_blacklisted(infile):
		print("Converting to XISO...")
		abs_xiso_file = os.path.abspath(convert_to_xiso(infile))
		abs_infile    = os.path.abspath(infile)
		if abs_xiso_file != abs_infile and os.path.isfile(abs_xiso_file) and os.path.isfile(abs_infile):
			is_redump_converted = True
			infile = abs_xiso_file

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

		write_pos = fout_1.tell()
		align_b = 1 << ciso['align']
		align_m = align_b - 1

		# Alignment buffer is unsigned char.
		alignment_buffer = struct.pack('<B', 0x00) * 64

		# Progress counters
		percent_period = ciso['total_blocks'] / 100
		percent_cnt = 0

		split_fout = fout_1

		for block in range(0, ciso['total_blocks']):
			# Check if we need to split the ISO (due to FATX limitations)
			# TODO: Determine a better value for this.
			if write_pos > 0xFFBF6000:
				# Create new file for the split
				fout_2     = open(os.path.splitext(infile)[0] + '.2.cso', 'wb')
				split_fout = fout_2

				# Reset write position
				write_pos  = 0

			# Write alignment
			align = int(write_pos & align_m)
			if align:
				align = align_b - align
				size = split_fout.write(alignment_buffer[:align])
				write_pos += align

			# Mark offset index
			block_index[block] = write_pos >> ciso['align']

			# Read raw data
			raw_data = fin.read(ciso['block_size'])
			raw_data_size = len(raw_data)

			# Compress block
			# Compressed data will have the gzip header on it, we strip that.
			lz4.frame.compress_begin(lz4_context, compression_level=lz4.frame.COMPRESSIONLEVEL_MAX,
				auto_flush=True, content_checksum=False, block_checksum=False, block_linked=False, source_size=False)

			compressed_data = lz4.frame.compress_chunk(lz4_context, raw_data, return_bytearray=True)
			compressed_size = len(compressed_data)

			lz4.frame.compress_flush(lz4_context)

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
			split_fout.write(writable_data)

			# Progress bar
			percent = int(round((block / (ciso['total_blocks'] + 1)) * 100))
			if percent > percent_cnt:
				update_progress((block / (ciso['total_blocks'] + 1)))
				percent_cnt = percent

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

	if is_redump_converted:
		os.remove(infile)

def get_iso_root_dir_offset_and_size(iso_file):
	global image_offset

	iso_header_offset    = 0x10000
	root_dir_sect_offset = 0x14
	sector_size          = 0x800

	with open(iso_file, 'rb') as f:
		detect_iso_type(f)

		f.seek(image_offset + iso_header_offset + root_dir_sect_offset)
		root_dir_sect   = struct.unpack('<I', f.read(4))[0]
		root_dir_offset = image_offset + root_dir_sect * sector_size
		root_dir_size   = struct.unpack('<I', f.read(4))[0]

	return root_dir_offset, root_dir_size

def get_file_offset_in_iso(iso_file, search_file):
	global image_offset

	file_offset, file_size = get_iso_root_dir_offset_and_size(iso_file)

	for item in search_file.split('\\'):
		file_offset, file_size = get_iso_entry_offset_and_size(iso_file, item, file_offset, file_size)

		if file_offset == 0 or file_size == 0:
			return 0

		file_offset += image_offset

	return file_offset

def get_iso_entry_offset_and_size(iso_file, search_file, dir_offset, dir_size):
	dir_ent_size = 0xe
	sector_size  = 0x800
	dword        = 4

	search_file = search_file.casefold()

	with open(iso_file, 'rb') as f:
		# seek to dir
		dir_sectors = math.ceil(dir_size / sector_size)
		f.seek(dir_offset)

		dir_bytes        = f.read(dir_sectors * sector_size)
		dir_sector_bytes = [dir_bytes[i: i + sector_size] for i in range(0, len(dir_bytes), sector_size)]

		# loop through dir entries
		for sector_bytes in dir_sector_bytes:
			cur_pos = 0

			while True:
				cur_pos_diff = sector_size - cur_pos

				if cur_pos_diff <= 1:
					break

				dir_ent  = sector_bytes[cur_pos: cur_pos + dir_ent_size]
				cur_pos += dir_ent_size
				l_offset = struct.unpack('<H', dir_ent[0:2])[0]

				if l_offset == 0xffff:
					break

				r_offset     = struct.unpack('<H', dir_ent[2:4])[0]
				start_sector = struct.unpack('<I', dir_ent[4:8])[0]
				file_size    = struct.unpack('<I', dir_ent[8:12])[0]
				attribs      = struct.unpack('<B', dir_ent[12:13])[0]
				filename_len = struct.unpack('<B', dir_ent[13:14])[0]
				filename     = sector_bytes[cur_pos: cur_pos + filename_len].decode('utf-8')

				#print("entry: %04X %04X %08X %02X" % (l_offset, r_offset, start_sector, attribs), file_size, filename_len, filename)

				# entries are aligned on 4 byte bounderies
				next_offset = (dword - ((dir_ent_size + filename_len) % dword)) % dword
				cur_pos += filename_len + next_offset

				# our entry was found, return the offset
				if filename.casefold() == search_file:
					ret_offset = start_sector * sector_size
					return ret_offset, file_size

	# entry wasn't found
	return 0, 0

def main(argv):
	global is_redump_converted

	infile = argv[1]
	compress_iso(infile)

	is_redump_converted = False

if __name__ == '__main__':
	sys.exit(main(sys.argv))
