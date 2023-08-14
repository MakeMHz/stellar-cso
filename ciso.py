#!/usr/bin/python3
# Copyright 2018 David O'Rourke <david.orourke@gmail.com>
# Copyright 2022 MakeMHz LLC <contact@makemhz.com>
# Based on ciso from https://github.com/jamie/ciso

import os
import struct
import sys
import shutil
import lz4.frame

CISO_MAGIC = 0x4F534943 # CISO
CISO_HEADER_SIZE = 0x18 # 24
CISO_BLOCK_SIZE = 0x800 # 2048
CISO_HEADER_FMT = '<LLQLBBxx' # Little endian
CISO_PLAIN_BLOCK = 0x80000000

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

def compress_iso(infile):
	lz4_context = lz4.frame.create_compression_context()

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


def is_xbe_file(xbe):
	if not os.path.isfile(xbe):
		return False

	with open(xbe, 'rb') as xbe_file:
		magic = xbe_file.read(4)

		if magic != b'XBEH':
			return False

	return True

def get_default_xbe_file_offset_in_iso(iso_file):
	return get_file_offset_in_iso(iso_file, 'default.xbe')

# only looks in root dir
def get_file_offset_in_iso(iso_file, search_file):
	global image_offset

	sector_size          = 0x800
	iso_header_offset    = 0x10000
	iso_header_magic_len = 20
	filename_offset      = 14

	search_file = search_file.casefold()

	with open(iso_file, 'rb') as f:
		detect_iso_type(f)

		# seek to root dir
		f.seek(image_offset + iso_header_offset + iso_header_magic_len)
		root_dir_offset = image_offset + struct.unpack('<I', f.read(4))[0] * sector_size
		f.seek(root_dir_offset)

		l_offset = 0
		dword    = 4

		# loop through root dir entries
		while True:
			l_offset = struct.unpack('<H', f.read(2))[0]

			# end of dir entries
			if l_offset == 0xffff:
				break

			r_offset     = struct.unpack('<H', f.read(2))[0]
			start_sector = struct.unpack('<I', f.read(4))[0]
			file_size    = struct.unpack('<I', f.read(4))[0]
			attribs      = struct.unpack('<B', f.read(1))[0]
			filename_len = struct.unpack('<B', f.read(1))[0]
			filename     = f.read(filename_len).decode('utf-8')

			#print("entry:", format(l_offset), format(r_offset), format(start_sector), format(file_size), format(attribs), format(filename_len), filename)

			# entries are aligned on 4 byte bounderies
			next_offset = (dword - ((filename_offset + filename_len) % dword)) % dword
			f.seek(next_offset, os.SEEK_CUR)

			# our file was found, return the abs offset
			if filename.casefold() == search_file:
				return image_offset + start_sector * sector_size

	# entry wasn't found
	return 0

# read C-style strings
def readcstr(bytes, start):
	end = bytes.find(b'\0', start)
	sub = bytes[start: end]

	return sub.decode()

def gen_attach_xbe(iso_file):
	base_dir      = os.path.dirname(os.path.abspath(iso_file))
	in_file_name  = os.path.dirname(os.path.abspath(__file__)) + '/attach_cso.xbe'
	out_file_name = base_dir + '/default.xbe'
	iso_base_name = os.path.splitext(os.path.basename(iso_file))[0]

	if not is_xbe_file(in_file_name):
		return

	xbe_offset = get_default_xbe_file_offset_in_iso(iso_file)

	if xbe_offset == 0:
		return

	# https://www.caustik.com/cxbx/download/xbe.htm
	title_max_length      = 40
	title_img_sect_name   = '$$XTIMAGE'
	num_new_sections      = 1
	xbe_header_size       = 0x1000
	section_header_size   = 0x38
	base_addr_offset      = 0x104
	xbe_img_size_offset   = 0x10c
	cert_addr_offset      = 0x118
	num_sections_offset   = 0x11c
	sect_headers_offset   = 0x120
	sect_rv_addr_offset   = 0x4
	sect_rv_size_offset   = 0x8
	sect_raw_addr_offset  = 0xc
	sect_raw_size_offset  = 0x10
	sect_name_addr_offset = 0x14
	sect_name_ref_offset  = 0x18
	sect_head_ref_offset  = 0x1c
	sect_tail_ref_offset  = 0x20
	sect_digest_offset    = 0x24
	cert_title_id_offset  = 0x8
	cert_title_offset     = 0xc

	title_img_sect_header_bytes = None
	title_img_sect_bytes = None

	# pull data from source xbe
	with open(iso_file, 'rb') as f:
		f.seek(xbe_offset)
		header_bytes = f.read(xbe_header_size * 10)

		base_addr         = struct.unpack('<I', header_bytes[base_addr_offset: base_addr_offset + 4])[0]
		cert_addr         = struct.unpack('<I', header_bytes[cert_addr_offset: cert_addr_offset + 4])[0]
		num_sections      = struct.unpack('<I', header_bytes[num_sections_offset: num_sections_offset + 4])[0]
		sect_headers_addr = struct.unpack('<I', header_bytes[sect_headers_offset: sect_headers_offset + 4])[0]

		# title
		offset = cert_addr - base_addr + cert_title_offset
		title_bytes = header_bytes[offset: offset + title_max_length * 2]

		# title id
		offset = cert_addr - base_addr + cert_title_id_offset
		title_id_bytes = header_bytes[offset: offset + 4]

		# section headers
		for i in range(0, num_sections):
			offset = sect_headers_addr - base_addr + i * section_header_size
			sect_header_bytes = header_bytes[offset: offset + section_header_size]

			flags     = sect_header_bytes[0:4]
			rv_addr   = sect_header_bytes[4:8]
			rv_size   = sect_header_bytes[8:12]
			raw_addr  = sect_header_bytes[12:16]
			raw_size  = sect_header_bytes[16:20]
			name_addr = sect_header_bytes[20:24]

			raw_addr  = struct.unpack('<I', raw_addr)[0]
			raw_size  = struct.unpack('<I', raw_size)[0]
			name_addr = struct.unpack('<I', name_addr)[0]

			name_offset = name_addr - base_addr
			name = readcstr(header_bytes, name_offset)

			# title image section
			if name == title_img_sect_name:
				title_img_sect_header_bytes = bytearray(sect_header_bytes)
				f.seek(xbe_offset + raw_addr)
				title_img_sect_bytes = f.read(raw_size)

	# we got a blank title, fallback to iso name
	if title_bytes[0] == 0:
		title = os.path.splitext(os.path.basename(iso_file))[0]
		title = title.ljust(title_max_length, "\x00")
		title_bytes = title.encode('utf-16-le')

	title_decoded = title_bytes.decode('utf-16-le').replace('\0', '')
	title_bytes   = title_bytes[0:title_max_length * 2]
	title_id      = '{:02X}'.format(struct.unpack("<I", title_id_bytes)[0])
	print("Generating default.xbe - Title ID:", title_id, '- Title:', title_decoded)

	# patch output xbe
	with open(in_file_name, 'rb') as f:
		out_bytes = bytearray(f.read())

	base_addr = struct.unpack('<I', out_bytes[base_addr_offset: base_addr_offset + 4])[0]
	cert_addr = struct.unpack('<I', out_bytes[cert_addr_offset: cert_addr_offset + 4])[0]
	xbe_size  = struct.unpack('<I', out_bytes[xbe_img_size_offset: xbe_img_size_offset + 4])[0] - base_addr

	# title
	title_offset = cert_addr - base_addr + cert_title_offset
	out_bytes[title_offset: title_offset + title_max_length * 2] = title_bytes

	# title id
	title_id_offset = cert_addr - base_addr + cert_title_id_offset
	out_bytes[title_id_offset: title_id_offset + 4] = title_id_bytes

	# title image
	# patch gore incoming
	if title_img_sect_header_bytes != None and title_img_sect_bytes != None:
		num_sections      = struct.unpack('<I', out_bytes[num_sections_offset: num_sections_offset + 4])[0]
		sect_headers_addr = struct.unpack('<I', out_bytes[sect_headers_offset: sect_headers_offset + 4])[0]

		title_img_sect_name_len = len(title_img_sect_name)
		title_img_size  = len(title_img_sect_bytes)
		old_sect_offset = sect_headers_addr - base_addr
		old_section     = out_bytes[old_sect_offset: old_sect_offset + section_header_size * num_sections]
		new_sect_addr   = xbe_header_size - section_header_size * num_sections - title_img_sect_name_len - num_new_sections - section_header_size
		new_sect_len    = xbe_header_size - new_sect_addr

		# patch title img section header
		new_sect_digest_addr = new_sect_addr + section_header_size * num_sections + sect_digest_offset
		new_sect_name_addr   = new_sect_addr + new_sect_len - title_img_sect_name_len - 1
		title_img_sect_header_bytes[sect_rv_addr_offset: sect_rv_addr_offset + 4] = struct.pack('<I', xbe_size + base_addr)
		title_img_sect_header_bytes[sect_rv_size_offset: sect_rv_size_offset + 4] = struct.pack('<I', title_img_size)
		title_img_sect_header_bytes[sect_raw_addr_offset: sect_raw_addr_offset + 4] = struct.pack('<I', xbe_size)
		title_img_sect_header_bytes[sect_raw_size_offset: sect_raw_size_offset + 4] = struct.pack('<I', title_img_size)
		title_img_sect_header_bytes[sect_name_addr_offset: sect_name_addr_offset + 4] = struct.pack('<I', new_sect_name_addr + base_addr)
		title_img_sect_header_bytes[sect_name_ref_offset: sect_name_ref_offset + 4] = bytearray(4)
		title_img_sect_header_bytes[sect_digest_offset: sect_digest_offset + 20] = bytearray(20)
		title_img_sect_header_bytes[sect_head_ref_offset: sect_head_ref_offset + 4] = struct.pack('<I', new_sect_digest_addr + base_addr)
		title_img_sect_header_bytes[sect_tail_ref_offset: sect_tail_ref_offset + 4] = struct.pack('<I', new_sect_digest_addr + 2 + base_addr)

		# placed at the end of the xbe header
		out_bytes[new_sect_addr: new_sect_addr + new_sect_len] = (
			old_section +
			title_img_sect_header_bytes +
			bytearray(title_img_sect_name.encode()) +
			b'\0'
		)

		# patch new data in xbe header
		out_bytes[num_sections_offset: num_sections_offset + 4] = struct.pack('<I', num_sections + num_new_sections)
		out_bytes[sect_headers_offset: sect_headers_offset + 4] = struct.pack('<I', new_sect_addr + base_addr)
		out_bytes[xbe_img_size_offset: xbe_img_size_offset + 4] = struct.pack('<I', xbe_size + title_img_size + base_addr)

		out_bytes += title_img_sect_bytes

	with open(out_file_name, 'wb') as f:
		f.write(out_bytes)

	# move output files to sub-folder
	keepcharacters = (' ', '.', '_')
	safe_title = "".join(c for c in title_decoded if c.isalnum() or c in keepcharacters).rstrip()
	cios1_file = iso_base_name + '.1.cso'
	cios2_file = iso_base_name + '.2.cso'
	out_dir    = base_dir + '/' + safe_title
	ciso1      = base_dir + '/' + cios1_file
	ciso2      = base_dir + '/' + cios2_file
	new_file   = out_dir  + '/' + os.path.basename(out_file_name)
	new_cios1  = out_dir  + '/' + cios1_file
	new_cios2  = out_dir  + '/' + cios2_file

	if not os.path.isdir(out_dir):
		os.makedirs(out_dir)
	if os.path.exists(out_file_name) and os.path.exists(new_file):
		os.remove(new_file)
	if os.path.exists(ciso1) and os.path.exists(new_cios1):
		os.remove(new_cios1)
	if os.path.exists(ciso2) and os.path.exists(new_cios2):
		os.remove(new_cios2)
	if os.path.exists(out_file_name) and not os.path.exists(new_file):
		shutil.move(out_file_name, new_file)
	if os.path.exists(ciso1) and not os.path.exists(new_cios1):
		shutil.move(ciso1, new_cios1)
	if os.path.exists(ciso2) and not os.path.exists(new_cios2):
		shutil.move(ciso2, new_cios2)

def main(argv):
	infile = argv[1]
	compress_iso(infile)
	gen_attach_xbe(infile)

if __name__ == '__main__':
	sys.exit(main(sys.argv))
