#!/usr/bin/python3
# Copyright 2018 David O'Rourke <david.orourke@gmail.com>
# Copyright 2022 MakeMHz LLC <contact@makemhz.com>
# Based on ciso from https://github.com/jamie/ciso

import os
import struct
import sys
import math
import lz4.frame
import json

CISO_MAGIC = 0x4F534943 # CISO
CISO_HEADER_SIZE = 0x18 # 24
CISO_BLOCK_SIZE = 0x800 # 2048
CISO_HEADER_FMT = '<LLQLBBxx' # Little endian
CISO_PLAIN_BLOCK = 0x80000000

TITLE_MAX_LENGTH = 40

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

def is_xbe_file(xbe, offset = 0):
	if not os.path.isfile(xbe):
		return False

	with open(xbe, 'rb') as xbe_file:
		xbe_file.seek(offset)
		magic = xbe_file.read(4)

		if magic != b'XBEH':
			return False

	return True

def get_iso_root_dir_offset_and_size(iso_file):
	global image_offset

	iso_header_offset    = 0x10000
	root_dir_sect_offset = 0x14

	with open(iso_file, 'rb') as f:
		detect_iso_type(f)

		f.seek(image_offset + iso_header_offset + root_dir_sect_offset)
		root_dir_sect    = struct.unpack('<I', f.read(4))[0]
		root_dir_offset  = image_offset + root_dir_sect * CISO_BLOCK_SIZE
		root_dir_size    = struct.unpack('<I', f.read(4))[0]

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
	dword        = 4

	search_file = search_file.casefold()

	with open(iso_file, 'rb') as f:
		# seek to dir
		dir_sectors = math.ceil(dir_size / CISO_BLOCK_SIZE)
		f.seek(dir_offset)

		dir_bytes        = f.read(dir_sectors * CISO_BLOCK_SIZE)
		dir_sector_bytes = [dir_bytes[i: i + CISO_BLOCK_SIZE] for i in range(0, len(dir_bytes), CISO_BLOCK_SIZE)]

		# loop through dir entries
		for sector_bytes in dir_sector_bytes:
			cur_pos = 0

			while True:
				cur_pos_diff = CISO_BLOCK_SIZE - cur_pos

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
					ret_offset = start_sector * CISO_BLOCK_SIZE
					return ret_offset, file_size

	# entry wasn't found
	return 0, 0

def get_xbe_section_offsets_from_bytes(header_bytes, search_section):
	section_header_size = 0x38
	base_addr_offset    = 0x104
	cert_addr_offset    = 0x118
	num_sections_offset = 0x11c
	sect_headers_offset = 0x120

	base_addr         = struct.unpack('<I', header_bytes[base_addr_offset: base_addr_offset + 4])[0]
	cert_addr         = struct.unpack('<I', header_bytes[cert_addr_offset: cert_addr_offset + 4])[0]
	num_sections      = struct.unpack('<I', header_bytes[num_sections_offset: num_sections_offset + 4])[0]
	sect_headers_addr = struct.unpack('<I', header_bytes[sect_headers_offset: sect_headers_offset + 4])[0]

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
		if name == search_section:
			return offset, raw_addr, raw_size

	return 0, 0, 0

def get_xbe_section_offsets(xbe_file, search_section, xbe_offset = 0):
	xbe_header_size = 0x1000
	num_pages = 10

	if type(xbe_file) == bytearray or type(xbe_file) == bytes:
		header_bytes = xbe_file[xbe_offset: xbe_offset + xbe_header_size * num_pages]
	else:
		with open(xbe_file, 'rb') as f:
			f.seek(xbe_offset)
			header_bytes = f.read(xbe_header_size * num_pages)

	header_offset, raw_offset, raw_size = get_xbe_section_offsets_from_bytes(header_bytes, search_section)

	if not header_offset:
		xbe_offset = 0

	return xbe_offset + header_offset, xbe_offset + raw_offset, raw_size

# returns array with section header and raw bytes
def get_xbe_section_bytes(xbe_file, search_section, xbe_offset = 0):
	section_header_size = 0x38

	ret_header_bytes = None
	ret_raw_bytes    = None

	header_offset, raw_offset, raw_size = get_xbe_section_offsets(xbe_file, search_section, xbe_offset)

	if header_offset:
		with open(xbe_file, 'rb') as f:
			f.seek(header_offset)
			ret_header_bytes = f.read(section_header_size)

			f.seek(raw_offset)
			ret_raw_bytes = f.read(raw_size)

	return ret_header_bytes, ret_raw_bytes

# read C-style strings
def readcstr(bytes, start):
	end = bytes.find(b'\0', start)
	sub = bytes[start: end]

	return sub.decode()

def format_title_bytes(title):
	title = title[0: TITLE_MAX_LENGTH].strip()
	title = title.ljust(TITLE_MAX_LENGTH, "\x00")
	title_bytes = title.encode('utf-16-le')

	return title_bytes

def get_iso_file_title_bytes(iso_file):
	title = os.path.splitext(os.path.basename(iso_file))[0]
	title_bytes = format_title_bytes(title)
	return title_bytes

# Some discs have better data from alternate XBEs
def get_alt_xbe_from_iso(iso_file, title_id = 0, title = None, version = None):
	xbe_file = None

	if title_id:
		# Forza Motorsport + XBLA
		if title_id == 0x584C8014 and title == 'CDX':
			xbe_file = 'Forza.xbe'
		# NCAA Football 2005 + Top Spin
		elif title_id == 0x584C000F and title == 'CDX':
			xbe_file = 'NCAA\\DEFAULT.XBE'
		# Hitman 2: Silent Assassin (Rev 2)
		elif title_id == 0x45530009 and title == 'CDX':
			xbe_file = 'hm2.xbe'
		# Star Wars: The Clone Wars + Tetris Worlds
		elif title_id == 0x584C000D and title == 'CDX':
			xbe_file = 'CW\\default.xbe'
		# Ninja Gaiden Video + Dead or Alive X-Treme Beach Volleyball Video + DOA 3 Bonus Materials
		elif title_id == 0x54438005 and title == 'Xbox Demos':
			xbe_file = 'Doa3\\doa3b.xbe'
		# Outlaw Golf: 9 Holes of X-Mas
		elif title_id == 0x5655801B and title == 'Xbox Demos':
			xbe_file = 'OGXmas\\OLGDemo.xbe'
		# Outlaw Golf: Holiday Golf
		elif title_id == 0x53538005 and title == 'Xbox Demos':
			xbe_file = 'OGXmas\\OLGDemo.xbe'
		# Sega GT 2002 + Jet Set Radio Future
		elif title_id == 0x4D53003D and title == 'Xbox Demos':
			xbe_file = 'SegaGT.xbe'
		# World Series Baseball
		elif title_id == 0x5345000E:
			xbe_file = 'wsb2k3_xbox_rel.xbe'
		# NCAA College Basketball 2K3
		elif title_id == 0x53450018:
			xbe_file = 'game.xbe'

	return xbe_file

def get_xbe_data_from_iso(iso_file, xbe_file = 'default.xbe'):
	xbe_header_size       = 0x1000
	base_addr_offset      = 0x104
	cert_addr_offset      = 0x118
	cert_title_id_offset  = 0x8
	cert_title_offset     = 0xc
	cert_title_ver_offset = 0xac

	timage_sect_hdr_bytes = None
	timage_raw_bytes      = None

	xbe_offset = get_file_offset_in_iso(iso_file, xbe_file)

	if xbe_offset == 0:
		return None

	# pull data from source xbe
	with open(iso_file, 'rb') as f:
		f.seek(xbe_offset)
		header_bytes = f.read(xbe_header_size * 10)

		base_addr = struct.unpack('<I', header_bytes[base_addr_offset: base_addr_offset + 4])[0]
		cert_addr = struct.unpack('<I', header_bytes[cert_addr_offset: cert_addr_offset + 4])[0]

		# title
		offset = cert_addr - base_addr + cert_title_offset
		title_bytes = header_bytes[offset: offset + TITLE_MAX_LENGTH * 2]

		# title id
		offset = cert_addr - base_addr + cert_title_id_offset
		title_id_bytes = header_bytes[offset: offset + 4]

		#title version
		offset = cert_addr - base_addr + cert_title_ver_offset
		title_ver_bytes = header_bytes[offset: offset + 4]

	title_id  = struct.unpack("<I", title_id_bytes)[0]
	title_ver = struct.unpack("<I", title_ver_bytes)[0]

	title_id_decoded  = "%08X" % title_id
	title_ver_decoded = "%08X" % title_ver
	title_decoded     = title_bytes.decode('utf-16-le').replace('\0', '')

	timage_sect_hdr_bytes, timage_raw_bytes = get_xbe_section_bytes(iso_file, '$$XTIMAGE', xbe_offset)

	return {
		'title_id':title_id,
		'title_ver':title_ver,
		'title_bytes':title_bytes,
		'title_id_bytes':title_id_bytes,
		'title_ver_bytes':title_ver_bytes,
		'title_id_decoded':title_id_decoded,
		'title_ver_decoded':title_ver_decoded,
		'title_decoded':title_decoded,
		'timage_sect_hdr_bytes':timage_sect_hdr_bytes,
		'timage_raw_bytes':timage_raw_bytes
	}

def patch_xbe_timage_data(xbe_bytes, timage_sect_hdr_bytes, timage_raw_bytes):
	title_img_sect_name   = '$$XTIMAGE'
	num_new_sections      = 1
	xbe_header_size       = 0x1000
	section_header_size   = 0x38
	base_addr_offset      = 0x104
	num_sections_offset   = 0x11c
	xbe_img_size_offset   = 0x10c
	sect_headers_offset   = 0x120
	sect_digest_offset    = 0x24
	sect_rv_addr_offset   = 0x4
	sect_rv_size_offset   = 0x8
	sect_raw_addr_offset  = 0xc
	sect_raw_size_offset  = 0x10
	sect_name_addr_offset = 0x14
	sect_name_ref_offset  = 0x18
	sect_head_ref_offset  = 0x1c
	sect_tail_ref_offset  = 0x20
	title_img_sect_name_len = len(title_img_sect_name)

	if timage_sect_hdr_bytes != None and timage_raw_bytes != None:
		title_img_size = len(timage_raw_bytes)

		orig_header_offset, orig_raw_offset, orig_raw_size = get_xbe_section_offsets(xbe_bytes, title_img_sect_name)

		# patch existing $$XTIMAGE section
		if orig_header_offset:
			if title_img_size <= orig_raw_size:
				size_start_offset = orig_header_offset + sect_rv_size_offset
				raw_size_start_offset = orig_header_offset + sect_raw_size_offset
				xbe_bytes[size_start_offset: size_start_offset + 4] = struct.pack('<I', title_img_size)
				xbe_bytes[raw_size_start_offset: raw_size_start_offset + 4] = struct.pack('<I', title_img_size)

				pad_bytes = b'\x00' * (orig_raw_size - title_img_size)
				timage_raw_bytes += pad_bytes
				xbe_bytes[orig_raw_offset: orig_raw_offset + orig_raw_size] = timage_raw_bytes

		# no existing $$XTIMAGE section, add it
		else:
			base_addr         = struct.unpack('<I', xbe_bytes[base_addr_offset: base_addr_offset + 4])[0]
			num_sections      = struct.unpack('<I', xbe_bytes[num_sections_offset: num_sections_offset + 4])[0]
			sect_headers_addr = struct.unpack('<I', xbe_bytes[sect_headers_offset: sect_headers_offset + 4])[0]
			xbe_size          = struct.unpack('<I', xbe_bytes[xbe_img_size_offset: xbe_img_size_offset + 4])[0] - base_addr

			old_sect_offset = sect_headers_addr - base_addr
			old_section     = xbe_bytes[old_sect_offset: old_sect_offset + section_header_size * num_sections]
			new_sect_addr   = xbe_header_size - section_header_size * num_sections - title_img_sect_name_len - num_new_sections - section_header_size
			new_sect_len    = xbe_header_size - new_sect_addr

			# patch title img section header
			new_sect_digest_addr = new_sect_addr + section_header_size * num_sections + sect_digest_offset
			new_sect_name_addr   = new_sect_addr + new_sect_len - title_img_sect_name_len - 1
			timage_sect_hdr_bytes[sect_rv_addr_offset: sect_rv_addr_offset + 4]     = struct.pack('<I', xbe_size + base_addr)
			timage_sect_hdr_bytes[sect_rv_size_offset: sect_rv_size_offset + 4]     = struct.pack('<I', title_img_size)
			timage_sect_hdr_bytes[sect_raw_addr_offset: sect_raw_addr_offset + 4]   = struct.pack('<I', xbe_size)
			timage_sect_hdr_bytes[sect_raw_size_offset: sect_raw_size_offset + 4]   = struct.pack('<I', title_img_size)
			timage_sect_hdr_bytes[sect_name_addr_offset: sect_name_addr_offset + 4] = struct.pack('<I', new_sect_name_addr + base_addr)
			timage_sect_hdr_bytes[sect_name_ref_offset: sect_name_ref_offset + 4]   = bytearray(4)
			timage_sect_hdr_bytes[sect_digest_offset: sect_digest_offset + 20]      = bytearray(20)
			timage_sect_hdr_bytes[sect_head_ref_offset: sect_head_ref_offset + 4]   = struct.pack('<I', new_sect_digest_addr + base_addr)
			timage_sect_hdr_bytes[sect_tail_ref_offset: sect_tail_ref_offset + 4]   = struct.pack('<I', new_sect_digest_addr + 2 + base_addr)

			# placed at the end of the xbe header
			xbe_bytes[new_sect_addr: new_sect_addr + new_sect_len] = (
				old_section +
				timage_sect_hdr_bytes +
				bytearray(title_img_sect_name.encode()) +
				b'\0'
			)

			# patch new data in xbe header
			xbe_bytes[num_sections_offset: num_sections_offset + 4] = struct.pack('<I', num_sections + num_new_sections)
			xbe_bytes[sect_headers_offset: sect_headers_offset + 4] = struct.pack('<I', new_sect_addr + base_addr)
			xbe_bytes[xbe_img_size_offset: xbe_img_size_offset + 4] = struct.pack('<I', xbe_size + title_img_size + base_addr)

			xbe_bytes += timage_raw_bytes

	return xbe_bytes

def gen_attach_xbe(iso_file):
	me_path       = os.path.dirname(os.path.abspath(__file__))
	base_dir      = os.path.dirname(os.path.abspath(iso_file))
	in_file_name  = me_path + '/attach.xbe'
	json_file     = me_path + '/RepackList.json'
	out_file_name = base_dir + '/default.xbe'

	if not is_xbe_file(in_file_name):
		return

	# https://www.caustik.com/cxbx/download/xbe.htm
	base_addr_offset      = 0x104
	cert_addr_offset      = 0x118
	cert_title_id_offset  = 0x8
	cert_title_offset     = 0xc
	cert_title_ver_offset = 0xac

	alt_data = None
	timage_sect_hdr_bytes = None
	timage_raw_bytes      = None

	xbe_data = get_xbe_data_from_iso(iso_file)
	alt_xbe  = get_alt_xbe_from_iso(iso_file, xbe_data['title_id'], xbe_data['title_decoded'], xbe_data['title_ver'])

	# We have an alternate xbe to pull data from
	if alt_xbe:
		alt_data = get_xbe_data_from_iso(iso_file, alt_xbe)

	timage_raw_bytes      = xbe_data['timage_raw_bytes']
	timage_sect_hdr_bytes = xbe_data['timage_sect_hdr_bytes']
	title_bytes           = xbe_data['title_bytes']
	title_id_bytes        = xbe_data['title_id_bytes']
	title_ver_bytes       = xbe_data['title_ver_bytes']
	title_decoded         = xbe_data['title_decoded']
	title_id_decoded      = xbe_data['title_id_decoded']
	title_ver_decoded     = xbe_data['title_ver_decoded']

	if alt_data:
		timage_raw_bytes      = alt_data['timage_raw_bytes']
		timage_sect_hdr_bytes = alt_data['timage_sect_hdr_bytes']
		title_bytes           = alt_data['title_bytes']
		title_decoded         = alt_data['title_decoded']

	if timage_sect_hdr_bytes != None:
		timage_sect_hdr_bytes = bytearray(timage_sect_hdr_bytes)

	if os.path.isfile(json_file):
		# Parse JSON and set title, fallback to filename
		if not hasattr(gen_attach_xbe, 'title_json'):
			title_list_fp = open(json_file)
			gen_attach_xbe.title_json = json.load(title_list_fp)
			title_list_fp.close()

		title_json = gen_attach_xbe.title_json

		title_found = False
		for ref_json in title_json:
			if ref_json['Title ID'] == xbe_data['title_id_decoded'] and ref_json['Version'] == xbe_data['title_ver_decoded']:
				ref_title = ref_json['XBE Title']
				title = ref_title.split('(', 1)[0][:-1]
				title_bytes = format_title_bytes(title)
				title_found = True
				break

		if not title_found and not title_decoded:
			title_bytes = get_iso_file_title_bytes(iso_file)

	# we got a blank title, fallback to iso name
	elif not title_decoded:
		title_bytes = get_iso_file_title_bytes(iso_file)

	title_decoded = title_bytes.decode('utf-16-le').replace('\0', '')
	title_bytes   = title_bytes[0:TITLE_MAX_LENGTH * 2]

	print("Generating default.xbe - Title ID:", title_id_decoded, '- Version:', title_ver_decoded, '- Title:', title_decoded)

	# patch output xbe
	with open(in_file_name, 'rb') as f:
		out_bytes = bytearray(f.read())

	base_addr = struct.unpack('<I', out_bytes[base_addr_offset: base_addr_offset + 4])[0]
	cert_addr = struct.unpack('<I', out_bytes[cert_addr_offset: cert_addr_offset + 4])[0]

	# title
	title_offset = cert_addr - base_addr + cert_title_offset
	out_bytes[title_offset: title_offset + TITLE_MAX_LENGTH * 2] = title_bytes

	# title id
	title_id_offset = cert_addr - base_addr + cert_title_id_offset
	out_bytes[title_id_offset: title_id_offset + 4] = title_id_bytes

	# title version
	title_ver_offset = cert_addr - base_addr + cert_title_ver_offset
	out_bytes[title_ver_offset: title_ver_offset + 4] = title_ver_bytes

	# title image
	out_bytes = patch_xbe_timage_data(out_bytes, timage_sect_hdr_bytes, timage_raw_bytes)

	with open(out_file_name, 'wb') as f:
		f.write(out_bytes)

	return title_decoded

def main(argv):
	infile = argv[1]
	compress_iso(infile)
	gen_attach_xbe(infile)

if __name__ == '__main__':
	sys.exit(main(sys.argv))
