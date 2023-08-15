/* Stellar-CSO
   A tool for converting ISO/XISO files to CSO (Compressed ISO)

   Copyright 2018 David O'Rourke <david.orourke@gmail.com>
   Copyright 2022 MakeMHz LLC <contact@makemhz.com>
   Based on ciso from https://github.com/jamie/ciso
*/

#include <lz4frame.h>
#include <lz4hc.h>

#include <iostream>
#include <ios>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

const uint32_t FATX_SIZE_LIMIT = 0xFFBF6000;

const std::string CISO_MAGIC = "CISO";
const uint32_t CISO_HEADER_SIZE = 0x18;
const uint32_t CISO_BLOCK_SIZE = 0x800;
const uint32_t CISO_PLAIN_BLOCK = 0x80000000;

size_t image_offset = 0;

void detect_iso_type(std::ifstream& f) {
    try {
	f.seekg(0x18310000, std::ios::beg);
    } catch (std::exception const& e) {
	std::cout << "File not big enough to be a Redump style image." << std::endl;
    }
    if (f.tellg() == 0x18310000) {
	std::string buf(20, '\0');
	f.read(&buf[0], 20);
	if (buf == "MICROSOFT*XBOX*MEDIA") {
	    image_offset = 0x18300000;
	    return;
	}
    }
    if (f.bad() || f.fail() || f.eof()) {
        f.clear();
    }

    try {
	f.seekg(0x10000, std::ios::beg);
    } catch (std::exception &e) {
	std::cout << "File not big enough to be a raw XDVDFS image." << std::endl;
    }
    if (f.tellg() == 0x10000) {
	std::string buf(20, '\0');
	f.read(&buf[0], 20);
	if (buf == "MICROSOFT*XBOX*MEDIA") {
	    image_offset = 0;
	    return;
	} else {
            std::cout << buf << std::endl;
        }
    }
    std::cerr << "Could not detect ISO type."<< std::endl;
    exit(1);
}

class ciso {
private:
    std::string magic;
    uint32_t ver;
    uint32_t block_size;
    uint64_t total_bytes;
    uint32_t total_blocks;
    uint32_t align;
public:
    ciso (uint64_t total_bytes) : magic(CISO_MAGIC), ver(2), block_size(CISO_BLOCK_SIZE),
				  total_bytes(total_bytes), align(2) {
	total_blocks = total_bytes/CISO_BLOCK_SIZE;
    }

    ciso (std::ifstream &f) {
	f.seekg(0, std::ios::end);
	uint32_t file_size = (int32_t)f.tellg() - image_offset;
	*this = ciso(file_size);
        f.seekg(0, std::ios::beg);
    }

    ciso (const char* filename) {
	std::ifstream f(filename);
	*this = ciso(f);
    }

    friend std::ostream& operator<<(std::ostream& os, ciso const& c);

    uint32_t get_block_size() { return block_size; };
    uint32_t get_total_blocks() { return total_blocks; };
    uint32_t get_align() { return align; };
    
    void write_header(std::ofstream& f) {
 	f << magic;
        f.write((char*)&CISO_HEADER_SIZE, sizeof(CISO_HEADER_SIZE))
            .write((char*)&total_bytes, sizeof(total_bytes))
            .write((char*)&block_size, sizeof(block_size));
	f << reinterpret_cast<char*>(&ver) << reinterpret_cast<char*>(&align);
	f << "\0\0" << std::flush;
    }

    void write_block_index(std::ofstream& f, std::vector<uint32_t> const& block_index) {
	for (uint32_t i: block_index) {
            f.write((char*)&i, sizeof(i));
	}
    }
};

std::ostream& operator<<(std::ostream& os, ciso const& c) {
    os << "Magic:        " << c.magic << '\n'
       << "Version:      " << c.ver << '\n'
       << "Block Size:   " << c.block_size << '\n'
       << "Total Bytes:  " << c.total_bytes << '\n'
       << "Total Blocks: " << c.total_blocks << '\n'
       << "Alignment:    " << c.align << std::endl;
    return os;
}

void pad_file_size(std::ofstream& f) {
    f.seekp(0, std::ios::end);
    size_t size = f.tellp();
    std::string zero(0x400 - (size & 0x3FF), '\0');
    f << zero << std::flush;
}

void compress_iso(std::string &infile) {
    LZ4F_cctx* cctxPtr;
    auto ret = LZ4F_createCompressionContext(&cctxPtr, LZ4F_VERSION);
    if (ret != 0) {
	std::cerr << "CompressionContext creation failed, exiting...";
	exit(2);
    }
    std::ofstream fout_1(infile + ".1.cso", std::ios::binary);
    std::ofstream fout_2;

    std::ifstream fin(infile, std::ios::binary);
    if (!fin.is_open()) {
        std::cerr << "ERROR: Could not open input file " << infile << "!" << std::endl;
        exit(4);
    }

    std::cout << "Compressing " << infile << std::endl;
    detect_iso_type(fin);
    ciso ciso(fin);
    fin.seekg(0, std::ios::beg);
    std::cout << ciso;
    ciso.write_header(fout_1);
    std::vector<uint32_t> block_index(ciso.get_total_blocks() + 1, 0);
    ciso.write_block_index(fout_1, block_index);

    size_t write_pos = fout_1.tellp();
    uint32_t align_b = 1 << ciso.get_align();
    uint32_t align_m = align_b - 1;

    std::string raw_data(ciso.get_block_size(), '\0');
    std::string compressed_data(ciso.get_block_size()+27, '\0');
    std::string alignment_buffer(64, '\0');

    std::string *writable_data;
    std::ofstream *split_fout = &fout_1;

    LZ4F_preferences_t* lz4pref = new LZ4F_preferences_t();
    lz4pref->frameInfo.blockMode = LZ4F_blockIndependent;
    lz4pref->compressionLevel = LZ4HC_CLEVEL_MAX;
    lz4pref->autoFlush = 1;

    uint32_t block;

    for (block = 0; block < ciso.get_total_blocks(); ++block) {
	// Check if we need to split the ISO (due to FATX limitations)
	if (write_pos > FATX_SIZE_LIMIT) {
	    fout_2.open(infile + ".2.cso", std::ios::binary);
	    split_fout = &fout_2;
	    write_pos = 0;
	}

	// Write alignment
	uint32_t align = write_pos & align_m;
	if (align != 0) {
	    align = align_b - align;
	    split_fout->write(alignment_buffer.c_str(), align);
	    write_pos += align;
	}

	// Mark offset index
	block_index[block] = write_pos >> ciso.get_align();

	// Read raw data
        auto raw_data_chunk_start = fin.tellg();
	fin.read(&raw_data[0], ciso.get_block_size());
	size_t data_size = fin.tellg() - raw_data_chunk_start;

        // Compress all the things
        LZ4F_compressBegin(cctxPtr, &compressed_data[0], compressed_data.size(), lz4pref);
        auto compressed_size = LZ4F_compressUpdate(cctxPtr,
                                                   &compressed_data[0], compressed_data.size(),
                                                   &raw_data[0], data_size,
                                                   nullptr);
        if (LZ4F_isError(compressed_size)) {
            std::cerr << "ERROR: " << LZ4F_getErrorName(compressed_size) << std::endl;
            exit(1);
        }
        LZ4F_flush(cctxPtr, &compressed_data[0], 0x800, nullptr);

        // Make sure the data we write back actually saves space
        if ((compressed_size + 12) >= data_size) {
            writable_data = &raw_data;
            write_pos += data_size;
        } else {
            writable_data = &compressed_data;
            block_index[block] |= 0x80000000;
            write_pos += compressed_size;
            data_size = compressed_size;
        }
        split_fout->write(writable_data->c_str(), data_size);
    }

    fin.close();
    *block_index.rbegin() = write_pos >> ciso.get_align();

    fout_1.seekp(CISO_HEADER_SIZE, std::ios::beg);
    ciso.write_block_index(fout_1, block_index);

    pad_file_size(fout_1);
    fout_1.close();

    if (split_fout == &fout_2) {
        pad_file_size(fout_2);
        fout_2.close();
    }
    
    LZ4F_freeCompressionContext(cctxPtr);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage:\n" << argv[0] << " <image file>" << std::endl;
        return 1;
    }
    std::string file(argv[1]);
    compress_iso(file);
    return 0;
}
