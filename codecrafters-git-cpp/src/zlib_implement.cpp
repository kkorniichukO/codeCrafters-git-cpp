#include <iostream>
#include <cstdlib>
#include <cstring>
#include <zlib.h>
#include <sstream>
#include <stdexcept>
#include "zlib_implement.h"

#define CHUNK 16384 //16KB

/**
 * Decompresses data from an input file and writes the decompressed output to an output file.
 * 
 * @param input Pointer to the input FILE stream containing compressed data.
 * @param output Pointer to the output FILE stream where decompressed data will be written.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int decompress(FILE* input, FILE* output) {
    // initialize decompression stream
    //std::cout << "Initializing decompression stream.\n";
    z_stream stream = {0};
    if (inflateInit(&stream) != Z_OK) {
        std::cerr << "Failed to initialize decompression stream.\n";
        return EXIT_FAILURE;
    }

    // initialize decompression variables
    char in[CHUNK];          // buffer for compressed input data
    char out[CHUNK];         // buffer for decompressed output data
    bool haveHeader = false; // flag to indicate if header has been processed
    char header[64];         // buffer to store header string
    int ret;                 // return code from inflate function

    do {
        // read compressed data from input file into 'in' buffer
        stream.avail_in = fread(in, 1, CHUNK, input);
        stream.next_in = reinterpret_cast<unsigned char*>(in); // set input pointer for decompression

        if (ferror(input)) {
            std::cerr << "Failed to read from input file.\n";
            return EXIT_FAILURE;
        }
        if (stream.avail_in == 0) {
            break; // no more data to read
        }

        do {
            stream.avail_out = CHUNK; // set output buffer size
            stream.next_out = reinterpret_cast<unsigned char*>(out); // set output pointer for decompression

            ret = inflate(&stream, Z_NO_FLUSH); // decompress data chunk

            // check for decompression errors
            if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                std::cerr << "Failed to decompress file.\n";
                return EXIT_FAILURE;
            }

            unsigned headerLen = 0, dataLen = 0;
            if (!haveHeader) {
                // parse header and data length from decompressed output
                sscanf(out, "%s %u", header, &dataLen);
                haveHeader = true;
                headerLen = strlen(out) + 1; // length of header string including null terminator
            }

            // write decompressed data (excluding header) to output file
            if (dataLen > 0) {
                if (fwrite(out + headerLen, 1, dataLen, output) != dataLen) {
                    std::cerr << "Failed to write to output file.\n";
                    return EXIT_FAILURE;
                }
            }
        } while (stream.avail_out == 0); // continue if output buffer was fully used
        
    } while (ret != Z_STREAM_END); // continue until end of compressed stream

    // clean up decompression stream and return success or failure
    return inflateEnd(&stream) == Z_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * Compresses data from an input file and writes the compressed output to an output file.
 * 
 * @param input Pointer to the input FILE stream containing data to compress.
 * @param output Pointer to the output FILE stream where compressed data will be written.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int compress(FILE* input, FILE* output) {
    // Initialize compression stream.
    //std::cout << "Initializing compression stream.\n";
    z_stream stream = {0};
    if (deflateInit(&stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        std::cerr << "Failed to initialize compression stream.\n";
        return EXIT_FAILURE;
    }

    char in[CHUNK];   // Buffer for input data to compress
    char out[CHUNK];  // Buffer for compressed output data
    int ret;          // Return code from deflate function
    int flush;        // Flush mode for deflate

    do {
        // Read data from input file into 'in' buffer
        stream.avail_in = fread(in, 1, CHUNK, input);
        stream.next_in = reinterpret_cast<unsigned char*>(in);
        if (ferror(input)) {
            (void)deflateEnd(&stream);  // Free memory
            std::cerr << "Failed to read from input file.\n";
            return EXIT_FAILURE;
        }
        // Determine flush mode: finish if end of file, else no flush
        flush = feof(input) ? Z_FINISH : Z_NO_FLUSH;

        do {
            stream.avail_out = CHUNK; // Set output buffer size
            stream.next_out = reinterpret_cast<unsigned char*>(out); // Set output pointer for compression
            ret = deflate(&stream, flush); // Compress data chunk
            if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
                (void)deflateEnd(&stream);  // Free memory
                std::cerr << "Failed to compress file.\n";
                return EXIT_FAILURE;
            }
            size_t have = CHUNK - stream.avail_out; // Number of bytes compressed
            // Write compressed data to output file
            if (fwrite(out, 1, have, output) != have || ferror(output)) {
                (void)deflateEnd(&stream);  // Free memory
                std::cerr << "Failed to write to output file.\n";
                return EXIT_FAILURE;
            }
        } while (stream.avail_out == 0); // Continue if output buffer was fully used
    } while (flush != Z_FINISH); // Continue until all input is processed and flushed

    // Clean up and check for errors
    if (deflateEnd(&stream) != Z_OK) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Decompresses a compressed string using zlib.
 * 
 * @param compressed_str The compressed string to decompress.
 * @return The decompressed string.
 */
std::string decompress_string (const std::string& compressed_str) {
    z_stream d_stream; // Structure to hold decompression state
    memset(&d_stream, 0, sizeof(d_stream)); // Initialize the structure to zero

    // Initialize the decompression stream
    if (inflateInit(&d_stream) != Z_OK) {
        throw(std::runtime_error("inflateInit failed while decompressing."));
    }

    // Set the input data for decompression
    d_stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed_str.data()));
    d_stream.avail_in = compressed_str.size();

    int status; // Variable to hold the status of decompression
    const size_t buffer_size = 32768; // 32KB buffer size for decompression
    char buffer[buffer_size]; // Buffer to hold decompressed data
    std::string decompressed_str; // String to accumulate decompressed data

    do {
        // Set the output buffer for decompression
        d_stream.next_out = reinterpret_cast<Bytef*>(buffer);
        d_stream.avail_out = buffer_size;

        // Perform decompression
        status = inflate(&d_stream, 0);

        // Append decompressed data to the output string
        if (decompressed_str.size() < d_stream.total_out) {
            decompressed_str.append(buffer, d_stream.total_out - decompressed_str.size());
        }
    } while (status == Z_OK); // Continue until decompression is complete

    // Clean up the decompression stream
    if (inflateEnd(&d_stream) != Z_OK) {
        throw(std::runtime_error("inflateEnd failed while decompressing."));
    }

    // Check for errors in decompression
    if (status != Z_STREAM_END) {
        std::ostringstream oss;
        oss << "Exception during zlib decompression: (" << status << ") " << d_stream.msg;
        throw(std::runtime_error(oss.str()));
    }

    return decompressed_str; // Return the decompressed string
}

/**
 * Compresses a string using zlib.
 * 
 * @param input_str The string to compress.
 * @return The compressed string.
 */
std::string compress_string (const std::string& input_str) {
    z_stream c_stream; // Structure to hold compression state
    memset(&c_stream, 0, sizeof(c_stream)); // Initialize the structure to zero

    // Initialize the compression stream
    if (deflateInit(&c_stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        throw(std::runtime_error("deflateInit failed while compressing."));
    }

    // Set the input data for compression
    c_stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input_str.data()));
    c_stream.avail_in = input_str.size();

    int status; // Variable to hold the status of compression
    const size_t buffer_size = 32768; // 32KB buffer size for compression
    char buffer[buffer_size]; // Buffer to hold compressed data
    std::string compressed_str; // String to accumulate compressed data

    do {
        // Set the output buffer for compression
        c_stream.next_out = reinterpret_cast<Bytef*>(buffer);
        c_stream.avail_out = sizeof(buffer);

        // Perform compression
        status = deflate(&c_stream, Z_FINISH);

        // Append compressed data to the output string
        if (compressed_str.size() < c_stream.total_out) {
            compressed_str.append(buffer, c_stream.total_out - compressed_str.size());
        }
    } while (status == Z_OK); // Continue until compression is complete

    // Clean up the compression stream
    if (deflateEnd(&c_stream) != Z_OK) {
        throw(std::runtime_error("deflateEnd failed while compressing."));
    }

    // Check for errors in compression
    if (status != Z_STREAM_END) {
        std::ostringstream oss;
        oss << "Exception during zlib compression: (" << status << ") " << c_stream.msg;
        throw(std::runtime_error(oss.str()));
    }

    return compressed_str; // Return the compressed string
}