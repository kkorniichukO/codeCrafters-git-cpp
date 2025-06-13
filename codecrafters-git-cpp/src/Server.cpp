#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <algorithm>
#include <set>
#include <ctime>
#include <curl/curl.h>
#include "zlib_implement.h"

/**
 * Initializes a new git repository in the specified directory.
 * 
 * @param dir The directory where the git repository will be initialized.
 * @return True if the initialization is successful, false otherwise.
 */
bool gitInit (const std::string& dir) {
    std::cout << "git init \n";
    try {
        // Create .git directory
        std::filesystem::create_directory(dir + "/.git");
        // Create .git/objects directory
        std::filesystem::create_directory(dir + "/.git/objects");
        // Create .git/refs directory
        std::filesystem::create_directory(dir + "/.git/refs");

        // Create and open .git/HEAD file
        std::ofstream headFile(dir + "/.git/HEAD");
        if (headFile.is_open()) { 
            // Write the reference to the master branch to the HEAD file
            headFile << "ref: refs/heads/master\n"; 
            headFile.close(); // Close the HEAD file
        } else {
            std::cerr << "Failed to create .git/HEAD file.\n";
            return false;
        }
       
        std::cout << "Initialized git directory in " << dir << "\n";
        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << e.what() << '\n';
        return false;
    }
}


/**
 * Outputs the contents of a file after decompressing it.
 * 
 * @param filepath The path to the file to be read and decompressed.
 * @return EXIT_SUCCESS if successful, EXIT_FAILURE otherwise.
 */
int catFile(const char* filepath) {
    FILE* dataFile = fopen(filepath, "rb"); // Open the file in binary read mode
    if (!dataFile) {
        std::cerr << "Invalid object hash.\n"; // Error if file cannot be opened
        return EXIT_FAILURE;
    }

    // Create output file stream for standard output (stdout)
    FILE* outputFile = fdopen(1, "wb");
    if (!outputFile) {
        std::cerr << "Failed to create output file.\n"; // Error if stdout cannot be opened as file stream
        return EXIT_FAILURE;
    }

    // Decompress the data from dataFile and write to outputFile
    if (decompress(dataFile, outputFile) != EXIT_SUCCESS) {
        std::cerr << "Failed to decompress data file.\n"; // Error if decompression fails
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS; // Success
}

/**
 * Computes the SHA-1 hash of the given data string.
 * 
 * @param data The input string to hash.
 * @param print_out If true, prints the resulting hash to standard output.
 * @return The SHA-1 hash as a hexadecimal string.
 */
std::string compute_sha1 (const std::string& data, bool print_out = false) {
    unsigned char hash[20]; // Buffer to hold the 20-byte (160-bit) SHA-1 hash
    // Compute SHA-1 hash of the input data
    SHA1(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);

    std::stringstream ss;
    ss << std::hex << std::setfill('0'); // Format output as hexadecimal with leading zeros

    // Convert each byte of the hash to a two-digit hexadecimal string
    for (const auto& byte : hash) {
        ss << std::setw(2) << static_cast<int>(byte);
    }

    if (print_out)  {
        std::cout << ss.str() << std::endl; // Optionally print the hash
    }

    return ss.str(); // Return the hexadecimal hash string
}

/**
 * Compresses and stores the given content in the specified directory.
 * 
 * @param hash The hash of the content to be used as the filename.
 * @param content The content to be compressed and stored.
 * @param dir The directory where the compressed content will be stored (default is current directory).
 */
void compressAndStore (const std::string& hash, const std::string& content, std::string dir = ".") {
    // Open a memory stream for the content to be compressed
    FILE* input = fmemopen((void*) content.c_str(), content.length(), "rb");
    
    // Create the directory path for storing the compressed object
    std::string hash_folder = hash.substr(0, 2);
    std::string object_path = dir + "/.git/objects/" + hash_folder + '/';
    if (!std::filesystem::exists(object_path)) {
        std::filesystem::create_directories(object_path); // Create directories if they do not exist
    }
    
    // Create the file path for the compressed object
    std::string object_file_path = object_path + hash.substr(2);
    if (!std::filesystem::exists(object_file_path)) {
        // Open the file for writing the compressed data
        FILE* output = fopen(object_file_path.c_str(), "wb");
        if (compress(input, output) != EXIT_SUCCESS) {
            std::cerr << "Failed to compress data.\n"; // Error if compression fails
            return;
        }
        fclose(output); // Close the output file
    }

    fclose(input); // Close the input memory stream
}

/**
 * Computes the hash of a file and stores the compressed content in the .git/objects directory.
 * 
 * @param filepath The path to the file to be hashed and stored.
 * @param type The type of the object (default is "blob").
 * @param print_out If true, prints the resulting hash to standard output.
 * @return The SHA-1 hash of the file content.
 */
std::string hashObject (std::string filepath, std::string type = "blob", bool print_out = false) {
    // Open the file
    std::ifstream inputFile(filepath, std::ios::binary);
    if(inputFile.fail()) {
        std::cerr << "Failed to open file.\n";
        return {};
    }

    // Read the file content
    std::string content(
        (std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>()
    );

    // Create the content with header
    std::string header = type + " " + std::to_string(content.size());
    std::string file_content = header + '\0' + content;

    // Compute the SHA-1 hash of the content
    std::string hash = compute_sha1(file_content, false);

    // Compress and store the content in the .git/objects directory
    compressAndStore(hash, file_content);
    inputFile.close();

    // Optionally print the hash
    if (print_out) {
        std::cout << hash << std::endl;
    }
    return hash;
}

/**
 * Parses a git tree object from a decompressed file stream.
 * 
 * @param tree_object Pointer to a FILE stream containing the decompressed tree object data.
 * @return A sorted set of filenames (directory entries) contained in the tree object.
 */
std::set<std::string> parseTreeObject (FILE* tree_object) {
    rewind(tree_object); // Reset file position indicator to the beginning
    
    std::vector<std::string> unsorted_directories; // Temporary container for filenames
    char mode[7];        // Buffer to read the file mode (e.g., "100644")
    char filename[256];  // Buffer to read the filename
    unsigned char hash[20]; // Buffer to read the 20-byte SHA-1 hash

    // Loop until fscanf fails (EOF)
    while (fscanf(tree_object, "%6s", mode) != EOF) {
        // Read the filename character by character until null byte or EOF
        int i = 0;
        int c;
        while ((c = fgetc(tree_object)) != 0 && c != EOF) {
            // Skip spaces in filename (if any)
            if (c == ' ') {
                continue;
            }
            filename[i++] = c;
        }
        filename[i] = '\0'; // Null-terminate the filename string

        // Read the 20-byte SHA-1 hash following the filename
        fread(hash, 1, 20, tree_object);

        // Add the filename to the list
        unsorted_directories.push_back(filename);
    }

    // Sort the filenames lexicographically
    std::sort(unsorted_directories.begin(), unsorted_directories.end());

    // Convert to set to remove duplicates and return
    std::set<std::string> sorted_directories(unsorted_directories.begin(), unsorted_directories.end());

    return sorted_directories;
}

/**
 * Lists the contents of a git tree object.
 * 
 * @param object_hash The hash of the tree object to list.
 * @return EXIT_SUCCESS if successful, EXIT_FAILURE otherwise.
 */
int ls_tree (const char* object_hash) {
    // Retrieve the object path
    char object_path[64];
    snprintf(object_path, sizeof(object_path), ".git/objects/%.2s/%s", object_hash, object_hash + 2);

    // Set the input and output file descriptors
    FILE* object_file = fopen(object_path, "rb");
    if(object_file == NULL) {
        std::cerr << "Invalid object hash.\n";
        return EXIT_FAILURE;
    }
    FILE* output_file = tmpfile();
    if(output_file == NULL) {
        std::cerr << "Failed to create output file.\n";
        return EXIT_FAILURE;
    }

    // Decompress the object file into the output file
    if(decompress(object_file, output_file) != EXIT_SUCCESS) {
        std::cerr << "Failed to decompress object file.\n";
        return EXIT_FAILURE;
    }

    // Parse the tree object to get the list of directories
    std::set<std::string> directories = parseTreeObject(output_file);

    // Print the directories
    for (const std::string& directory : directories) {
        std::cout << directory << '\n';
    }

    return EXIT_SUCCESS;
}

/**
 * Converts a hexadecimal string to its binary representation.
 * 
 * @param input The hexadecimal string to convert.
 * @return The binary representation of the input string.
 */
std::string hashDigest (const std::string& input) {
    std::string condensed;

    // Iterate over the input string in steps of 2 characters
    for (size_t i = 0; i < input.length(); i += 2) {
        // Extract a substring of 2 characters (one byte)
        std::string byte_string = input.substr(i, 2);
        // Convert the hexadecimal string to a byte (char)
        char byte = static_cast<char>(std::stoi(byte_string, nullptr, 16));
        // Append the byte to the condensed string
        condensed.push_back(byte);
    }

    return condensed;
}

/**
 * Recursively writes a git tree object for the given directory.
 * 
 * @param directory The directory path to write the tree object from.
 * @return The SHA-1 hash of the created tree object.
 */
std::string writeTree (const std::string& directory) {
    std::vector<std::string> tree_entries;
    // List of directory or file names to skip when writing the tree
    std::vector<std::string> skip = {
        ".git", "server", "CMakeCache.txt", 
        "CMakeFiles", "Makefile", "cmake_install.cmake"
    };

    // Iterate over each entry in the directory
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        std::string path = entry.path().string();
        
        // Skip entries that match any of the skip patterns
        if (std::any_of(skip.begin(), skip.end(), [&path](const std::string& s) {
            return path.find(s) != std::string::npos;
        })) {
            continue;
        }

        std::error_code ec;
        // Determine if the entry is a directory or a file and set the mode accordingly
        std::string entry_type = std::filesystem::is_directory(path, ec) ? "40000 " : "100644 ";
        // Get the relative path of the entry with respect to the base directory
        std::string relative_path = path.substr(path.find(directory) + directory.length() + 1);
        // Recursively write tree for directories or hash blob for files, then convert to binary hash
        std::string hash = std::filesystem::is_directory(path, ec) ?
                           hashDigest(writeTree(path.c_str())):
                           hashDigest(hashObject(path.c_str(), "blob", false));
        
        // Store the tree entry in the format: mode + filename + null byte + hash
        tree_entries.emplace_back(path + '\0' + entry_type + relative_path + '\0' + hash);
    }

    // Sort the entries lexicographically by their absolute path
    std::sort(tree_entries.begin(), tree_entries.end());

    int bytes = 0;
    // Remove the absolute path prefix from each entry and calculate total byte length
    for (auto& entry : tree_entries) {
        entry = entry.substr(entry.find('\0') + 1);
        bytes += entry.length();
    }

    // Construct the tree object content with header and concatenated entries
    std::string tree_content = "tree " + std::to_string(bytes) + '\0';
    for (const auto& entry : tree_entries) {
        tree_content += entry;
    }

    // Compute the SHA-1 hash of the tree content and store the compressed object
    std::string tree_hash = compute_sha1(tree_content, false);
    compressAndStore(tree_hash.c_str(), tree_content);

    return tree_hash; // Return the hash of the tree object
}

/**
 * Creates a commit object in the git repository.
 * 
 * @param tree_sha The SHA-1 hash of the tree object.
 * @param parent_sha The SHA-1 hash of the parent commit.
 * @param message The commit message.
 * @return The SHA-1 hash of the created commit object.
 */
std::string commitTree (std::string tree_sha, std::string parent_sha, std::string message) {
    std::string author = "author"; // Author information
    std::string committer = "committer"; // Committer information
    std::string timestamp = std::to_string(std::time(nullptr)); // Current timestamp

    // Construct the commit content
    std::string commit_content = "tree " + tree_sha + "\n" +
                                 "parent " + parent_sha + "\n" +
                                 "author " + author + " " + timestamp + " -0800\n" +
                                 "committer " + committer + " " + timestamp + " -0800\n" +
                                 "\n" + message + "\n";
    
    // Add the commit header
    std::string header = "commit " + std::to_string(commit_content.length()) + '\0';
    commit_content = header + commit_content;

    // Compute the SHA-1 hash of the commit content
    std::string commit_hash = compute_sha1(commit_content, false);
    // Compress and store the commit object
    compressAndStore(commit_hash.c_str(), commit_content);

    return commit_hash; // Return the commit hash
}

// curl helper function
/**
 * Callback function for curl to write received data.
 * 
 * @param received_data Pointer to the received data.
 * @param element_size Size of each element.
 * @param num_element Number of elements.
 * @param userdata Pointer to user data, expected to be a std::string* to accumulate data.
 * @return The number of bytes processed.
 */
size_t writeCallback (void* received_data, size_t element_size, size_t num_element, void* userdata) {
    size_t total_size = element_size * num_element;
    // Construct a string from the received data
    std::string received_text((char*) received_data, num_element);

    // Cast userdata to string pointer to store the master hash
    std::string* master_hash = (std::string*) userdata;

    // Check if the received text does not contain the service string (likely a typo "servie")
    if (received_text.find("servie=git-upload-pack") == std::string::npos) {
        // Find the position of "refs/heads/master\n" in the received text
        size_t hash_pos = received_text.find("refs/heads/master\n");
        if (hash_pos != std::string::npos) {
            // Extract the 40-character hash preceding the found position
            *master_hash = received_text.substr(hash_pos - 41, 40);
        }
    }

    return total_size; // Return the total size processed
}

// curl helper function
/**
 * Callback function for curl to write received data.
 * 
 * @param received_data Pointer to the received data.
 * @param element_size Size of each element.
 * @param num_element Number of elements.
 * @param userdata Pointer to user data, expected to be a std::string* to accumulate data.
 * @return The number of bytes processed.
 */
size_t packDataCallback (void* received_data, size_t element_size, size_t num_element, void* userdata) {
    // Cast userdata to string pointer to accumulate received data
    std::string* accumulated_data = (std::string*) userdata;
    // Append received data to accumulated_data
    *accumulated_data += std::string((char*) received_data, num_element);

    // Return the total size of processed data
    return element_size * num_element;
}

/**
 * Makes a curl request to fetch git repository information and pack data.
 * 
 * @param url The URL of the git repository.
 * @return A pair containing the pack data and the pack hash.
 */
std::pair<std::string, std::string> curlRequest (const std::string& url) {
    CURL* handle = curl_easy_init(); // Initialize a curl session
    if (handle) {
        // Fetch info/refs
        curl_easy_setopt(handle, CURLOPT_URL, (url + "/info/refs?service=git-upload-pack").c_str());
        
        std::string packhash;
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writeCallback); // Set the write callback function
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void*) &packhash); // Set the userdata for the callback
        curl_easy_perform(handle); // Perform the curl request
        curl_easy_reset(handle); // Reset the curl session

        // Fetch git-upload-pack
        curl_easy_setopt(handle, CURLOPT_URL, (url + "/git-upload-pack").c_str());
        std::string postdata = "0032want " + packhash + "\n" +
                               "00000009done\n";
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, postdata.c_str()); // Set the POST data

        std::string pack;
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void*) &pack); // Set the userdata for the callback
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, packDataCallback); // Set the write callback function

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-git-upload-pack-request");
        curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers); // Set the HTTP headers
        curl_easy_perform(handle); // Perform the curl request

        // Clean up
        curl_easy_cleanup(handle); // Clean up the curl session
        curl_slist_free_all(headers); // Free the list of headers

        return {pack, packhash}; // Return the pack data and pack hash
    }
    else {
        std::cerr << "Failed to initialize curl.\n"; // Error message if curl initialization fails
        return {};
    }
}


/**
 * Converts a git hash digest (binary data) to its hexadecimal string representation.
 * 
 * @param digest The binary digest string (typically 20 bytes for SHA-1).
 * @return The hexadecimal string representation of the digest.
 */
std::string digestToHash (const std::string& digest) {
    std::stringstream ss;
    for (unsigned char c : digest) {
        // Convert each byte to a two-digit hexadecimal string with leading zeros
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }

    return ss.str();
}

/**
 * Reads the length of an object from the pack data.
 * 
 * @param pack The string containing the pack data.
 * @param pos Pointer to the current position in the pack data.
 * @return The length of the object.
 */
int readLength (const std::string& pack, int* pos) {
    int length = 0;

    // Extract the lower 4 bits of the first byte
    length |= pack[*pos] & 0x0F;

    // If the MSB is set, read the next byte
    if (pack[*pos] & 0x80) {
        (*pos)++;

        // Continue reading bytes while the MSB is set
        while (pack[*pos] & 0x80) {
            length <<= 7;
            length |= pack[*pos] & 0x7F;
            (*pos)++;
        }

        // Read the last byte
        length <<= 7;
        length |= pack[*pos];
    }

    (*pos)++; // Move to the next position

    return length;
}

/**
 * Applies a delta to a base object to reconstruct the original object.
 * 
 * @param delta_contents The contents of the delta.
 * @param base_contents The contents of the base object.
 * @return The reconstructed object.
 */
std::string applyDelta (const std::string& delta_contents, const std::string& base_contents) {
    std::string reconstructed_object;
    int current_position_in_delta = 0;

    // Read and skip the length of the base object
    readLength(delta_contents, &current_position_in_delta);
    readLength(delta_contents, &current_position_in_delta);

    // Iterate through the delta contents
    while (current_position_in_delta < delta_contents.length()) {
        unsigned char current_instruction = delta_contents[current_position_in_delta++];

        // Check if the highest bit of the instruction byte is set
        if (current_instruction & 0x80) {
            int copy_offset = 0;
            int copy_size = 0;
            int bytes_processed_for_offset = 0;

            // Calculate copy offset from the delta contents
            for (int i = 3; i >= 0; i--) {
                copy_offset <<= 8;
                if (current_instruction & (1 << i)) {
                    copy_offset += static_cast<unsigned char>(delta_contents[current_position_in_delta + i]);
                    bytes_processed_for_offset++;
                }
            }

            int bytes_processed_for_size = 0;
            // Calculate copy size from the delta contents
            for (int i = 6; i >= 4; i--) {
                copy_size <<= 8;
                if (current_instruction & (1 << i)) {
                    copy_size += static_cast<unsigned char>(delta_contents[current_position_in_delta + i - (4 - bytes_processed_for_offset)]);
                    bytes_processed_for_size++;
                }
            }

            // Default size to 0x100000 if no size was specified
            if (copy_size == 0) {
                copy_size = 0x100000;
            }

            // Append the copied data from base contents to the reconstructed object
            reconstructed_object += base_contents.substr(copy_offset, copy_size);
            current_position_in_delta += bytes_processed_for_size + bytes_processed_for_offset;
        }
        else {
            // Direct add instruction, the highest bit is not set
            int add_size = current_instruction & 0x7F;
            reconstructed_object += delta_contents.substr(current_position_in_delta, add_size);
            current_position_in_delta += add_size;
        }
    }

    return reconstructed_object;
}

/**
 * Reads the contents of a blob object and writes it to the destination file.
 * 
 * @param file_path The path to the blob object.
 * @param dir The directory containing the git objects.
 * @param dest The destination file to write the blob contents to.
 * @param print_out Flag to indicate whether to print the blob path.
 * @return EXIT_SUCCESS if successful, EXIT_FAILURE otherwise.
 */
int catFileForClone(const char* file_path, const std::string& dir, FILE* dest, bool print_out = false) {
    try {
        std::string blob_sha = file_path; // Convert file path to blob SHA-1 hash
        std::string blob_path = dir + "/.git/objects/" + blob_sha.insert(2, "/"); // Construct the blob path
        if (print_out) std::cout << "blob path: " << blob_path << std::endl;

        FILE* blob_file = fopen(blob_path.c_str(), "rb"); // Open the blob file
        if (blob_file == NULL) {
            std::cerr << "Invalid object hash.\n";
            return EXIT_FAILURE;
        }

        decompress(blob_file, dest); // Decompress the blob file to the destination file
        fclose(blob_file); // Close the blob file
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Restores a git tree object by creating directories and files as specified in the tree object.
 * 
 * @param tree_hash The SHA-1 hash of the tree object.
 * @param dir The directory to restore the tree object into.
 * @param proj_dir The base directory of the git project.
 */
void restoreTree (const std::string& tree_hash, const std::string& dir, const std::string& proj_dir) {
    // Construct the path to the tree object
    std::string object_path = proj_dir + "/.git/objects/" + tree_hash.substr(0, 2) + '/' + tree_hash.substr(2);
    std::ifstream master_tree(object_path);

    // Read the contents of the tree object into a buffer
    std::ostringstream buffer;
    buffer << master_tree.rdbuf();

    // Decompress the tree object
    std::string tree_contents = decompress_string(buffer.str());

    // Skip the metadata part of the tree object
    tree_contents = tree_contents.substr(tree_contents.find('\0') + 1);

    // Iterate over each entry in the tree object
    int pos = 0;
    while (pos < tree_contents.length()) {
        if (tree_contents.find("40000", pos) == pos) {
            pos += 6; // Skip the mode 40000

            // Extract the directory path
            std::string path = tree_contents.substr(pos, tree_contents.find('\0', pos) - pos);
            pos += path.length() + 1; // Skip the path and the null byte

            // Extract the hash of the nested tree object
            std::string next_hash = digestToHash(tree_contents.substr(pos, 20));

            // Create directories and recursively restore the nested tree
            std::filesystem::create_directory(dir + '/' + path);
            restoreTree(next_hash, dir + '/' + path, proj_dir);
            pos += 20; // Skip the hash
        }
        else {
            pos += 7; // Skip the mode 100644

            // Extract the file path
            std::string path = tree_contents.substr(pos, tree_contents.find('\0', pos) - pos);
            pos += path.length() + 1; // Skip the path and the null byte

            // Extract the hash of the blob object
            std::string blob_hash = digestToHash(tree_contents.substr(pos, 20));

            // Create the file and write its contents
            FILE* new_file = fopen((dir + '/' + path).c_str(), "wb");
            catFileForClone(blob_hash.c_str(), proj_dir, new_file);
            fclose(new_file);
            pos += 20; // Skip the hash
        }
    }
}

/**
 * Clones a git repository from the given URL into the specified directory.
 * 
 * @param url The URL of the git repository to clone.
 * @param dir The directory to clone the repository into.
 * @return EXIT_SUCCESS if successful, EXIT_FAILURE otherwise.
 */
int clone (std::string url, std::string dir) {
    // create the repository directory and initialize it
    std::filesystem::create_directory(dir);
    if (gitInit(dir) != true) {
        std::cerr << "Failed to initialize git repository.\n";
        return EXIT_FAILURE;
    }

    // fetch the repository
    auto [pack, packhash] = curlRequest(url);

    // parse the pack file
    int num_objects = 0;
    for (int i=16; i<20; i++) {
        num_objects = num_objects << 8;
        num_objects = num_objects | (unsigned char) pack[i];
    }
    pack = pack.substr(20, pack.length() - 40); // removing the headers of HTTP

    // proecessing object files in a git pack file
    int object_type;
    int current_position = 0;
    std::string master_commit_contents;
    for (int object_index = 0; object_index < num_objects; object_index++) {
        // extract object type from the first byte
        object_type = (pack[current_position] & 112) >> 4; // 112 is 11100000

        // read the object's length
        int object_length = readLength(pack, &current_position);

        // process based on object type
        if (object_type == 6) { // offset deltas: ignore it
            throw std::invalid_argument("Offset deltas not implemented.\n");
        }
        else if (object_type == 7) { // reference deltas
            // process reference deltas
            std::string digest = pack.substr(current_position, 20);
            std::string hash = digestToHash(digest);
            current_position += 20;

            // read the base object's contents
            std::ifstream file(dir + "/.git/objects/" + hash.insert(2, "/"));
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string file_contents = buffer.str();

            std::string base_object_contents = decompress_string(file_contents);
            
            // extract and remove the object type
            std::string object_type_extracted = base_object_contents.substr(0, base_object_contents.find(" "));
            base_object_contents = base_object_contents.substr(base_object_contents.find('\0') + 1);

            // apply delta to base object
            std::string delta_contents = decompress_string(pack.substr(current_position));
            std::string reconstructed_contents = applyDelta(delta_contents, base_object_contents);

            // reconstruct the object with its type and length
            reconstructed_contents = object_type_extracted + ' ' + std::to_string(reconstructed_contents.length()) + '\0' + reconstructed_contents;

            // compute the object hash and store it
            std::string object_hash = compute_sha1(reconstructed_contents);
            compressAndStore(object_hash.c_str(), reconstructed_contents, dir);

            // advance position past the delta data
            std::string compressed_delta = compress_string(delta_contents);
            current_position += compressed_delta.length();

            // update master commits if hash matches
            if (hash.compare(packhash) == 0) {
                master_commit_contents = reconstructed_contents.substr(reconstructed_contents.find('\0'));
            }
        }
        else { // other object types (1: commit, 2: tree, other: blob)
            // process standard objects
            std::string object_contents = decompress_string(pack.substr(current_position));
            current_position += compress_string(object_contents).length();

            // prepare object header
            std::string object_type_str = (object_type == 1) ? "commit " : (object_type == 2) ? "tree " : "blob ";
            object_contents = object_type_str + std::to_string(object_contents.length()) + '\0' + object_contents;

            // store the object and update master commits if hash matches
            std::string object_hash = compute_sha1(object_contents, false);
            std::string compressed_object = compress_string(object_contents);
            compressAndStore(object_hash.c_str(), object_contents, dir);
            if (object_hash.compare(packhash) == 0) {
                master_commit_contents = object_contents.substr(object_contents.find('\0'));
            }
        }
    }

    // restore the tree
    std::string tree_hash = master_commit_contents.substr(master_commit_contents.find("tree") + 5, 40);
    restoreTree(tree_hash, dir, dir);

    return EXIT_SUCCESS;
}

/**
 * Main entry point of the program that processes git-like commands.
 * 
 * @param argc The number of command-line arguments.
 * @param argv The array of command-line argument strings.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "No command provided.\n";
        return EXIT_FAILURE;
    }

    std::string command = argv[1];

    if (command == "init") {
        // Initialize a new git repository in the current directory
        if (gitInit(".") != true) {
            std::cerr << "Failed to initialize git repository.\n";
            return EXIT_FAILURE;
        }
    }
    else if (command == "cat-file") {
        // Check if object hash is provided
        if (argc < 3) {
            std::cerr << "No object hash provided.\n";
            return EXIT_FAILURE;
        }

        // Construct the path to the object file based on the hash
        char dataPath[64];
        snprintf(dataPath, sizeof(dataPath), ".git/objects/%.2s/%s", argv[3], argv[3] + 2);
        // Output the contents of the object file
        if (catFile(dataPath) != EXIT_SUCCESS) {
            std::cerr << "Failed to retrieve object.\n";
            return EXIT_FAILURE;
        }
    }
    else if (command == "hash-object") {
        // Check if file path is provided
        if (argc < 4) {
            std::cerr << "No file path provided.\n";
            return EXIT_FAILURE;
        }

        // Retrieve file name from arguments
        std::string fileName = argv[3];

        // Compute the hash of the file object
        std::string hash = hashObject(fileName, "blob", false);
        if (hash.empty()) {
            std::cerr << "Failed to hash object.\n";
            return EXIT_FAILURE;
        }

        // Print the computed hash
        std::cout << hash << std::endl;
    }
    else if (command == "ls-tree") {
        // Check if object hash is provided
        if (argc < 4) {
            std::cerr << "No object hash provided.\n";
            return EXIT_FAILURE;
        }

        // Retrieve the object hash from arguments
        std::string objectHash = argv[3];
        // List the contents of the tree object
        if (ls_tree(objectHash.c_str()) != EXIT_SUCCESS) {
            std::cerr << "Failed to retrieve object.\n";
            return EXIT_FAILURE;
        }
    }
    else if (command == "write-tree") {
        // Check if command is provided (redundant here)
        if (argc < 2) {
            std::cerr << "No command provided.\n";
            return EXIT_FAILURE;
        }

        // Get the current working directory path
        std::filesystem::path current_path = std::filesystem::current_path();
        // Write the tree object for the current directory and print its hash
        std::string tree_hash = writeTree(current_path.string());
        std::cout << tree_hash << std::endl;
    }
    else if (command == "commit-tree") {
        // Check if enough arguments are provided for commit-tree
        if (argc < 7) {
            std::cerr << "Too few arguments.\n";
            return EXIT_FAILURE;
        }

        // Extract tree SHA, parent SHA, and commit message from arguments
        std::string tree_sha = argv[2];
        std::string parent_sha = argv[4];
        std::string message = argv[6];
        
        // Create a commit object and print its hash
        std::string commit_hash = commitTree(tree_sha, parent_sha, message);
        std::cout << commit_hash << std::endl;
    }
    else if (command == "clone") {
        // Check if repository URL is provided
        if (argc < 3) {
            std::cerr << "No repository provided.\n";
            return EXIT_FAILURE;
        }

        // Extract URL and target directory from arguments
        std::string url = argv[2];
        std::string directory = argv[3];

        // Clone the repository into the specified directory
        if (clone(url, directory) != EXIT_SUCCESS) {
            std::cerr << "Failed to clone repository.\n";
            return EXIT_FAILURE;
        }
    }
    else {
        // Unknown command error
        std::cerr << "Unknown command " << command << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}