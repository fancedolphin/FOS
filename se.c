#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <minix/mthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#define HANDLE_ERRORS(msg) handleErrors(__FILE__, __LINE__, msg)
#define KEY_LENGTH 32  // 256 bits
#define IV_LENGTH 16   // 128 bits
#define BUFFER_SIZE 1024 // 1 KB buffer size
#define AES_BLOCK_SIZE 16 // 128 bits
#define HASH_LENGTH SHA256_DIGEST_LENGTH // 32 bytes
#define ADMIN_KEY_FILE "adminKey.bin" // File to store the admin password hash
#define HASH_VALUE_FILE "HashValue.bin" // File to store the hash values of encrypted files
#define LARGE_BUFFER_SIZE (4 * 1024 * 1024) // 4MB buffer for improved I/O
#define NUM_BUFFERS 2 // The number of double buffers

// 32 bytes fixed key and 16 bytes fixed IV
const unsigned char fixed_key[KEY_LENGTH] = "01234567890123456789012345678901"; // 32 bytes fixed key
const unsigned char fixed_iv[IV_LENGTH] = "0123456789012345"; // 16 bytes fixed IV

// Mutex lock used to protect the writing of the hash value file
static mthread_mutex_t hash_file_mutex;

/**
 * @brief Double buffer structure, used to optimize I/O operations
 */
typedef struct {
    unsigned char *buffers[NUM_BUFFERS];  /**< Buffer array */
    unsigned char *out_buffers[NUM_BUFFERS]; /**< Output buffer array */
    size_t buffer_size;                   /**< Buffer size */
    int active_buffer;                    /**< Index of the current active buffer */
} DoubleBuffer;

/**
 * @brief Struct to hold data for thread processing.
 */
typedef struct {
    char *input_filename;  /**< Input filename */
    char *output_filename; /**< Output filename */
    unsigned char key[KEY_LENGTH]; /**< Encryption/Decryption key */
    unsigned char iv[IV_LENGTH]; /**< Initialization Vector */
    int do_encrypt; /**< Flag to indicate whether to encrypt (1) or decrypt (0) */
} ThreadData;

/**
 * @brief Handles errors by printing the error message and exiting the program.
 *
 * @param file The name of the file where the error occurred.
 * @param line The line number where the error occurred.
 * @param msg The error message to print.
 */
void handleErrors(const char *file, int line, const char *msg) {
    printf("Error occurred in file %s at line %d: %s\n", file, line, msg);
    exit(1);
}

/**
 * @brief Initializes the double buffer structure
 *
 * @param db Pointer to the double buffer structure
 * @param buffer_size Buffer size
 * @return int Returns 0 on success, -1 on failure
 */
int init_double_buffer(DoubleBuffer *db, size_t buffer_size) {
    db->buffer_size = buffer_size;
    db->active_buffer = 0;
    
    for (int i = 0; i < NUM_BUFFERS; i++) {
        db->buffers[i] = (unsigned char *)malloc(buffer_size);
        db->out_buffers[i] = (unsigned char *)malloc(buffer_size + AES_BLOCK_SIZE);
        
        if (!db->buffers[i] || !db->out_buffers[i]) {
            // Clean up the allocated memory
            for (int j = 0; j <= i; j++) {
                if (db->buffers[j]) free(db->buffers[j]);
                if (db->out_buffers[j]) free(db->out_buffers[j]);
            }
            return -1;      
        }
    }
    
    return 0;
}

/**
 * @brief Cleans up the double buffer structure
 *
 * @param db Pointer to the double buffer structure
 */
void cleanup_double_buffer(DoubleBuffer *db) {
    for (int i = 0; i < NUM_BUFFERS; i++) {
        if (db->buffers[i]) {
            free(db->buffers[i]);
            db->buffers[i] = NULL;
        }
        
        if (db->out_buffers[i]) {
            free(db->out_buffers[i]);
            db->out_buffers[i] = NULL;
        }
    }
}

/**
 * @brief Switches to the next buffer
 *
 * @param db Pointer to the double buffer structure
 * @return int Returns the index of the new active buffer
 */
int switch_buffer(DoubleBuffer *db) {
    db->active_buffer = (db->active_buffer + 1) % NUM_BUFFERS;
    return db->active_buffer;
}

/**
 * @brief Gets the current active buffer
 *
 * @param db Pointer to the double buffer structure
 * @return unsigned char* Returns the pointer to the current active buffer
 */
unsigned char *get_active_buffer(DoubleBuffer *db) {
    return db->buffers[db->active_buffer];
}

/**
 * @brief Gets the current active output buffer
 *
 * @param db Pointer to the double buffer structure
 * @return unsigned char* Returns the pointer to the current active output buffer
 */
unsigned char *get_active_out_buffer(DoubleBuffer *db) {
    return db->out_buffers[db->active_buffer];
}

/**
 * @brief Computes the SHA-256 hash of a file.
 *
 * @param filename The name of the file to hash.
 * @param hash The buffer to store the computed hash.
 */
void sha256_file(const char *filename, unsigned char *hash) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        HANDLE_ERRORS("Failed to open file for hashing");
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    // Use a larger buffer to improve performance
    unsigned char *buffer = malloc(LARGE_BUFFER_SIZE);
    if (!buffer) {
        close(fd);
        HANDLE_ERRORS("Failed to allocate hash calculation buffer");
    }
    
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, LARGE_BUFFER_SIZE)) > 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }

    if (bytes_read < 0) {
        free(buffer);
        close(fd);
        HANDLE_ERRORS("Error reading file for hash calculation");
    }

    SHA256_Final(hash, &sha256);
    free(buffer);
    close(fd);
}

/**
 * @brief Checks if a given hash exists in a file.
 *
 * @param hash The hash to check.
 * @param filename The file containing the list of hashes.
 * @return int 1 if the hash is found, 0 otherwise.
 */
int hash_in_file(const unsigned char *hash, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        HANDLE_ERRORS("Failed to open hash value file");
    }

    char line[HASH_LENGTH * 2 + 1]; // SHA256 hash in hex + null terminator
    unsigned char file_hash[HASH_LENGTH];
    int found = 0;
    
    // Acquire the mutex lock to read the hash file
    mthread_mutex_lock(&hash_file_mutex);
    
    while (fgets(line, sizeof(line), file)) {
        for (int i = 0; i < HASH_LENGTH; ++i) {
            sscanf(&line[i * 2], "%2hhx", &file_hash[i]);
        }
        if (memcmp(hash, file_hash, HASH_LENGTH) == 0) {
            found = 1;
            break;
        }
    }
    
    mthread_mutex_unlock(&hash_file_mutex);
    fclose(file);
    return found;
}

/**
 * @brief Saves a hash to a file with mutex protection.
 *
 * @param hash The hash to save.
 * @param filename The file to save the hash to.
 */
void save_hash_to_file(const unsigned char *hash, const char *filename) {
    // Acquire the mutex lock to write to the hash file
    mthread_mutex_lock(&hash_file_mutex);
    
    FILE *file = fopen(filename, "a");
    if (!file) {
        mthread_mutex_unlock(&hash_file_mutex);
        HANDLE_ERRORS("Failed to open hash value file for writing");
    }

    for (int i = 0; i < HASH_LENGTH; ++i) {
        fprintf(file, "%02x", hash[i]);
    }
    fprintf(file, "\n");
    fclose(file);
    
    mthread_mutex_unlock(&hash_file_mutex);
}

/**
 * @brief Uses the double buffer to optimize the encryption or decryption of a file
 *
 * @param data The data required for encryption or decryption
 */
void encrypt_decrypt_file(ThreadData *data) {
    int input_fd = open(data->input_filename, O_RDONLY);
    int output_fd = open(data->output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    
    if (input_fd < 0 || output_fd < 0) {
        HANDLE_ERRORS("Failed to open input or output file");
    }
    
    DoubleBuffer db;
    if (init_double_buffer(&db, LARGE_BUFFER_SIZE) != 0) {
        close(input_fd);
        close(output_fd);
        HANDLE_ERRORS("Failed to initialize double buffer");
    }
    
    unsigned char iv[IV_LENGTH];
    AES_KEY aes_key;
    
    if (data->do_encrypt) {
        // Generate a random IV and write it to the output file
        if (!RAND_bytes(iv, IV_LENGTH)) {
            HANDLE_ERRORS("Failed to generate random IV");
        }
        if (write(output_fd, iv, IV_LENGTH) != IV_LENGTH) {
            HANDLE_ERRORS("Failed to write IV to output file");
        }
        
        if (AES_set_encrypt_key(data->key, 256, &aes_key) < 0) {
            HANDLE_ERRORS("Failed to set encryption key");
        }
    } else {
        // Read the IV from the input file
        if (read(input_fd, iv, IV_LENGTH) != IV_LENGTH) {
            HANDLE_ERRORS("Failed to read IV from input file");
        }
        
        if (AES_set_decrypt_key(data->key, 256, &aes_key) < 0) {
            HANDLE_ERRORS("Failed to set decryption key");
        }
    }
    
    // Get the file size
    off_t file_size = lseek(input_fd, 0, SEEK_END);
    lseek(input_fd, data->do_encrypt ? 0 : IV_LENGTH, SEEK_SET);
    
    size_t remaining = data->do_encrypt ? file_size : (file_size - IV_LENGTH);
    int last_block = 0;
    int padding = 0;
    
    // Process the file data
    while (remaining > 0) {
        // Get the current active buffer
        unsigned char *buffer = get_active_buffer(&db);
        unsigned char *out_buffer = get_active_out_buffer(&db);
        
        // Read the data
        size_t to_read = (remaining < db.buffer_size) ? remaining : db.buffer_size;
        ssize_t bytes_read = read(input_fd, buffer, to_read);
        
        if (bytes_read <= 0) {
            break;
        }
        
        // Check if it is the last block
        if (bytes_read < db.buffer_size) {
            last_block = 1;
        }
        
        size_t process_size = bytes_read;
        
        // Encrypt or decrypt the data
        if (data->do_encrypt) {
            if (last_block) {
                // Add padding
                padding = AES_BLOCK_SIZE - (bytes_read % AES_BLOCK_SIZE);
                memset(buffer + bytes_read, padding, padding);
                process_size += padding;
            }
            AES_cbc_encrypt(buffer, out_buffer, process_size, &aes_key, iv, AES_ENCRYPT);
        } else {
            AES_cbc_encrypt(buffer, out_buffer, process_size, &aes_key, iv, AES_DECRYPT);
            if (last_block) {
                // Check and remove padding
                padding = out_buffer[process_size - 1];
                if (padding > 0 && padding <= AES_BLOCK_SIZE) {
                    process_size -= padding;
                }
            }
        }
        
        // Write the data
        ssize_t bytes_written = write(output_fd, out_buffer, process_size);
        if (bytes_written != process_size) {
            HANDLE_ERRORS("Failed to write to output file");
        }
        
        // Switch to the next buffer
        switch_buffer(&db);
        
        remaining -= bytes_read;
    }
    
    // Clean up resources
    cleanup_double_buffer(&db);
    close(input_fd);
    close(output_fd);
    
    // Print the success message
    if (data->do_encrypt) {
        printf("File '%s' has been encrypted successfully.\n", data->input_filename);
        // Compute and save the hash value of the encrypted file
        unsigned char hash[HASH_LENGTH];
        sha256_file(data->output_filename, hash);
        save_hash_to_file(hash, HASH_VALUE_FILE);
    } else {
        // Verify the hash value of the decrypted file
        unsigned char hash[HASH_LENGTH];
        sha256_file(data->input_filename, hash);
        if (hash_in_file(hash, HASH_VALUE_FILE)) {
            printf("File '%s' has been decrypted successfully.\n", data->input_filename);
        } else {
            printf("Hash value of file '%s' not found. Continue decryption? (y/n): ", data->input_filename);
            char choice;
            scanf(" %c", &choice);
            if (choice == 'y' || choice == 'Y') {
                printf("File '%s' has been decrypted successfully.\n", data->input_filename);
            } else {
                printf("Decryption of file '%s' aborted.\n", data->input_filename);
                remove(data->output_filename);  // Delete the decrypted file
            }
        }
    }
}

/**
 * @brief Thread function for encrypting or decrypting a file.
 *
 * @param arg Pointer to the ThreadData structure.
 * @return void* Always returns NULL.
 */
void *thread_func(void *arg) {
    ThreadData *data = (ThreadData *) arg;
    encrypt_decrypt_file(data);
    return NULL;
}

/**
 * @brief Constructs the output filename based on the input filename and the operation (encrypt/decrypt).
 *
 * @param output_filename The buffer to store the output filename.
 * @param input_filename The input filename.
 * @param do_encrypt Flag indicating whether to encrypt (1) or decrypt (0).
 */
void construct_output_filename(char *output_filename, const char *input_filename, int do_encrypt) {
    const char *ext = do_encrypt ? ".encrypted" : ".decrypted";
    snprintf(output_filename, strlen(input_filename) + strlen(ext) + 1, "%s%s", input_filename, ext);
}

/**
 * @brief Computes the SHA-256 hash of a string.
 *
 * @param str The string to hash.
 * @param len The length of the string.
 * @param hash The buffer to store the computed hash.
 */
void sha256(const char *str, size_t len, unsigned char *hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, len);
    SHA256_Final(hash, &sha256);
}

/**
 * @brief Verifies the password by comparing its hash with the stored hash in the admin key file.
 *
 * @param password The password to verify.
 * @return int 1 if the password is correct, 0 otherwise.
 */
int verify_password(const char *password) {
    unsigned char hash[HASH_LENGTH];
    sha256(password, strlen(password), hash);

    FILE *file = fopen(ADMIN_KEY_FILE, "rb");
    if (!file) {
        HANDLE_ERRORS("Failed to open admin key file");
    }

    unsigned char stored_hash[HASH_LENGTH];
    fread(stored_hash, 1, HASH_LENGTH, file);
    fclose(file);

    return memcmp(hash, stored_hash, HASH_LENGTH) == 0;
}

/**
 * @brief Sets the admin password by storing its hash in the admin key file.
 *
 * @param password The password to set.
 */
void set_password(const char *password) {
    unsigned char hash[HASH_LENGTH];
    sha256(password, strlen(password), hash);

    FILE *file = fopen(ADMIN_KEY_FILE, "wb");
    if (!file) {
        HANDLE_ERRORS("Failed to open admin key file for writing");
    }

    fwrite(hash, 1, HASH_LENGTH, file);
    fclose(file);
}

/**
 * @brief Lists the files available for encryption or decryption.
 *
 * @param files The buffer to store the file names.
 * @param num_files The number of files found.
 * @param encrypt Flag indicating whether to list files for encryption (1) or decryption (0).
 */

/**
 * @brief Lists the files available for encryption or decryption.
 *
 * @param files The buffer to store the file names.
 * @param num_files The number of files found.
 * @param encrypt Flag indicating whether to list files for encryption (1) or decryption (0).
 */
void list_files(char ***files, int *num_files, int encrypt) {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (!d) {
        HANDLE_ERRORS("Failed to open current directory");
    }

    *num_files = 0;
    *files = NULL;

    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG) {
            int len = strlen(dir->d_name);
            if ((encrypt && (len < 10 || strcmp(dir->d_name + len - 10, ".encrypted") != 0)) ||
                (!encrypt && len >= 10 && strcmp(dir->d_name + len - 10, ".encrypted") == 0)) {
                *files = realloc(*files, (*num_files + 1) * sizeof(char *));
                (*files)[*num_files] = strdup(dir->d_name);
                (*num_files)++;
            }
        }
    }
    closedir(d);
}

/**
 * @brief Processes the user command to encrypt or decrypt files.
 *
 * @param encrypt Flag indicating whether to encrypt (1) or decrypt (0).
 */
void process_command(int encrypt) {
    char **files;
    int num_files;
    list_files(&files, &num_files, encrypt);

    if (num_files == 0) {
        printf("No files available for %s.\n", encrypt ? "encryption" : "decryption");
        return;
    }

    printf("Available files for %s:\n", encrypt ? "encryption" : "decryption");
    for (int i = 0; i < num_files; i++) {
        printf("%d: %s\n", i + 1, files[i]);
    }

    char input[256];
    int selected_files[256];
    int count = 0;

    while (1) {
        printf("Enter the numbers of the files to %s (separated by spaces): ", encrypt ? "encrypt" : "decrypt");
        fgets(input, sizeof(input), stdin);

        char *token = strtok(input, " ");
        count = 0;
        int valid_input = 1;

        while (token != NULL) {
            if (*token == '\n' || *token == '\0') {
                break;
            }
            int index = atoi(token) - 1;
            if (index < 0 || index >= num_files) {
                valid_input = 0;
                break;
            }
            selected_files[count++] = index;
            token = strtok(NULL, " ");
        }

        if (valid_input && count > 0) {
            break;
        } else {
            printf("Invalid input. Please enter valid numbers separated by spaces.\n");
        }
    }

    ThreadData *data = malloc(count * sizeof(ThreadData));
    mthread_thread_t *threads = malloc(count * sizeof(mthread_thread_t));

    for (int i = 0; i < count; i++) {
        int index = selected_files[i];
        data[i].input_filename = files[index];
        data[i].output_filename = malloc(strlen(files[index]) + 11);  // 11 for ".encrypted" or ".decrypted"
        construct_output_filename(data[i].output_filename, files[index], encrypt);
        memcpy(data[i].key, fixed_key, KEY_LENGTH);
        memcpy(data[i].iv, fixed_iv, IV_LENGTH);
        data[i].do_encrypt = encrypt;
        if (mthread_create(&threads[i], NULL, thread_func, &data[i]) != 0) {
            HANDLE_ERRORS("Failed to create thread");
        }
    }

    for (int i = 0; i < count; i++) {
        if (mthread_join(threads[i], NULL) != 0) {
            HANDLE_ERRORS("Failed to join thread");
        }
        free(data[i].output_filename);
    }

    free(data);
    free(threads);

    for (int i = 0; i < num_files; i++) {
        free(files[i]);
    }
    free(files);
}

int main() {
    // init mutex
    if (mthread_mutex_init(&hash_file_mutex, NULL) != 0) {
        HANDLE_ERRORS("Failed to initialize mutex");
    }
    
    // check if the admin key file exists
    FILE *admin_key_file = fopen(ADMIN_KEY_FILE, "rb");
    if (admin_key_file) {
        // check if the file is empty
        fseek(admin_key_file, 0, SEEK_END);
        long file_size = ftell(admin_key_file);
        fclose(admin_key_file);

        if (file_size == 0) {
            // the file is empty, prompt the user to set a new password
            char password[256];
            printf("Set a new admin password: ");
            scanf("%255s", password);
            set_password(password);
            printf("Password set successfully.\n");
        } else {
            // the file exists and is not empty, prompt the user to enter the password
            while (1) {
                char password[256];
                printf("Enter admin password: ");
                scanf("%255s", password);
                if (verify_password(password)) {
                    printf("Password verified. Access granted.\n");
                    break;
                } else {
                    printf("Incorrect password. Try again.\n");
                }
            }
        }
    } else {
        // the admin key file does not exist, prompt the user to set a new password
        char password[256];
        printf("Set a new admin password: ");
        scanf("%255s", password);
        set_password(password);
        printf("Password set successfully.\n");
    }

    while (1) {
        char command[10];
        printf("Enter command (encrypt/decrypt) or 'exit' to quit: ");
        scanf("%9s", command);
        while (getchar() != '\n');  // clear the input buffer

        if (strcmp(command, "exit") == 0) {
            break;
        } else if (strcmp(command, "encrypt") == 0) {
            process_command(1);
        } else if (strcmp(command, "decrypt") == 0) {
            process_command(0);
        } else {
            printf("Invalid command. Please enter 'encrypt', 'decrypt', or 'exit'.\n");
        }
    }
    
    // destroy the mutex
    mthread_mutex_destroy(&hash_file_mutex);

    return 0;
       

}

