//////////////////////////////////////////////////////////////////////////
// COMP1521 21T3 --- Assignment 2: `chicken', a simple file archiver
// <https://www.cse.unsw.edu.au/~cs1521/21T3/assignments/ass2/index.html>
//
// Written by John Henderson (z5368143) on 09/11/2021.
//
// 2021-11-08   v1.1    Team COMP1521 <cs1521 at cse.unsw.edu.au>
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "chicken.h"

// ADD ANY extra #defines HERE
#define TRUE 1
#define FALSE 0

#define PERMISSION_LENGTH 10
#define CONTENT_LENGTH 6

#define BITS_IN_BYTE 8

// ADD YOUR FUNCTION PROTOTYPES HERE
void create_directory(FILE *input_stream, int permission_level);
void create_file(FILE *input_stream, int permission_level, int format);
int *pack_bits(int format, int *file_content, int file_size);
int *unpack_bits(int format, int *packed_array, int unpacked_size);

int add_packed_content(FILE *original_user_files, int content_length, FILE *new_egg_file, int format, int *hash);
void add_file(char *pathname, FILE *new_egg_file, int format);
void add_files_in_directory(DIR *dirp, char *pathname, FILE *new_egg_file, int format);
void add_directory_name(char *pathname, FILE *new_egg_file, int format);

int is_file(char *path);
int is_formatting_option_valid(int format, int *file_content, int file_content_size);

char *get_file_name(FILE *input_stream);
char *get_file_permissions_from_egg(FILE *input_stream);
int *get_file_permissions(char *pathname);
int get_formatted_byte(int byte, int format);
int get_unformatted_byte(int byte, int format);
uint64_t get_content_size(FILE *input_stream, int *hash);
u_int64_t get_packed_size(uint64_t unpacked_size, int format);

// print the files & directories stored in egg_pathname (subset 0)
//
// if long_listing is non-zero then file/directory permissions, formats & sizes are also printed (subset 0)
void list_egg(char *egg_pathname, int long_listing) {

    FILE *input_stream = fopen(egg_pathname, "r");
    if (input_stream == NULL) {
        perror(egg_pathname);
        return;
    }

    // Gets the size of the whole file
    fseek(input_stream, 0, SEEK_END);
    long place = ftell(input_stream);
    fseek(input_stream, 0, SEEK_SET);

    int finished_search = FALSE;
    while (!finished_search) {

        fseek(input_stream, 1, SEEK_CUR);
        
        // Stores egglet format
        int egglet_format = fgetc(input_stream);

        // Stores permissions
        char *permissions = get_file_permissions_from_egg(input_stream);

        char *file_name = get_file_name(input_stream);

        // Get size of content in the file
        uint64_t unpacked_content_size = get_content_size(input_stream, NULL);
        uint64_t packed_content_size = get_packed_size(unpacked_content_size, egglet_format);

        // Move over content
        fseek(input_stream, packed_content_size, SEEK_CUR);

        // Go over hash
        fseek(input_stream, 1, SEEK_CUR);

        // Print formatted names and details of the file        
        if (long_listing) {
            printf("%s  %c  %5lu  %s\n", permissions, egglet_format, unpacked_content_size, file_name);
        } else {
            printf("%s\n", file_name);
        }

        // Check if we are at the end of the file
        if (place == ftell(input_stream)) {
            finished_search = TRUE;
        }
        free(file_name);
        free(permissions);
    }
    // Close the input stream
    fclose(input_stream);
}

// check the files & directories stored in egg_pathname (subset 1)
//
// prints the files & directories stored in egg_pathname with a message
// either, indicating the hash byte is correct, or
// indicating the hash byte is incorrect, what the incorrect value is and the correct value would be
void check_egg(char *egg_pathname) {

    FILE *input_stream = fopen(egg_pathname, "r");
    if (input_stream == NULL) {
        perror(egg_pathname);
        return;
    }

    // Gets the size of the whole file
    fseek(input_stream, 0, SEEK_END);
    long total_file_length = ftell(input_stream);
    fseek(input_stream, 0, SEEK_SET);

    int byte = 0;
    int finished_search = FALSE;

    while (!finished_search) {
        int new_hash = 0;

        // magic number
        byte = fgetc(input_stream);
        if (byte != 'c') {
            fprintf(stderr, "error: incorrect first egglet byte: 0x%x should be 0x%x\n", byte, 'c');
            return;
        }
        new_hash = egglet_hash(new_hash, byte);

        // format
        int format = fgetc(input_stream);
        new_hash = egglet_hash(new_hash, format);

        // Hashes over the permissions
        for (int j = 0; j < EGG_LENGTH_MODE; j++) {
            new_hash = egglet_hash(new_hash, fgetc(input_stream));
        }

        // Gets the size of the file name
        int file_name_size = 0;
        for (int num_of_bytes = 0; num_of_bytes < EGG_LENGTH_PATHNLEN; num_of_bytes++) {
            u_int64_t size_byte = fgetc(input_stream);
            new_hash = egglet_hash(new_hash, size_byte);
            file_name_size += size_byte << (num_of_bytes * BITS_IN_BYTE);
        }

        // Stores the file name
        char file_name[file_name_size + 1];
        for (int j = 0; j < file_name_size; j++) {
            byte = fgetc(input_stream);
            file_name[j] = byte;
            new_hash = egglet_hash(new_hash, byte);
        }
        file_name[file_name_size] = '\0';

        // Get size of content in the file and hash each byte
        uint64_t file_content_size = get_content_size(input_stream, &new_hash);
        uint64_t packed_size = get_packed_size(file_content_size, format);

        // content
        for (int j = 0; j < packed_size; j++) {
            byte = fgetc(input_stream);
            new_hash = egglet_hash(new_hash, byte);
        }

        // Go over hash
        int file_hash = fgetc(input_stream);
        if (file_hash == new_hash) {
            printf("%s - correct hash\n", file_name);
        } else {
            printf("%s - incorrect hash 0x%x should be 0x%x\n", file_name, new_hash, file_hash);
        }
        // Check if we are at the end of the file. 
        if (total_file_length == ftell(input_stream)) {
            finished_search = TRUE;
        }
    }
    // Close the input stream
    fclose(input_stream);
}

// extract the files/directories stored in egg_pathname (subset 2 & 3)
void extract_egg(char *egg_pathname) {

    FILE *input_stream = fopen(egg_pathname, "r");
    if (input_stream == NULL) {
        perror(egg_pathname);
        return;
    }

    // Gets the size of the whole file
    fseek(input_stream, 0, SEEK_END);
    long place = ftell(input_stream);
    fseek(input_stream, 0, SEEK_SET);

    int finished_search = FALSE;
    while (!finished_search) {

        fseek(input_stream, 1, SEEK_CUR);

        // Stores egglet format
        int format = fgetc(input_stream);

        // Gets directory
        char permissions[11];
        for (int j = 0; j < EGG_LENGTH_MODE; j++) {
            permissions[j] = fgetc(input_stream);
        }
        permissions[10] = '\0';
        
        // Get permission number
        int permission_level = 0;
        // first loop controls which section you are looking at |rwx|rwx|rwx|
        for (int j = 0; j < 3; j++) {
            // Controls individually looking at each secton
            for (int k = j * 3 + 1; k < (j + 1) * 3 + 1; k++) {  
                if (permissions[k] == 'r') {
                    permission_level += 4; 
                } else if (permissions[k] == 'w') {
                    permission_level += 2; 
                } else if (permissions[k] == 'x') {
                    permission_level += 1; 
                }
            }
            // This stops the permission level from being timesed by 1 too many 
            if (j != 2) {
                // converts to octal
                permission_level *= 8;
            }
        }

        int is_directory = FALSE;
        if (permissions[0] == 'd') {
            is_directory = TRUE;
        }

        if (is_directory) {
            create_directory(input_stream, permission_level);
        } else {
            create_file(input_stream, permission_level, format);
        }

        // Check if we are at the end of the file
        if (place == ftell(input_stream)) {
            finished_search = TRUE;
        }

    }
    // Close the input stream
    fclose(input_stream);
}


// create egg_pathname containing the files or directories specified in pathnames (subset 3)
//
// if append is zero egg_pathname should be over-written if it exists
// if append is non-zero egglets should be instead appended to egg_pathname if it exists
//
// format specifies the egglet format to use, it must be one EGGLET_FMT_6,EGGLET_FMT_7 or EGGLET_FMT_8
void create_egg(char *egg_pathname, int append, int format,
                int n_pathnames, char *pathnames[n_pathnames]) {
    
    // Switches bwtween append and write
    char property[2] = "w";
    if (append) {
        property[0] = 'a';
    }

    // Create or open the new egg file
    FILE *new_egg_file = fopen(egg_pathname, property);
    if (new_egg_file == NULL) {
        perror(egg_pathname);
        return;
    }

    // Loop through all files
    for (int p = 0; p < n_pathnames; p++) {
        if (is_file(pathnames[p])) {
            // Add directpry
            char *last_slash = strrchr(pathnames[p], '/');
            // If there is a slash, then the we need to add the 
            // parent directories, else just add the file
            if (last_slash != NULL) {
                char *file_path = strndup(pathnames[p], strlen(pathnames[p]) - strlen(last_slash));
                add_directory_name(file_path, new_egg_file, format);
                add_file(pathnames[p], new_egg_file, format);
            } else {
                add_file(pathnames[p], new_egg_file, format);
            }
        
        } else {

            // This occures when we are dealing with a directory
            DIR *dirp = opendir(pathnames[p]);
            if (dirp == NULL) {
                perror(pathnames[p]);  // prints why the open failed
                return;
            }
            
            // Adds the directory name
            add_directory_name(pathnames[p], new_egg_file, format);
            // Adds the files in the directory
            add_files_in_directory(dirp, pathnames[p], new_egg_file, format);

            closedir(dirp);
        }
    }

    fclose(new_egg_file);
}

// ADD YOUR EXTRA FUNCTIONS HERE

// Recusively steps through a directory, and all subdirectories, 
// adding all files. It takes in a pointer to a directory, the directory 
// pathname, the new egg file, and the format of the egg file.
void add_files_in_directory(DIR *dirp, char *pathname, FILE *new_egg_file, int format) {

    struct dirent *de;

    while ((de = readdir(dirp)) != NULL) {

        // Checks that the directory is not the current or the previous directory, prventing loops
        int is_not_dot_directories = TRUE;
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            is_not_dot_directories = FALSE;
        }

        // Creates an array that will contain the full file name + path   
        // + 3 for '0' at the end, and the possible concat of a 2 '/' when further processing.
        // These are used to prevent concat of files names onto directories incorrectly.  
        int total_length = strlen(pathname) + strlen(de->d_name) + 3;
        char directory_name[total_length];
        memset(directory_name, '\0', total_length);

        strcat(directory_name, pathname);
        // Checks if the directory has a '/' at the end or not
        if (directory_name[strlen(directory_name) - 1] != '/') {
            strcat(directory_name, "/");
        }
        strcat(directory_name, de->d_name);
        
        // If the file is a directory, go in and look at those files
        if (de->d_type == 4 && is_not_dot_directories) {
            // Adds the directory 
            add_file(directory_name, new_egg_file, format);
            strcat(directory_name, "/");
            
            DIR *new_dirp = opendir(directory_name);
            if (new_dirp == NULL) {
                perror(directory_name);  // prints why the open failed
                return;
            }   
            add_files_in_directory(new_dirp, directory_name, new_egg_file, format);

            closedir(new_dirp);
        
        // else add all file names
        } else if (is_not_dot_directories) {
            add_file(directory_name, new_egg_file, format);
        }
    }

    return;
}

// Given the name of the file, a pointer to a new .egg file, and the 
// format that is used, add_file() will take the content of the file 
// from the pathname, and add it to the .egg file. Does not modify pathname.
// This function can also be used to add directories.
void add_file(char *pathname, FILE *new_egg_file, int format) {

    // Open file with which content will be coming from    
    FILE *original_user_files = fopen(pathname, "r");
    if (original_user_files == NULL) {
        perror(pathname);
        return;
    }

    int hash = 0;

    // Insert magic number
    hash = egglet_hash(hash, EGGLET_MAGIC);
    fputc(EGGLET_MAGIC, new_egg_file);

    // Insert format
    hash = egglet_hash(hash, format);
    fputc(format, new_egg_file);

    // Gets the permissions of the file
    int *permissions = get_file_permissions(pathname);

    // Hashses the user permissions and stores them in the file
    for (int j = 0; permissions[j] != '\0'; j++) {
        fputc(permissions[j], new_egg_file);
        hash = egglet_hash(hash, permissions[j]);
    }

    // Gets the path name length
    int pathname_length = 0;
    for (int j = 0; pathname[j] != '\0'; j++) {
        pathname_length = j + 1;
    }
    
    // stores the path name length as little-endian 
    uint64_t test_byte = 255;
    for (int j = 0; j < EGG_LENGTH_PATHNLEN; j++) {
        uint64_t store_byte = pathname_length & (test_byte << (BITS_IN_BYTE * j));
        store_byte = store_byte >> (j * BITS_IN_BYTE);
        fputc(store_byte, new_egg_file);
        hash = egglet_hash(hash, store_byte);
    }

    // Stores the actual name of the file
    // char pathname[pathname_length + 1];
    for (int j = 0; j < pathname_length; j++) {
        fputc(pathname[j], new_egg_file);
        hash = egglet_hash(hash, pathname[j]);
    }

    // Gets the length of the user file
    int byte; 
    int content_length = 0;
    while ((byte = fgetc(original_user_files)) != EOF) {
        content_length++;
    }
    // Formula to calculate actual length 
    // Stores the length in little-endian as well as hashes
    test_byte = 255;
    for (int j = 0; j < CONTENT_LENGTH; j++) {
        uint64_t store_byte = content_length & (test_byte << (BITS_IN_BYTE * j));
        store_byte = store_byte >> (j * 8);
        fputc(store_byte, new_egg_file);
        hash = egglet_hash(hash, store_byte);
    }

    // This is to avoid doing more work on packing already 8 bit packed bytes
    if (format == '8') {
        fseek(original_user_files, 0, SEEK_SET);
        while ((byte = fgetc(original_user_files)) != EOF) {
            fputc(byte, new_egg_file);
            hash = egglet_hash(hash, byte);
        }   
    } else {
        int check = add_packed_content(original_user_files, content_length, new_egg_file, format, &hash);
        // Check that there were no issues 
        if (!check) {
            return;
        }
    }
    fputc(hash, new_egg_file);
    printf("Adding: %s\n", pathname);
    fclose(original_user_files);
    free(permissions);
}

// Takes in the files needed, the format, and a pointer to the current hash value, and it 
// preforms actions to pack the bits, and store them into the new_egg_file. This will also
// update the hash value. Returns FALSE (-1) is there is an issue, or TRUE (1) is ther is 
// none.
int add_packed_content(FILE *original_user_files, int content_length, FILE *new_egg_file, 
                        int format, int *hash) {
    // stores the user content into an array before N_bit packing.
    int byte;
    int file_content[content_length + 1];
    memset(file_content, '\0', content_length + 1);

    int i = 0;
    fseek(original_user_files, 0, SEEK_SET);
    while ((byte = fgetc(original_user_files)) != EOF) {
        file_content[i] = byte;
        i++;
    }

    // Check that all the bits can be stored in this format.
    int is_valid = is_formatting_option_valid(format, file_content, content_length);
    if (is_valid >= 0) {
        fprintf(stderr, "error: byte 0x%x can not be represented in %c-bit format\n", is_valid, format);
        return FALSE;
    }

    int *new_content = pack_bits(format, file_content, content_length);

    // Loop through, store and hash.
    for(int j = 0; new_content[j] != '\0'; j++) {
        fputc(new_content[j], new_egg_file);
        *hash = egglet_hash(*hash, new_content[j]);
    }

    free(new_content);

    return TRUE;
}

// Given a directory, format and a new egg file, it goes through the 
// pathname of the direcoty and adds all the parent directories. Note - 
// it does not add the files in all directories, only the directory 
// itself. This is to reconstrute the directories of a file. It does 
// modify pathname, but reconstructs it.
void add_directory_name(char *pathname, FILE *new_egg_file, int format) {
    int size_of_pathname = strlen(pathname);
    char *token = strtok(pathname, "/");

    // Counts the number of parent directories in the pathname. This is
    // used to make sure we have enough space.
    int counter = 1;
    for (int i = 0; i < size_of_pathname; i++) {
        if (pathname[i] == '/') {
            counter++;
        }
    }

    // This will be where all the token are concatonated onto. + 2 for 
    // the concatination 2 '/' in the process.
    char cumalative_path[counter * size_of_pathname + 2];
    memset(cumalative_path, '\0', counter * size_of_pathname + 2);

    while (token != NULL) {
        strcat(cumalative_path, token);
        // Adds the directory
        add_file(cumalative_path, new_egg_file, format);
        strcat(cumalative_path, "/");
        // Gets the next token, then adds it onto add_path
        token = strtok(NULL, " ");
    }

    // Chage original string back
    for (int i = 0; i < size_of_pathname; i++) {
        if (pathname[i] == '\0') {
            pathname[i] = '/';
        }
    }
}

// Creates a directory as described by the input egg file. Note - 
// file pointer must be just before directory name, similarly 
// to get_file_name(). 
void create_directory(FILE *input_stream, int permission_level) {
    char *file_name = get_file_name(input_stream);

    // Create directory
    if (mkdir(file_name, permission_level) != 0) {
        perror(file_name);  // prints why the mkdir failed
        return;
    }

    // Change premissions
    if (chmod(file_name, permission_level) != 0) {
        perror(file_name);  // prints why the chmod failed
        return;
    }
    // Get file pointer to the end of file
    fseek(input_stream, 7, SEEK_CUR);

    printf("Creating directory: %s\n", file_name);
    free(file_name);
}

// Much like create_directory(), create_file is given a FILE pointer, 
// permission_level and a format, and it creates the file as described by 
// the input_Stream egg file. Note - file pointer must be just 
// before file name, similarly to get_file_name(). 
void create_file(FILE *input_stream, int permission_level, int format) {

    char *file_name = get_file_name(input_stream);

    uint64_t file_content_size = get_content_size(input_stream, NULL);

    FILE *output_stream = fopen(file_name, "w");
    if (output_stream == NULL) {
        perror(file_name);
        return;
    }

    int file_content[file_content_size];
    memset(file_content, '\0', file_content_size);

    uint64_t packed_file_size = get_packed_size(file_content_size, format);

    // Move over content and store
    for (int j = 0; j < packed_file_size; j++) {
        int byte = fgetc(input_stream);
        file_content[j] = byte;
    }

    // Unpack and restore bits
    int *unpacked_file_content = unpack_bits(format, file_content, file_content_size);
    for(int j= 0; j < file_content_size; j++) {
        fputc(unpacked_file_content[j], output_stream);
    }

    // Change premissions
    if (chmod(file_name, permission_level) != 0) {
        perror(file_name);  // prints why the chmod failed
        return;
    }
    fclose(output_stream);

    // Go over hash
    fseek(input_stream, 1, SEEK_CUR);

    // Print formatted names and details of the file        
    printf("Extracting: %s\n", file_name);
    
    free(file_name);
    free(unpacked_file_content);
}

// Returns the file name. File pointer must be right before the pathname length
// ie. at byte 12 most of the time. Freeing must be done by the user.
char *get_file_name(FILE *input_stream) {

    // Gets the size of the file name
    int file_name_size = 0;
    for (int num_of_bytes = 0; num_of_bytes < EGG_LENGTH_PATHNLEN; num_of_bytes++) {
        u_int64_t size_byte = fgetc(input_stream);
        // Shifts and add bytes together as they are stored in little-endien
        file_name_size += size_byte << (num_of_bytes * BITS_IN_BYTE);
    }

    // + 1 for the null terminator
    char *file_name = malloc(file_name_size + 1);

    for (int j = 0; j < file_name_size; j++) {
        file_name[j] = fgetc(input_stream);
    }
    file_name[file_name_size] = '\0';

    return file_name;
}

// Returns the file permissions. Freeing must be done by the user.
int *get_file_permissions(char *pathname) {
    // Gets the user permissions
    struct stat fileStat;
    if (stat(pathname, &fileStat) != 0) {
        perror(pathname);
        exit(1);
    }

    // Stores the permission of the file. + 1 for NULL terminator
    int *permissions = malloc(sizeof(int) * (EGG_LENGTH_MODE + 1));
    permissions[0] = *((S_ISDIR(fileStat.st_mode))  ? "d" : "-");
    permissions[1] = *((fileStat.st_mode & S_IRUSR) ? "r" : "-");
    permissions[2] = *((fileStat.st_mode & S_IWUSR) ? "w" : "-");
    permissions[3] = *((fileStat.st_mode & S_IXUSR) ? "x" : "-");
    permissions[4] = *((fileStat.st_mode & S_IRGRP) ? "r" : "-");
    permissions[5] = *((fileStat.st_mode & S_IWGRP) ? "w" : "-");
    permissions[6] = *((fileStat.st_mode & S_IXGRP) ? "x" : "-");
    permissions[7] = *((fileStat.st_mode & S_IROTH) ? "r" : "-");
    permissions[8] = *((fileStat.st_mode & S_IWOTH) ? "w" : "-");
    permissions[9] = *((fileStat.st_mode & S_IXOTH) ? "x" : "-");
    permissions[10] = '\0';
    
    return permissions;
}   

// Given a pointer to an egg file, it will return a char array of the visual
// permissions of a file. Freeing must be done by the user. File pointer 
// must be just before permissions start.
char *get_file_permissions_from_egg(FILE *input_stream) {

    char *permissions = malloc(sizeof(int) * EGG_LENGTH_MODE + 1);
    
    for (int j = 0; j < EGG_LENGTH_MODE; j++) {
        permissions[j] = fgetc(input_stream);
    }
    permissions[10] = '\0';

    return permissions;
}

// Given a byte and format, get_formatted byte will call egg_to_6_bit() 
// to format the byte. If the format is correct, and the byte can be 
// converted, then it returnes the correct byte. Otherwise, if there is 
// any issues with these conditions, it will return -1.
int get_formatted_byte(int byte, int format) {
    if (format == '6') {
        int new_byte = egglet_to_6_bit(byte);
        return new_byte;
    } else if (format == '7' || format == '8') {
        return byte;
    } 
    return -1;
}

// Given a byte and format, get_formatted byte will call egg_from_6_bit() 
// to unformat the byte. If the format is correct, and the byte can be 
// converted, then it returnes the correct byte. Otherwise, if there is 
// any issues with these conditions, it will return -1.
int get_unformatted_byte(int byte, int format) {
    if (format == '6') {
        // Use loop up table
        int new_byte = egglet_from_6_bit(byte);
        return new_byte;
    } else if (format == '7' || format == '8') {
        return byte;
    } 
    return -1;
}

// Given a format, the file content that you are wishing to convert, and the 
// size of the content, this function scans through the content and, if there 
// are no issues, returns -1, but if there is a byte that cannot be converted
// to the format, it returns the position of that byte. This means that it 
// returns a positive number from 0 if there is an issue.
int is_formatting_option_valid(int format, int *file_content, int file_content_size) {
    if (format == '6') {
        for (int i = 0; i < file_content_size; i++) {
            if (egglet_to_6_bit(file_content[i]) == -1) {
                return i;
            }
        }
    } else if (format == '7') {
        for (int i = 0; i < file_content_size; i++) {
            if (file_content[i] > 127) {
                return i;
            }
        }
    } 
    return -1;
}


// Given an array, it will pack N_bits according to the format. 
// Note - the content of file_content should be checked with 
// is_formatting_option_valid() before calling this function, 
// otherwise infomation may be lost. This function may also be 
// called with format 8, but is not recommended as it will return 
// the same content as the original string. It is left to the user 
// to free the returned array.
int *pack_bits(int format, int *file_content, int file_size) {

    int n_bit_packing = format - '0';

    // Converts the whole file to the format given
    for(int i = 0; i < file_size; i++) {
        file_content[i] = get_formatted_byte(file_content[i], format);
    }

    // New array of same length all initialised to '\0'
    int *converted_content = malloc(sizeof(int)*(file_size + 1));
    // Used to keep track of how many bits the format distates are in a byte
    int count_N_bits = 0;
    // Used to keep track of when a byte ends
    int count_8_bits = 0;

    uint32_t test_bit = 1 << (n_bit_packing - 1);
    int new_content_size = 0;

    int curr_byte = 0;
    while (curr_byte < file_size) {
        int new_byte = 0;
        
        while (count_8_bits != 8) {
            // If we are finished, but caught in the middle of this loop,
            // finish last byte by shifting the content left, then exit.
            if (!(curr_byte < file_size)) {
                for (; count_8_bits != BITS_IN_BYTE - 1; count_8_bits++) {
                    new_byte = new_byte << 1;
                }
                break;
            }

            if ((test_bit & file_content[curr_byte]) > 0) {
                new_byte++;
            }
            count_8_bits++;

            // Prevents the last shift which would otherwise shift once too many
            if (count_8_bits != BITS_IN_BYTE) {
                new_byte  = new_byte << 1;
            }

            test_bit = test_bit >> 1;
            count_N_bits++;

            // If we have packed n bits, we need to look at the next byte
            if (count_N_bits == n_bit_packing) {
                test_bit = 1 << (n_bit_packing - 1);
                count_N_bits = 0;
                curr_byte++;
            }
        }
        count_8_bits = 0;
        // Stores new byte in an array
        converted_content[new_content_size] = new_byte;
        new_content_size++;
    }
    converted_content[new_content_size] = '\0';
    return converted_content;
}

// Given an array, it will pack N_bits according to the format. Note - 
// the content of file_content should be checked with is_formatting_option_valid
// before calling this function, otherwise infomation may be lost. This function
// may also be called with format 8, but is not recommended as it will return 
// the same content as the original string. It is left to the user to free the 
// returned array.
int *unpack_bits(int format, int *packed_array, int unpacked_size) {
    int count_8_bits = 0;
    int count_N_bits = 0;

    int n_bit_packing = format - '0';
    
    int packed_size = get_packed_size(unpacked_size, format);
    int *unpacked_array = malloc(sizeof(int) * (unpacked_size + 1));

    uint32_t test_byte = 1 << 7;
    int new_byte = 0;
    int byte_counter = 0;

    int curr_byte = 0;
    while (curr_byte < packed_size) {

        while (count_8_bits < 8) {
            if ((test_byte & packed_array[curr_byte]) > 0) {
                new_byte++;
            }

            test_byte = test_byte >> 1;

            count_N_bits++;
            count_8_bits++;

            // Prevents the byte from shift on the last event
            if (count_N_bits != n_bit_packing) {
                new_byte = new_byte << 1;
            } else { 
                // On the last Nth bit, where the format dictates N, we need to store the current byte,
                // and start again on the next byte.
                count_N_bits = 0;
                unpacked_array[byte_counter] = new_byte;
                new_byte = 0; 
                byte_counter++;               
            }
        }
        test_byte = 1 << 7;
        curr_byte++;
        count_8_bits = 0;
    }
    // At this point, the bytes are unpacked, but for 6 bit packing, they are 
    // not unformatted yet. This loops over and unformats them.
    for (int j = 0; j < unpacked_size; j++) {
        unpacked_array[j] = get_unformatted_byte(unpacked_array[j], format);
    }

    return unpacked_array;
}

// Given a pathname, return 1 if it is a file, and 0 if it is not.
// Does not modify pathname.
int is_file(char *path) {
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

// Given a FILE pointer, and that the input stream is right before the content size,
// convert the size from little endien in the file and return it. This function also
// takes in a pointer to a hash if you want to update it. If you want to call the 
// funtion, but are not hashing each byte, put NULL as the second argument.
uint64_t get_content_size(FILE *input_stream, int *hash) {
    
    uint64_t unpacked_content_size = 0;

    for (int num_of_bytes = 0; num_of_bytes < CONTENT_LENGTH; num_of_bytes++) {
        uint64_t size_byte = fgetc(input_stream);

        if (hash != NULL) {
            *hash = egglet_hash(*hash, size_byte);
        }
        unpacked_content_size += size_byte << (num_of_bytes * BITS_IN_BYTE);
    }
    return unpacked_content_size;
}

// Returns the packed size given a format and unpacked size. Helps reduce complexity 
// else where in program.
u_int64_t get_packed_size(uint64_t unpacked_size, int format) {
    int format_number = format - '0';
    return ceil(format_number/8.0 * unpacked_size);
}

//--FIN--//