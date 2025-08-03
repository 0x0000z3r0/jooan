// Install Libs:   libssl-dev openssl
// Compile:        gcc -Wall -Wextra -fsanitize=leak,address,undefined -lssl -lcrypto ./jooan-package.c -o jooan-package
// Usage:          ./jooan-package <firmware-input-file> <upgrade-script-file> <package-output-file>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <openssl/evp.h>

static void
dump(void *buffer, size_t size)
{
	uint8_t *pointer = buffer;
	for (size_t i = 0; i < size; ++i) {
		printf("%02x ", pointer[i]);

		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n");
}

static int
md5(void *buffer, size_t size, uint8_t output[static EVP_MAX_MD_SIZE])
{
	uint32_t md_len;
	EVP_MD_CTX* mdctx = NULL;

	int status = 1;
	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL) {
		printf("ERR: failed to create EVP_MD_CTX\n");
		goto _EXIT;
	}
	
	if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
		printf("ERR: failed to initialize the digest array\n");
		goto _FREE;
	}

	if (EVP_DigestUpdate(mdctx, buffer, size) != 1) {
		printf("ERR: failed to update the digest\n");
		goto _FREE;
	}
	
	if (EVP_DigestFinal_ex(mdctx, output, &md_len) != 1) {
		printf("ERR: failed to finalize the digest\n");
		goto _FREE;
	}
	
	status = 0;
_FREE:
	EVP_MD_CTX_free(mdctx);
_EXIT:
	return status;
}

static int
enc(void *buffer, size_t size)
{
	const size_t tail_size = 96;
	if (buffer == NULL || size < tail_size) {
	    return 1;
	}

	uint8_t *tail = (uint8_t*)buffer + size - tail_size;
	uint8_t temp[128];
	memset(temp, 0, sizeof(temp));

	for (size_t i = 0; i < tail_size - 1; ++i) {
		temp[i] = (tail[i] << 2) & 0xFC;
		temp[i] |= tail[i + 1] >> 6;
	}
	temp[tail_size - 1] = (tail[tail_size - 1] << 2) & 0xFC;
	temp[tail_size - 1] |= tail[0] >> 6;

	const size_t stride = ((temp[tail_size - 1] >> 2) & 0xF) + 1;
	for (size_t i = 93 / stride * stride; i >= stride; i -= stride) {
		const uint8_t swap = temp[i];
		temp[i] = temp[i + 1];
		temp[i + 1] = swap;
	}

	memcpy(tail, temp, tail_size);
	return 0;
}

static int
dec(void *buffer, size_t size)
{
	const size_t tail_size = 96;
	if (buffer == NULL || size < tail_size) {
		return 1;
	}

	uint8_t *tail = (uint8_t*)buffer + size - tail_size;
	uint8_t temp[128];
	memset(temp, 0, sizeof (temp));
	memcpy(temp, tail, tail_size);

	const size_t stride = ((temp[tail_size - 1] >> 2) & 0xF) + 1;
	for (size_t i = 93 / stride * stride; i >= stride; i -= stride) {
		const uint8_t swap = temp[i];
		temp[i] = temp[i + 1];
		temp[i + 1] = swap;
	}

	tail[0] = (temp[0] >> 2) | (temp[tail_size - 1] << 6);
	for (size_t i = 1; i < tail_size; ++i) {
		tail[i] = (temp[i] >> 2) | (temp[i - 1] << 6);
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	printf("INF: started the jooan package generator\n");
	if (argc < 2) {
		printf("ERR: input file path is missing\n");
		goto _EXIT;
	}
	
	char *input_path = argv[1];
	printf("INF: input file path '%s'\n", input_path);

	if (argc < 3) {
		printf("ERR: input script file path is missing\n");
		goto _EXIT;
	}

	char *script_path = argv[2];
	printf("INF: script file path '%s'\n", script_path);

	char *output_path = "jooan.fw";
	if (argc >= 4) {
		output_path = argv[3];
	}
	printf("INF: output file path '%s'\n", output_path);

	int input_file = open(input_path, O_RDONLY);
	if (input_file == -1) {
		printf("ERR: failed to open the input file, code: %i, message: %s\n", errno, strerror(errno));
		goto _EXIT;
	}
	printf("INF: input file descriptor %i\n", input_file);

	struct stat input_stat;
	if (fstat(input_file, &input_stat) == -1) {
		printf("ERR: failed to get the input file stats, code: %i, message: %s\n", errno, strerror(errno));
		goto _CLOSE_INPUT;
	}
	printf("INF: input file size %zu\n", input_stat.st_size);

	uint8_t *input_addr = NULL;
	if (input_stat.st_size > 0) { 
		input_addr = mmap(NULL, input_stat.st_size, PROT_READ, MAP_SHARED, input_file, 0);
		if (input_addr == MAP_FAILED) {
			printf("ERR: failed to map the input file, code: %i, message: %s\n", errno, strerror(errno));
			goto _CLOSE_INPUT;
		}
		printf("INF: input file addr %p, data = { 0x%02x, 0x%02x, ... 0x%02x }\n",
			input_addr, input_addr[0], input_addr[1], input_addr[input_stat.st_size - 1]);
	} else {
		printf("WRN: input file is empty skipping it\n");
	}

_CLOSE_INPUT:
	printf("INF: closing the input file\n");
	close(input_file);

	int script_file = open(script_path, O_RDONLY);
	if (script_file == -1) {
		printf("ERR: failed to open the script file, code: %i, message: %s\n", errno, strerror(errno));
		goto _EXIT;
	}
	printf("INF: script file descriptor %i\n", script_file);

	struct stat script_stat;
	if (fstat(script_file, &script_stat) == -1) {
		printf("ERR: failed to get the script file stats, code: %i, message: %s\n", errno, strerror(errno));
		goto _CLOSE_SCRIPT;
	}
	printf("INF: script file size %zu\n", script_stat.st_size);

	uint8_t *script_addr;
	script_addr = mmap(NULL, script_stat.st_size, PROT_READ, MAP_SHARED, script_file, 0);
	if (script_addr == MAP_FAILED) {
		printf("ERR: failed to map the script file, code: %i, message: %s\n", errno, strerror(errno));
		goto _CLOSE_SCRIPT;
	}
	printf("INF: script file addr %p, data = { 0x%02x, 0x%02x, ... 0x%02x }\n",
			script_addr, script_addr[0], script_addr[1], script_addr[script_stat.st_size - 1]);
_CLOSE_SCRIPT:
	printf("INF: closing the script file\n");
	close(script_file);

	int output_file = open(output_path, O_RDWR | O_CREAT, 0644);
	if (output_file == -1) {
		printf("ERR: failed to open the output file, code: %i, message: %s\n", errno, strerror(errno));
		goto _EXIT;
	}
	printf("INF: output file deoutputor %i\n", output_file);

	// 1. write the initial header
	struct jooan_header {
		char type[8];
		char size[8];
		char info[48];
		char csum[32];
	} __attribute__((packed)) header;
	printf("INF: created the initial jooan header, size: %zu\n", sizeof (header));

	memset(&header, 0, sizeof (header));
	strcpy(header.type, "jooan");
	strcpy(header.info, "ver=A1A;mod=A1A");

	off_t offset = 0;
	ssize_t written = pwrite(output_file, &header, sizeof (header), offset);
	if (written < 0 || written != sizeof (header)) {
		printf("ERR: failed to write into output file, code: %i, message: %s\n", errno, strerror(errno));
		goto _CLOSE_OUTPUT;
	}
	printf("INF: wrote the initial header into the output file, written: %zi, offset: 0x%lx\n", written, offset);

	// 2. write the input file
	offset = sizeof (header);
	if (input_stat.st_size > 0) {
		written = pwrite(output_file, input_addr, input_stat.st_size, offset);
		if (written < 0 || written != input_stat.st_size) {
			printf("ERR: failed to write into output file, code: %i, message: %s\n", errno, strerror(errno));
			goto _CLOSE_OUTPUT;
		}
		printf("INF: wrote input data into the output file, written: %zi, offset: 0x%lx\n", written, offset);
	} else {
		printf("WRN: skipped writing the input file since its empty, offset: 0x%lx\n", offset);
	}

	// 3. write the script file
	offset = sizeof (header) + input_stat.st_size;
	written = pwrite(output_file, script_addr, script_stat.st_size, offset);
	if (written < 0 || written != script_stat.st_size) {
		printf("ERR: failed to write into output file, code: %i, message: %s\n", errno, strerror(errno));
		goto _CLOSE_OUTPUT;
	}
	printf("INF: wrote script data into the output file, written: %zi, offset: 0x%lx\n", written, offset);

	// 4. write the initial tail
	struct jooan_tail {
		char type[8];
		char size[8];
		uint8_t pad[48];
		char csum[32];
	} __attribute__((packed)) tail;
	printf("INF: created the initial jooan tail, size: %zu\n", sizeof (tail));

	memset(&tail, 0, sizeof (tail));
	strcpy(tail.type, "toolv");
	snprintf(tail.size, sizeof (tail.size), "%li", script_stat.st_size);

    	uint8_t md5_digest[EVP_MAX_MD_SIZE];
	if (md5(script_addr, script_stat.st_size, md5_digest)) {
		printf("ERR: failed to generate the MD5 checksum\n");
		goto _CLOSE_OUTPUT;
	}
	printf("INF: calculated the MD5 checksum for the script file, size: %zu"
			", data: { 0x%02x, 0x%02x, 0x%02x, ... 0x%02x }\n",
			sizeof (md5_digest), md5_digest[0], md5_digest[1], md5_digest[2], md5_digest[15]);

	for (size_t i = 0; i < 16; ++i) {
		static const char hex[] = "0123456789abcdef";
		tail.csum[i * 2 + 0] = hex[md5_digest[i] >> 4];
		tail.csum[i * 2 + 1] = hex[md5_digest[i] & 0xF];
	}
	printf("INF: filled the tail checksum: %.*s\n", (int)sizeof (tail.csum), tail.csum);

	offset = sizeof (header) + input_stat.st_size + script_stat.st_size;
	written = pwrite(output_file, &tail, sizeof (tail), offset);
	if (written < 0 || written != sizeof (tail)) {
		printf("ERR: failed to write into output file, code: %i, message: %s\n", errno, strerror(errno));
		goto _CLOSE_OUTPUT;
	}
	printf("INF: wrote the initial tail into the output file, written: %zi, offset: 0x%lx\n", written, offset);

	// 5. write the final tail
	offset = sizeof (header) + input_stat.st_size + script_stat.st_size;
	uint8_t tail_unpacked[sizeof (tail)];
	ssize_t read = pread(output_file, tail_unpacked, sizeof (tail_unpacked), offset);
	if (read < 0 || read != sizeof (tail_unpacked)) {
		printf("ERR: failed to read from output file, code: %i, message: %s\n", errno, strerror(errno));
		goto _CLOSE_OUTPUT;
	}
	printf("INF: read the unpacked tail, bytes: %zi\n", read);
	dump(tail_unpacked, sizeof (tail_unpacked));

	uint8_t tail_packed[128];
	memcpy(tail_packed, tail_unpacked, sizeof (tail_unpacked));
	printf("INF: copied to the packed tail, bytes: %zi\n", sizeof (tail_unpacked));
	dump(tail_packed, sizeof (tail_unpacked));

	printf("INF: encrypting the packed tail\n");
	enc(tail_packed, sizeof (tail_unpacked));
	dump(tail_packed, sizeof (tail_unpacked));

	printf("INF: decrypting the packed tail\n");
	dec(tail_packed, sizeof (tail_unpacked));
	dump(tail_packed, sizeof (tail_unpacked));

	if (memcmp(tail_unpacked, tail_packed, sizeof (tail_unpacked)) != 0) {
		printf("ERR: encryption verification failed\n");
		goto _CLOSE_OUTPUT;
	}

	if (argc < 5) {
		printf("INF: encrypting the packed tail\n");
		enc(tail_packed, sizeof (tail_unpacked));
		dump(tail_packed, sizeof (tail_unpacked));
	} else {
		printf("WRN: skipped the last encryption phase\n");
	}

	offset = sizeof (header) + input_stat.st_size + script_stat.st_size;
	written = pwrite(output_file, &tail_packed, sizeof (tail), offset);
	if (written < 0 || written != sizeof (tail)) {
		printf("ERR: failed to write into output file, code: %i, message: %s\n", errno, strerror(errno));
		goto _CLOSE_OUTPUT;
	}
	printf("INF: wrote the final tail into the output file, written: %zi, offset: 0x%lx\n", written, offset);

	// 6. write the final header
	const ssize_t merged_size = input_stat.st_size + script_stat.st_size + sizeof (tail);
	void *merged_buffer = malloc(merged_size);
	if (merged_buffer == NULL) {
		printf("ERR: failed to allocated buffer for the merged content\n");
		goto _CLOSE_OUTPUT;
	}
	printf("INF: allocated %zu for the merged buffer\n", merged_size);

	read = pread(output_file, merged_buffer, merged_size, sizeof (header));
	if (read < 0 || read != merged_size) {
		printf("ERR: failed to read from output file, code: %i, message: %s\n", errno, strerror(errno));
		goto _FREE_MERGED;
	}
	printf("INF: read the merged content, bytes: %zi\n", read);

	if (md5(merged_buffer, merged_size, md5_digest)) {
		printf("ERR: failed to generate the MD5 checksum\n");
		goto _FREE_MERGED;
	}

_FREE_MERGED:
	printf("INF: freeing the merged buffer\n");
	free(merged_buffer);

	printf("INF: calculated the MD5 checksum for the merged content, size: %zu"
			", data: { 0x%02x, 0x%02x, 0x%02x, ... 0x%02x }\n",
			sizeof (md5_digest), md5_digest[0], md5_digest[1], md5_digest[2], md5_digest[15]);

	for (size_t i = 0; i < 16; ++i) {
		static const char hex[] = "0123456789abcdef";
		header.csum[i * 2 + 0] = hex[md5_digest[i] >> 4];
		header.csum[i * 2 + 1] = hex[md5_digest[i] & 0xF];
	}
	printf("INF: filled the header checksum: %.*s\n", (int)sizeof (tail.csum), tail.csum);

	snprintf(header.size, sizeof (header.size), "%li", merged_size);

	offset = 0;
	written = pwrite(output_file, &header, sizeof (header), offset);
	if (written < 0 || written != sizeof (header)) {
		printf("ERR: failed to write into output file, code: %i, message: %s\n", errno, strerror(errno));
		goto _CLOSE_OUTPUT;
	}
	printf("INF: wrote the final header into the output file, written: %zi, offset: 0x%lx\n", written, offset);

_CLOSE_OUTPUT:
	printf("INF: closing the output file\n");
	close(output_file);
_EXIT:
	printf("INF: exiting...\n");
	return 0;
}
