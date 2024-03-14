//
//  libqmc.c
//  QuickMerge Helper
//
//  Created by Snoolie Keffaber on 2024/03/13.
//

#include "libqmc.h"

size_t last_loaded_file_key_size;

size_t get_file_size(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        NSLog(@"QuickMerge Helper: Failed to open file");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fclose(fp);
    return size;
}
char *load_file_into_memory(const char *path, size_t size) {
    /* load shortcut into memory */
    FILE *fp = fopen(path, "r");
    if (!fp) {
        NSLog(@"QuickMerge Helper: Failed to open file");
        return 0;
    }
    char *archive = malloc(size * sizeof(char));
    /* copy bytes to binary */
    int c;
    size_t n = 0;
    while ((c = fgetc(fp)) != EOF) {
     archive[n++] = (char) c;
    }
    fclose(fp);
    return archive;
}
/* WARNING: Do not rely on this as reliable encryption to keep you safe, easily defeatable. */
char *load_file_into_memory_with_bitflip_keys(const char *path, size_t size, unsigned long long bitflip, unsigned long sizekey) {
    /* bitflip and sizekey are different as knowing the private key size and 04 bitflip is easily guessable */
    /* load shortcut into memory */
    FILE *fp = fopen(path, "r");
    if (!fp) {
        NSLog(@"QuickMerge Helper: Failed to open file");
        return 0;
    }
    char *archive = malloc(size * sizeof(char));
    /* skip first 4 bytes */
    for (int i = 0; i < 4; i++) {
        fgetc(fp);
    }
    unsigned int bitshift = 24;
    /* qmd h*/
    for (int i = 4; i < 8; i++) {
        archive[i] = (((char)fgetc(fp)) ^ ((bitflip >> bitshift) & 0xFF));
        bitshift -= 8;
    }
    /* first byte of ECDSA key will not be flipped */
    archive[8] = (char)fgetc(fp);
    /* copy bytes to binary */
    bitshift = 56;
    int c;
    size_t n = 9;
    char lastDecryptedChar = 0;
    while ((c = fgetc(fp)) != EOF) {
        lastDecryptedChar = (((char) c) ^ (((bitflip >> bitshift) & 0xFF) ^ lastDecryptedChar));
        archive[n++] = lastDecryptedChar;
        bitshift -= 8;
        if (bitshift > 64) {
            bitshift = 56;
        }
    }
    fclose(fp);
    /* PATCHWORK FIX: We accidentally flip the magic so fix it */
    archive[0] = 'Q';
    archive[1] = 'M';
    archive[2] = 'D';
    archive[3] = '\0';
    return archive;
}
/* Gives signing private key data for raw .qmd (QuickMerge Raw Data) */
uint8_t *signing_private_key_for_raw_qmd(const char *path) {
    size_t fileSize = get_file_size(path);
    if (!fileSize) { return 0; };
    char *archive = load_file_into_memory(path, fileSize);
    if (!archive) { return 0; };
    /* The len of the private signing key is the lower 32 bits of the first quadword */
    /* Highest 32 bits of quadword are "QMD\0" */
    register const char *sptr = archive + 0x7;
    size_t buf_size = *sptr << 24;
    buf_size += *(sptr - 1) << 16;
    buf_size += *(sptr - 2) << 8;
    buf_size += *(sptr - 3);
    last_loaded_file_key_size = buf_size;
    if (buf_size > fileSize-8) {
        fprintf(stderr,"QuickMerge Helper: buf_size reaches past fileSize\n");
        return 0;
    }
    /* we got buf_size, now fill buffer */
    uint8_t *buffer = (uint8_t *)malloc(buf_size);
    /*
     * the reason why we are doing a reverse
     * iteration is because doing it this way
     * will allow arm devices to take advantage
     * of the cbnz instruction, which should
     * mean about a 2 cycle save per iteration.
     *
     * also we're going to blindly trust that buf_size
     * is not larger than the buffer, because unless
     * you malform a aea file it should never be.
    */
    unsigned long i = buf_size;
    fill_buffer:
    i--;
    buffer[i] = archive[i+0x8];
    if (i != 0) {goto fill_buffer;};
    free(archive);
    return buffer;
}
/* Gives signing private key data for raw .qmd (QuickMerge Raw Data) */
uint8_t *signing_private_key_for_raw_qmd_bitflip(const char *path, unsigned long long bitflip, unsigned long sizekey) {
    size_t fileSize = get_file_size(path);
    if (!fileSize) { return 0; };
    char *archive = load_file_into_memory_with_bitflip_keys(path, fileSize, bitflip, sizekey);
    if (!archive) { return 0; };
    /* The len of the private signing key is the lower 32 bits of the first quadword */
    /* Highest 32 bits of quadword are "QMD\0" */
    register const char *sptr = archive + 0x7;
    size_t buf_size = *sptr << 24;
    buf_size += *(sptr - 1) << 16;
    buf_size += *(sptr - 2) << 8;
    buf_size += *(sptr - 3);
    last_loaded_file_key_size = buf_size;
    if (buf_size > fileSize-8) {
        fprintf(stderr,"QuickMerge Helper: buf_size reaches past fileSize\n");
        return 0;
    }
    /* we got buf_size, now fill buffer */
    uint8_t *buffer = (uint8_t *)malloc(buf_size);
    /*
     * the reason why we are doing a reverse
     * iteration is because doing it this way
     * will allow arm devices to take advantage
     * of the cbnz instruction, which should
     * mean about a 2 cycle save per iteration.
     *
     * also we're going to blindly trust that buf_size
     * is not larger than the buffer, because unless
     * you malform a aea file it should never be.
    */
    unsigned long i = buf_size;
    fill_buffer:
    i--;
    buffer[i] = archive[i+0x8];
    if (i != 0) {goto fill_buffer;};
    free(archive);
    return buffer;
}
/* Gives signing private key data for raw .qmd (QuickMerge Raw Data) */
uint8_t *signing_auth_data_for_raw_qmd(const char *path) {
    size_t fileSize = get_file_size(path);
    if (!fileSize) { return 0; };
    char *archive = load_file_into_memory(path, fileSize);
    if (!archive) { return 0; };
    /* The len of the private signing key is the lower 32 bits of the first quadword */
    /* Highest 32 bits of quadword are "QMC\0" */
    register const char *sptr = archive + 0x7;
    size_t buf_size = *sptr << 24;
    buf_size += *(sptr - 1) << 16;
    buf_size += *(sptr - 2) << 8;
    buf_size += *(sptr - 3);
    if (buf_size > fileSize-8) {
        fprintf(stderr,"QuickMerge Helper: buf_size reaches past fileSize\n");
        return 0;
    }
    /* Get starting position of auth data */
    unsigned long long offset = 0x8+buf_size;
    size_t auth_size = fileSize-offset;
    last_loaded_file_key_size = auth_size;
    /* we got buf_size, now fill buffer */
    uint8_t *buffer = (uint8_t *)malloc(auth_size);
    /*
     * the reason why we are doing a reverse
     * iteration is because doing it this way
     * will allow arm devices to take advantage
     * of the cbnz instruction, which should
     * mean about a 2 cycle save per iteration.
     *
     * also we're going to blindly trust that buf_size
     * is not larger than the buffer, because unless
     * you malform a aea file it should never be.
    */
    unsigned long i = auth_size;
    fill_auth_data:
    i--;
    buffer[i] = archive[i+offset];
    if (i != 0) {goto fill_auth_data;};
    free(archive);
    return buffer;
}
/* Gives signing private key data for .qmc (QuickMerge Context) */
NSData *signing_private_key_for_qmc_path(NSString *qmcPath) {
    NSString *qmcInfoPath = [qmcPath stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *qmcInfoPlist = [NSDictionary dictionaryWithContentsOfFile:qmcInfoPath];
    if (qmcInfoPlist) {
        id typeObj = qmcInfoPlist[@"type"];
        QmcType type = (QmcType)[typeObj longLongValue];
        const char *qmd = [[qmcPath stringByAppendingPathComponent:@"data.qmd"]fileSystemRepresentation];
        if (type == QMC_RAW) {
            uint8_t *privateKey = signing_private_key_for_raw_qmd(qmd);
            if (privateKey) {
                return [NSData dataWithBytesNoCopy:privateKey length:last_loaded_file_key_size];
            }
        } else if (type == QMC_OPTIMIZED) {
            
        } else if (type == QMC_RAW_FLIP) {
            id bkeyObj = qmcInfoPlist[@"bk"];
            unsigned long long bkey = [bkeyObj unsignedLongLongValue];
            id skeyObj = qmcInfoPlist[@"sk"];
            unsigned long skey = [skeyObj unsignedLongValue];
            uint8_t *privateKey = signing_private_key_for_raw_qmd_bitflip(qmd, bkey, skey);
            if (privateKey) {
                return [NSData dataWithBytesNoCopy:privateKey length:last_loaded_file_key_size];
            }
        } else {
            /* Unrecognized QMC type. */
            return 0;
        }
    }
    return 0;
}
/* Gives signing auth data for .qmc (QuickMerge Context) */
NSData *signing_auth_data_for_qmc_path(NSString *qmcPath) {
    NSString *qmcInfoPath = [qmcPath stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *qmcInfoPlist = [NSDictionary dictionaryWithContentsOfFile:qmcInfoPath];
    if (qmcInfoPlist) {
        id typeObj = qmcInfoPlist[@"type"];
        QmcType type = (QmcType)[typeObj longLongValue];
        const char *qmd = [[qmcPath stringByAppendingPathComponent:@"data.qmd"]fileSystemRepresentation];
        if (type == QMC_RAW) {
            uint8_t *buffer = signing_auth_data_for_raw_qmd(qmd);
            if (buffer) {
                return [NSData dataWithBytesNoCopy:buffer length:last_loaded_file_key_size];
            }
        } else if (type == QMC_OPTIMIZED) {
            
        } else if (type == QMC_RAW_FLIP) {
            /* In future add support using skey later */
            uint8_t *buffer = signing_auth_data_for_raw_qmd(qmd);
            if (buffer) {
                return [NSData dataWithBytesNoCopy:buffer length:last_loaded_file_key_size];
            }
        } else {
            /* Unrecognized QMC type. */
            return 0;
        }
    }
    return 0;
}
uint8_t *raw_qmd_for_private_key_and_auth_data(NSData *privateKey, NSData *authData) {
    unsigned long privKeyLen = [privateKey length];
    unsigned long authDataLen = [authData length];
    size_t qmdSize = privKeyLen + authDataLen + 8;
    uint8_t *qmd = malloc(qmdSize * 8);
    char privKeyChar[4];
    privKeyChar[0] = (privKeyLen & 0xFF);
    privKeyChar[1] = ((privKeyLen >> 8) & 0xFF);
    privKeyChar[2] = ((privKeyLen >> 16) & 0xFF);
    privKeyChar[3] = (privKeyLen >> 24);
    memcpy((char *)qmd, "QMD\0", 4);
    memcpy((char *)qmd + 4, privKeyChar, 4);
    memcpy((char *)qmd + 8, [privateKey bytes], privKeyLen);
    memcpy((char *)qmd + 8 + privKeyLen, [authData bytes], authDataLen);
    return qmd;
}
void create_qmc_at_path_for_raw_qmd(NSString *path, uint8_t *qmd, size_t qmd_size) {
    [[NSFileManager defaultManager]createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *qmcInfoPath = [path stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *qmcInfo = @{
        @"name" : @"data.qmd",
        @"type" : [NSNumber numberWithInt:QMC_RAW],
    };
    [qmcInfo writeToFile:qmcInfoPath atomically:YES];
    NSString *qmcDataPath = [path stringByAppendingPathComponent:@"data.qmd"];
    NSData *qmdData = [NSData dataWithBytesNoCopy:qmd length:qmd_size];
    [qmdData writeToFile:qmcDataPath atomically:YES];
}
