//
//  HomeViewController.m
//  QuickMerge Helper
//
//  Created by Snoolie Keffaber on 2024/03/13.
//

#import "HomeViewController.h"
#import "libshortcutsign/libshortcutsign.h"
#import "libqmc/libqmc.h"
#import <CoreServices/CoreServices.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

extern size_t last_loaded_file_key_size;

BOOL hasPickedQMD;
SecKeyRef key;
NSData *keyData;
NSData *authData;

NSString *createDirectoryStructureForUnsignedShortcut(NSData *shortcutData) {
    NSString *documentDir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *tmpDir = [documentDir stringByAppendingPathComponent:@"tmpUnsignedShortcut"];
    NSFileManager *defaultManager = [NSFileManager defaultManager];
    [defaultManager removeItemAtPath:tmpDir error:nil]; /* Remove dir if it exists */
    if ([defaultManager createDirectoryAtPath:tmpDir withIntermediateDirectories:NO attributes:nil error:nil]) {
        NSString *shortcutPath = [tmpDir stringByAppendingPathComponent:@"Shortcut.wflow"];
        [shortcutData writeToFile:shortcutPath atomically:YES];
    }
    return tmpDir;
}

@interface HomeViewController ()

@end

@implementation HomeViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    hasPickedQMD = NO;
    UIView *view = self.view;
    CGRect frame = view.frame;
    CGFloat buttonFrameX = frame.size.width / 4;
    CGFloat buttonFrameW = frame.size.width / 2;
    CGFloat buttonFrameH = 60.0;
    CGFloat buttonFrameY = (frame.size.height / 2) - (buttonFrameH / 2);
    CGRect buttonFrame = CGRectMake(buttonFrameX, buttonFrameY, buttonFrameW, buttonFrameH);
    UIButton *chooseFile = [[UIButton alloc]initWithFrame:buttonFrame];
    [chooseFile setBackgroundColor:[UIColor systemPinkColor]];
    [chooseFile.layer setCornerRadius:10.0];
    [chooseFile setTitle:@"Choose File" forState:UIControlStateNormal];
    [chooseFile setTitle:@"Choose File" forState:UIControlStateHighlighted];
    UITapGestureRecognizer *buttonTap = [[UITapGestureRecognizer alloc]initWithTarget:self action:@selector(pressChooseFileButton)];
    [chooseFile addGestureRecognizer:buttonTap];
    [view addSubview:chooseFile];
}

- (void)pressChooseFileButton {
    hasPickedQMD = NO;
    authData = nil;
    key = nil;
    keyData = nil;
    UIAlertController *controlMenu = [UIAlertController alertControllerWithTitle:@"QuickMerge Helper" message:@"Please select the QMD file to use to sign the shortcut." preferredStyle:UIAlertControllerStyleAlert];
    [controlMenu addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        /* Show File Picker */
        UTType *qmdType = [UTType typeWithFilenameExtension:@"qmd"];
        UIDocumentPickerViewController *qmcPickerController = [[UIDocumentPickerViewController alloc]initForOpeningContentTypes:@[qmdType]];
        qmcPickerController.delegate = self;
        qmcPickerController.modalPresentationStyle = UIModalPresentationOverFullScreen;
        [self presentViewController:qmcPickerController animated:YES completion:nil];
    }]];
    [self presentViewController:controlMenu animated:YES completion:nil];
}

-(void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls && [urls count]) {
        if (hasPickedQMD) {
            hasPickedQMD = NO;
            /* Unsigned Shortcut Handler */
            NSURL *wflowFileURL = urls[0];
            NSData *shortcutData = [NSData dataWithContentsOfURL:wflowFileURL];
            if (shortcutData) {
                NSString *tmpDir = createDirectoryStructureForUnsignedShortcut(shortcutData);
                NSString *destPath = [tmpDir stringByAppendingPathComponent:@"signed.shortcut"];
                int didFail = sign_shortcut_with_private_key_and_auth_data(key, authData, [tmpDir fileSystemRepresentation], [destPath fileSystemRepresentation]);
                if (didFail) {
                    /* libshortcutsign failed to sign the shortcut */
                    authData = nil;
                    CFBridgingRelease(key);
                    key = nil;
                    keyData = nil;
                    UIAlertController *controlMenu = [UIAlertController alertControllerWithTitle:@"QuickMerge Helper" message:@"libshortcutsign failed to sign shortcut." preferredStyle:UIAlertControllerStyleAlert];
                    [controlMenu addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                    [self presentViewController:controlMenu animated:YES completion:nil];
                    return;
                }
                /* Show export picker */
                NSURL *destURL = [NSURL fileURLWithPath:destPath];
                UIDocumentPickerViewController *exportController = [[UIDocumentPickerViewController alloc]initForExportingURLs:@[destURL]];
                exportController.delegate = self;
                exportController.modalPresentationStyle = UIModalPresentationOverFullScreen;
                [self presentViewController:exportController animated:YES completion:nil];
            }
            return;
        }
        authData = nil;
        CFBridgingRelease(key);
        key = nil;
        keyData = nil;
        NSURL *qmdFileURL = urls[0];
        NSData *qmdData = [NSData dataWithContentsOfURL:qmdFileURL];
        if (qmdData) {
            /* Get private key */
            uint8_t *keyBuffer = signing_private_key_for_raw_qmd([qmdFileURL fileSystemRepresentation]);
            if (keyBuffer) {
                keyData = [NSData dataWithBytesNoCopy:keyBuffer length:last_loaded_file_key_size];
                if (keyData) {
                    uint8_t *authDataBuffer = signing_auth_data_for_raw_qmd([qmdFileURL fileSystemRepresentation]);
                    if (authDataBuffer) {
                        authData = [NSData dataWithBytesNoCopy:authDataBuffer length:last_loaded_file_key_size];
                        if (authData) {
                            key = SecKeyCreateWithData((__bridge CFDataRef)keyData, (__bridge CFDictionaryRef)@{
                                (__bridge id)kSecAttrKeyType : (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
                                (__bridge id)kSecAttrKeyClass : (__bridge id)kSecAttrKeyClassPrivate,
                                (__bridge id)kSecAttrKeySizeInBits : @256,
                              }, nil);
                            if (key) {
                                NSLog(@"keyData: %@",keyData);
                                NSLog(@"authData: %@",authData);
                                /* Open a new document picker */
                                UIAlertController *controlMenu = [UIAlertController alertControllerWithTitle:@"QuickMerge Helper" message:@"Please select the unsigned shortcut file to sign." preferredStyle:UIAlertControllerStyleAlert];
                                [controlMenu addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                                    /* Show File Picker */
                                    hasPickedQMD = YES;
                                    UTType *shortcutType = [UTType typeWithFilenameExtension:@"shortcut"];
                                    UTType *wflowType = [UTType typeWithFilenameExtension:@"wflow"];
                                    UIDocumentPickerViewController *shortcutPickerController = [[UIDocumentPickerViewController alloc]initForOpeningContentTypes:@[shortcutType, wflowType]];
                                    shortcutPickerController.delegate = self;
                                    shortcutPickerController.modalPresentationStyle = UIModalPresentationOverFullScreen;
                                    [self presentViewController:shortcutPickerController animated:YES completion:nil];
                                }]];
                                [self presentViewController:controlMenu animated:YES completion:nil];
                            }
                        } else {
                            free(authDataBuffer);
                        }
                    }
                } else {
                    free(keyBuffer);
                }
            }
        }
    }
}

@end
