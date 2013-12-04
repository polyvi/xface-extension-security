
/*
 Copyright 2012-2013, Polyvi Inc. (http://polyvi.github.io/openxface)
 This program is distributed under the terms of the GNU General Public License.

 This file is part of xFace.

 xFace is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 xFace is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with xFace.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <CommonCrypto/CommonCryptor.h>
#import "XSecurityExt.h"
#import <Cordova/NSData+Base64.h>
#import <Cordova/CDVPluginResult.h>
#import <XFace/XApplication.h>
#import <XFace/XUtils.h>
#import <XFace/XCipher.h>
#import <Cordova/NSArray+Comparisons.h>
#import <XFace/NSData+Encoding.h>
#import <XFace/md5.h>

@interface CDVPluginResult (XPluginResult)

+ (CDVPluginResult*) ok:(NSString*)theMessage;
+ (CDVPluginResult*) error:(int)code;

@end

@implementation CDVPluginResult (XPluginResult)

+ (CDVPluginResult*) ok:(NSString*)theMessage
{
    return [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:theMessage];
}

+ (CDVPluginResult*) error:(int)code
{
    return [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsInt:code];
}

@end

#define SECURITY_KEY_MIN_LENGTH    8

#define kKeyForDES                 @1
#define kKeyFor3DES                @2

#define kKeyForALG                 @"CryptAlgorithm"
#define kKeyForEncodeDataType      @"EncodeDataType"
#define kKeyForEncodeKeyType       @"EncodeKeyType"

enum SecurityError {
    FILE_NOT_FOUND_ERR = 1,
    PATH_ERR = 2,
    OPERATION_ERR = 3
};
typedef NSUInteger SecurityError;

@interface NSDictionary (XCiphers)

/**
    获取指定的算法的加解密器
    @param key 加解密算法的键值
    @returns 返回键值对应的加解密算法的加解密器，或者默认des算法的加解密器如果键值对应的加解密算法不存在
 */
- (XCipher*) cipherForKey:(id)key;

@end

@interface XSecurityExt ()

/**
    检查加解密参数的有效性.
    @returns 有效返回YES,否则返回NO
 */
- (BOOL) checkArguments:(NSArray*)arguments;

/**
    根据arguments 和 action 加密或解密文件
    @param arguments
     - 0 XJsCallback* callback
     - 1 sKey 密钥
     - 2 sourceFile 源文件
     - 3 targetFile 目标文件所存的位置
    @param op 加密或解密
 */
- (CDVPluginResult*) doFileCrypt:(NSArray*)arguments useOperation:(SecurityAction)op;

@end

const NSDictionary* defaultJsOptions;

@implementation NSDictionary (XCiphers)

- (XCipher*) cipherForKey:(id)key
{
    XCipher* cipher = [self objectForKey:key];
    return cipher == nil ? [self objectForKey:kKeyForDES] : cipher;
}

@end

@implementation XSecurityExt

- (id)initWithWebView:(UIWebView*)theWebView
{
    self = [super initWithWebView:theWebView];
    defaultJsOptions = @{kKeyForALG : kKeyForDES,
                         kKeyForEncodeDataType : @(XDataBase64Encoding),
                         kKeyForEncodeKeyType : @(XDataUTF8Encoding)};

    if (self)
    {
        XCipher* cipher1 = [[XCipher alloc] initWithAlgorithm:kCCAlgorithmDES]; //使用DES对称加密算法
        XCipher* cipher2 = [[XCipher alloc] initWithAlgorithm:kCCAlgorithm3DES]; //使用3DES对称加密算法

        ciphers = @{kKeyForDES:cipher1, kKeyFor3DES:cipher2};
    }
    return self;
}

- (void) encrypt:(CDVInvokedUrlCommand*)command
{
    NSString* keyString = [command.arguments objectAtIndex:0];
    NSString* sourceDataStr = [command.arguments objectAtIndex:1];
    NSDictionary* jsOptions = command.arguments.count >= 3 ? [command.arguments objectAtIndex:2 withDefault:defaultJsOptions]  : defaultJsOptions;

    NSNumber* alg = [jsOptions objectForKey:kKeyForALG];
    NSNumber* dataEncoding = [jsOptions objectForKey:kKeyForEncodeDataType];
    NSNumber* keyEncoding = [jsOptions objectForKey:kKeyForEncodeKeyType];

    XCipher* cipher = [ciphers cipherForKey:alg];

    CDVPluginResult* result    = nil;
    NSData* sourceData          = nil;//原数据
    NSData* resultData          = nil;//加密后的数据

    NSAssert((([keyString length] >= SECURITY_KEY_MIN_LENGTH) && [sourceDataStr length]), @"Input data invalid!");

    sourceData = [sourceDataStr dataUsingEncoding:NSUTF8StringEncoding];

    NSData* keyData = [NSData dataWithString:keyString usingEncoding:[keyEncoding unsignedIntValue]];

    [cipher setKey:keyData];
    resultData = [cipher encryptData:sourceData];

    if(resultData != nil)
    {
        result = [CDVPluginResult ok:[resultData stringUsingEncoding:[dataEncoding unsignedIntValue]]];
    }
    else
    {
        XLogE(@"Encrypt failed！");
        result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString: @"Encrypt failed！"];
    }

    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (void) decrypt:(CDVInvokedUrlCommand*)command
{
    NSString* keyString = [command.arguments objectAtIndex:0];
    NSString* sourceDataStr = [command.arguments objectAtIndex:1];
    NSDictionary* jsOptions = [command.arguments objectAtIndex:2 withDefault:defaultJsOptions];

    NSNumber* alg = [jsOptions objectForKey:kKeyForALG];
    NSNumber* dataEncoding = [jsOptions objectForKey:kKeyForEncodeDataType];
    NSNumber* keyEncoding = [jsOptions objectForKey:kKeyForEncodeKeyType];

    XCipher* cipher = [ciphers cipherForKey:alg];

    CDVPluginResult* result    = nil;
    NSData* sourceData          = nil;//原数据
    NSData* resultData          = nil;//解密后的数据

    NSAssert((([keyString length] >= SECURITY_KEY_MIN_LENGTH) && [sourceDataStr length]), @"Input data invalid!");

    sourceData = [NSData dataWithString:sourceDataStr usingEncoding:[dataEncoding unsignedIntValue]];

    NSData* keyData = [NSData dataWithString:keyString usingEncoding:[keyEncoding unsignedIntValue]];
    [cipher setKey:keyData];
    resultData = [cipher decryptData:sourceData];

    if(resultData != nil)//return string
    {
        NSString* resultstr = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
        result = [CDVPluginResult resultWithStatus: CDVCommandStatus_OK messageAsString: resultstr];
    }
    else
    {
        XLogE(@"Dencrypt failed！");
        result = [CDVPluginResult resultWithStatus: CDVCommandStatus_ERROR messageAsString: @"Dencrypt failed！"];
    }
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (void) encryptFile:(CDVInvokedUrlCommand*)command
{
    CDVPluginResult* result = [self doFileCrypt:command.arguments useOperation:kCCEncrypt];
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (void) decryptFile:(CDVInvokedUrlCommand*)command
{
     CDVPluginResult* result = [self doFileCrypt:command.arguments useOperation:kCCDecrypt];
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (CDVPluginResult*) doFileCrypt:(NSArray*)arguments useOperation:(CCOperation)op
{
    NSString* keyString = [arguments objectAtIndex:0];
    NSString* sourceFilePath = [arguments objectAtIndex:1];
    NSString* targetFilePath = [arguments objectAtIndex:2];
    NSDictionary* jsOptions =  arguments.count >= 4 ? [arguments objectAtIndex:3] : defaultJsOptions;

    NSNumber* alg = [jsOptions objectForKey:kKeyForALG];

    XCipher* cipher = [ciphers cipherForKey:alg];

    id<XApplication> app = [self ownerApp];
    if( ![self checkArguments:arguments] )
    {
        return [CDVPluginResult error:PATH_ERR];
    }
    sourceFilePath = [XUtils resolvePath:sourceFilePath usingWorkspace:[app getWorkspace]];
    targetFilePath = [XUtils resolvePath:targetFilePath usingWorkspace:[app getWorkspace]];
    NSFileManager* fileMgr = [NSFileManager defaultManager];
    if(![fileMgr fileExistsAtPath:sourceFilePath])
    {
        return [CDVPluginResult error:FILE_NOT_FOUND_ERR];
    }

    NSData* sourceData          = nil;//原数据
    NSData* resultData          = nil;//解密后的数据
    sourceData = [[NSData alloc] initWithContentsOfFile:sourceFilePath];

    [cipher setKey:[keyString dataUsingEncoding:NSUTF8StringEncoding]];

    resultData = [cipher cryptData:sourceData withOperation:op];
    if(resultData != nil)
    {
        if([fileMgr createFileAtPath:targetFilePath contents:resultData attributes:nil])
        {
            CDVPluginResult* result = [CDVPluginResult resultWithStatus: CDVCommandStatus_OK messageAsString:targetFilePath];
              return result;
        }
    } else
    {
        return [CDVPluginResult error:OPERATION_ERR];
    }
    return nil;
}

- (void) digest:(CDVInvokedUrlCommand*)command
{
    NSString* data = [command.arguments objectAtIndex:0];
    NSString* md5 = [data md5];
    CDVPluginResult* result = [CDVPluginResult ok:md5];
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (BOOL) checkArguments:(NSArray *)arguments
{
    NSString* keyString = [arguments objectAtIndex:0];
    NSAssert(([keyString length] >= SECURITY_KEY_MIN_LENGTH), @"Input key invalid!");

    NSString* sourceFilePath = [arguments objectAtIndex:1];
    NSString* targetFilePath = [arguments objectAtIndex:2];
    id<XApplication> app = [self ownerApp];
    //不能是空串
    if(0 == [sourceFilePath length] || 0 == [targetFilePath length])
    {
        return NO;
    }
    //都是相对workspace的相对路径，不能是 形如C:/a/bc 这种
    if( (NSNotFound !=[sourceFilePath rangeOfString:@":"].location) || (NSNotFound !=[targetFilePath rangeOfString:@":"].location) )
    {
        return NO;
    }
    sourceFilePath = [XUtils resolvePath:sourceFilePath usingWorkspace:[app getWorkspace]];
    targetFilePath = [XUtils resolvePath:targetFilePath usingWorkspace:[app getWorkspace]];
    if (!sourceFilePath || !targetFilePath)
    {
        //不在workspace下
        return NO;
    }
    return YES;
}

@end

