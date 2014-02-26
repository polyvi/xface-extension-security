
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

package com.polyvi.xface.extension.security;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaResourceApi;
import org.apache.cordova.CordovaWebView;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.net.Uri;

import com.polyvi.xface.exception.XCryptionException;
import com.polyvi.xface.util.XBase64;
import com.polyvi.xface.util.XCryptor;
import com.polyvi.xface.util.XFileUtils;
import com.polyvi.xface.util.XLog;
import com.polyvi.xface.util.XPathResolver;
import com.polyvi.xface.util.XStringUtils;
import com.polyvi.xface.view.XAppWebView;

public class XSecurityExt extends CordovaPlugin {
    private static final String CLASS_NAME = XSecurityExt.class.getSimpleName();

    /** Security 提供给js用户的接口名字 */
    private static final String COMMAND_ENCRYPT = "encrypt";
    private static final String COMMAND_DECRYPT = "decrypt";
    private static final String COMMAND_ENCRYPT_FILE = "encryptFile";
    private static final String COMMAND_DECRYPT_FILE = "decryptFile";
    private static final String COMMAND_DIGEST = "digest";

    /** 加解密过程中的错误 */
    private static final int FILE_NOT_FOUND_ERR = 1;
    private static final int PATH_ERR = 2;
    private static final int OPERATION_ERR = 3;
    private static final int UNKNOWN_ERR = 4;

    /** 加解密报错 */
    private static final String KEY_EMPTY_ERROR = "Error:key null or empty";
    private static final String CRYPTION_ERROR = "Error:cryption error";

    /** 加密算法选择 */
    private static final int DES_ALOGRITHEM = 1; // DES方式加解密
    private static final int TRIPLE_DES_ALOGRITHEM = 2; // 3DES方式加解密
    private static final int RSA_ALOGRITHEM = 3; // RSA方式加解密
    /** 返回数据类型选择 */
    private static final int ENCODE_TYPE_STRING = 0; // 返回数据为String
    private static final int ENCODE_TYPE_BASE64 = 1; // 返回的数据以Base64编码格式
    private static final int ENCODE_TYPE_HEX = 2; // 返回的数据以16进制编码格式
    /** 加解密配置选项的属性名称 */
    private static final String KEY_CRYPT_ALGORITHM = "CryptAlgorithm";
    private static final String KEY_ENCODE_DATA_TYPE = "EncodeDataType";
    private static final String KEY_ENCODE_KEY_TYPE = "EncodeKeyType";

    /** 加解密工具类 */
    private XCryptor mCryptor;
    private CordovaResourceApi mResourceApi;

    private interface SecurityOp {
        void run() throws Exception;
    }

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        mCryptor = new XCryptor();
        mResourceApi = this.webView.getResourceApi();
        super.initialize(cordova, webView);
    }

    public boolean execute(String action, final JSONArray args,
            final CallbackContext callbackContext) throws JSONException {
        if (action.equals(COMMAND_ENCRYPT)) {
            threadhelper(new SecurityOp() {

                @Override
                public void run() throws Exception {
                    String encryptResult = encrypt(args.getString(0),
                            args.getString(1), args.optJSONObject(2));
                    callbackContext.success(encryptResult);
                }
            }, callbackContext);
        } else if (action.equals(COMMAND_DECRYPT)) {
            threadhelper(new SecurityOp() {

                @Override
                public void run() throws Exception {
                    String decryptResult = decrypt(args.getString(0),
                            args.getString(1), args.optJSONObject(2));
                    callbackContext.success(decryptResult);
                }
            }, callbackContext);
        } else if (action.equals(COMMAND_ENCRYPT_FILE)) {
            threadhelper(new SecurityOp() {

                @Override
                public void run() throws Exception {
                    String result = encryptFile(args.getString(0),
                            args.getString(1), args.getString(2));
                    callbackContext.success(result);
                }
            }, callbackContext);
        } else if (action.equals(COMMAND_DECRYPT_FILE)) {
            threadhelper(new SecurityOp() {

                @Override
                public void run() throws Exception {
                    String result = decryptFile(args.getString(0),
                            args.getString(1), args.getString(2));
                    callbackContext.success(result);
                }
            }, callbackContext);
        } else if (action.equals(COMMAND_DIGEST)) {
            threadhelper(new SecurityOp() {

                @Override
                public void run() throws Exception {
                    String result = digest(args.getString(0));
                    callbackContext.success(result);
                }
            }, callbackContext);
        } else {
            return false; // Invalid action, return false
        }
        return true;
    }

    /**
     * 异步执行扩展功能，并处理结果
     *
     * @param zipOp
     * @param callbackContext
     * @param action
     */
    private void threadhelper(final SecurityOp securityOp,
            final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    securityOp.run();
                } catch (Exception e) {
                    XLog.e(CLASS_NAME, e.getMessage());
                    e.printStackTrace();
                    if (e instanceof IllegalArgumentException) {
                        callbackContext.error(PATH_ERR);
                    } else if (e instanceof FileNotFoundException) {
                        callbackContext.error(FILE_NOT_FOUND_ERR);
                    } else if (e instanceof XCryptionException) {
                        callbackContext.error(OPERATION_ERR);
                    } else if (e instanceof IOException) {
                        callbackContext.error(OPERATION_ERR);
                    } else {
                        callbackContext.error(UNKNOWN_ERR);
                    }
                }
            }
        });
    }

    /**
     * 获取workspace路径
     *
     * @return
     */
    private String getWorkspacePath() {
        XAppWebView xAppWebView = (XAppWebView) this.webView;
        String appWorkspace = xAppWebView.getOwnerApp().getWorkSpace();
        return appWorkspace;
    }

    /**
     * 解析路径
     *
     * @param filePath
     * @return
     * @throws IllegalArgumentException
     */
    private Uri resolveUri(String filePath) throws IllegalArgumentException {
        // 检查传入文件路径是否为空
        if (XStringUtils.isEmptyString(filePath)) {
            throw new IllegalArgumentException();
        }

        XPathResolver pathResolver = new XPathResolver(filePath,
                getWorkspacePath());
        return pathResolver.getUri(mResourceApi);
    }

    /**
     * 获取文件的数据流
     *
     * @param filePath
     *            文件名称，不带路径
     * @return 所请求文件路径的绝对路径
     * @throws IOException
     */
    private InputStream readFile(String filePath)
            throws IllegalArgumentException, IOException {
        Uri fileUri = resolveUri(filePath);
        if (!XFileUtils.isFilePathValid(fileUri.getPath())) {
            // 加密原文件不存在应该抛出FileNotFoundException异常
            throw new FileNotFoundException();
        }
        InputStream inputStream = mResourceApi.openForRead(fileUri).inputStream;
        if (null == inputStream) {
            throw new FileNotFoundException();
        }
        return inputStream;
    }

    /**
     * 创建目标文件，并返回文件路径
     *
     * @param absFilePath
     * @return
     * @throws FileNotFoundException
     */
    private String createTargetFile(String absFilePath)
            throws FileNotFoundException, IllegalArgumentException {
        // 对文件作路径解析和检测
        absFilePath = resolveUri(absFilePath).getPath();
        File requestFile = new File(absFilePath);
        if (requestFile.exists()) {
            requestFile.delete();
        }
        if (!XFileUtils.createFile(absFilePath)) {
            throw new FileNotFoundException();
        }
        return absFilePath;
    }

    /**
     * 对称加密字节数组并返回
     *
     * @param sKey
     *            密钥
     * @param sourceData
     *            需要加密的数据
     * @param options
     *            加解密配置选项
     * @return 经过加密的数据
     */
    private String encrypt(String sKey, String sourceData, JSONObject options)
            throws XCryptionException, XCryptionException {
        if (XStringUtils.isEmptyString(sKey)) {
            XLog.e(CLASS_NAME, KEY_EMPTY_ERROR);
            throw new XCryptionException(KEY_EMPTY_ERROR);
        }
        int cryptAlgorithm = DES_ALOGRITHEM;
        int encodeDataType = ENCODE_TYPE_STRING;
        int encodeKeyType = ENCODE_TYPE_STRING;
        if (options != null) {
            cryptAlgorithm = options
                    .optInt(KEY_CRYPT_ALGORITHM, DES_ALOGRITHEM);
            encodeDataType = options.optInt(KEY_ENCODE_DATA_TYPE,
                    ENCODE_TYPE_BASE64);
            encodeKeyType = options.optInt(KEY_ENCODE_KEY_TYPE,
                    ENCODE_TYPE_STRING);
        }
        byte[] keyBytes = null;
        keyBytes = getBytesEncode(encodeKeyType, sKey);
        switch (cryptAlgorithm) {
        case TRIPLE_DES_ALOGRITHEM:
            switch (encodeDataType) {
            case ENCODE_TYPE_HEX:
                return XStringUtils.hexEncode(mCryptor.encryptBytesFor3DES(
                        sourceData.getBytes(), keyBytes));
            default:
                return XBase64.encodeToString((mCryptor.encryptBytesFor3DES(
                        sourceData.getBytes(), keyBytes)), XBase64.NO_WRAP);
            }
        case RSA_ALOGRITHEM:
            switch (encodeDataType) {
            case ENCODE_TYPE_HEX:
                return XStringUtils.hexEncode(mCryptor.encryptRSA(
                        sourceData.getBytes(), keyBytes));
            default:
                return XBase64.encodeToString(
                        (mCryptor.encryptRSA(sourceData.getBytes(), keyBytes)),
                        XBase64.NO_WRAP);
            }
        default:
            switch (encodeDataType) {
            case ENCODE_TYPE_HEX:
                return XStringUtils.hexEncode(mCryptor.encryptBytesForDES(
                        sourceData.getBytes(), keyBytes));
            default:
                return XBase64.encodeToString((mCryptor.encryptBytesForDES(
                        sourceData.getBytes(), keyBytes)), XBase64.NO_WRAP);
            }
        }
    }

    /**
     * 对称加密文件并返回
     *
     * @param sKey
     *            密钥
     * @param sourceFilePath
     *            需要加密的文件的路径
     * @param targetFilePath
     *            经过加密得到的文件的路径
     * @return 加密后文件的相对路径
     * @throws XCryptionException
     * @throws IOException
     * @throws IllegalArgumentException
     * @throws FileNotFoundException
     */
    private String encryptFile(String sKey, String sourceFilePath,
            String targetFilePath) throws XCryptionException,
            IllegalArgumentException, IOException {
        InputStream sourceIs = readFile(sourceFilePath);
        targetFilePath = createTargetFile(targetFilePath);
        return cryptFile(sKey, sourceIs, targetFilePath, true);
    }

    /**
     * 对称解密字节数组并返回
     *
     * @param sKey
     *            密钥
     * @param sourceData
     *            需要解密的数据
     * @param options
     *            加解密配置选项
     * @return 经过解密的数据
     */
    private String decrypt(String sKey, String sourceData, JSONObject options)
            throws XCryptionException {
        if (XStringUtils.isEmptyString(sKey)) {
            XLog.e(CLASS_NAME, KEY_EMPTY_ERROR);
            throw new XCryptionException(KEY_EMPTY_ERROR);
        }
        int cryptAlgorithm = DES_ALOGRITHEM;
        int encodeDataType = ENCODE_TYPE_STRING;
        int encodeKeyType = ENCODE_TYPE_STRING;
        if (options != null) {
            cryptAlgorithm = options
                    .optInt(KEY_CRYPT_ALGORITHM, DES_ALOGRITHEM);
            encodeDataType = options.optInt(KEY_ENCODE_DATA_TYPE,
                    ENCODE_TYPE_STRING);
            encodeKeyType = options.optInt(KEY_ENCODE_KEY_TYPE,
                    ENCODE_TYPE_STRING);
        }
        byte[] keyBytes = null;
        keyBytes = getBytesEncode(encodeKeyType, sKey);
        switch (cryptAlgorithm) {
        case TRIPLE_DES_ALOGRITHEM:
            switch (encodeDataType) {
            case ENCODE_TYPE_HEX:
                return new String(mCryptor.decryptBytesFor3DES(
                        XStringUtils.hexDecode(sourceData), keyBytes));
            default:
                return new String(mCryptor.decryptBytesFor3DES(
                        XBase64.decode(sourceData, XBase64.NO_WRAP), keyBytes));
            }
        case RSA_ALOGRITHEM:
            switch (encodeDataType) {
            case ENCODE_TYPE_HEX:
                return new String(mCryptor.decryptRSA(
                        XStringUtils.hexDecode(sourceData), keyBytes));
            default:
                return new String(mCryptor.decryptRSA(
                        XBase64.decode(sourceData, XBase64.NO_WRAP), keyBytes));
            }
        default:
            switch (encodeDataType) {
            case ENCODE_TYPE_HEX:
                return new String(mCryptor.decryptBytesForDES(
                        XStringUtils.hexDecode(sourceData), keyBytes));
            default:
                return new String(mCryptor.decryptBytesForDES(
                        XBase64.decode(sourceData, XBase64.NO_WRAP), keyBytes));
            }
        }
    }

    /**
     * 对称解密文件并返回
     *
     * @param sKey
     *            密钥
     * @param sourceFilePath
     *            需要解密的文件的路径
     * @param targetFilePath
     *            经过解密得到的文件的路径
     * @return 解密后文件的相对路径
     * @throws IOException
     * @throws IllegalArgumentException
     */
    private String decryptFile(String sKey, String sourceFilePath,
            String targetFilePath) throws XCryptionException,
            IllegalArgumentException, IOException {
        InputStream sourceIs = readFile(sourceFilePath);
        targetFilePath = createTargetFile(targetFilePath);
        return cryptFile(sKey, sourceIs, targetFilePath, false);
    }

    /**
     * 对文件进行加解密操作,并返回文件路径
     *
     * @param sKey
     * @param fileIs
     * @param absTargetFilePath
     * @param isEncrypt
     * @return
     * @throws XCryptionException
     */
    private String cryptFile(String sKey, InputStream fileIs,
            String absTargetFilePath, boolean isEncrypt)
            throws XCryptionException {
        byte[] keyBytes = getBytesEncode(ENCODE_TYPE_STRING, sKey);
        byte[] cryptedBytes = null;
        if (isEncrypt) {
            cryptedBytes = mCryptor.encryptStreamForDES(keyBytes, fileIs);
        } else {
            cryptedBytes = mCryptor.decryptStreamForDES(keyBytes, fileIs);
        }
        if (XFileUtils.writeFileByByte(absTargetFilePath, cryptedBytes)) {
            return absTargetFilePath;
        }
        throw new XCryptionException(CRYPTION_ERROR);
    }

    /**
     * 求md5值
     *
     * @param data
     * @return
     * @throws UnsupportedEncodingException
     * @throws XCryptionException
     */
    private String digest(String data) throws XCryptionException {
        if (XStringUtils.isEmptyString(data)) {
            XLog.e(CLASS_NAME, KEY_EMPTY_ERROR);
            throw new XCryptionException(KEY_EMPTY_ERROR);
        }
        XCryptor cryptor = new XCryptor();
        try {
            return cryptor.calMD5Value(data.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            XLog.e(CLASS_NAME, "digest failed: UnsupportedEncodingException");
            e.printStackTrace();
            throw new XCryptionException(CRYPTION_ERROR);
        }
    }

    /**
     * 获取按直接编码解码后的keyBytes
     *
     * @param encodeKeyType
     *            编码类型
     * @param keyString
     *            解码前的keyString
     * @return 解码后的二进制串
     */
    private byte[] getBytesEncode(int encodeKeyType, String keyString)
            throws IllegalArgumentException {
        if (XStringUtils.isEmptyString(keyString)) {
            throw new IllegalArgumentException();
        }
        switch (encodeKeyType) {
        case ENCODE_TYPE_BASE64:
            return XBase64.decode(keyString, XBase64.NO_WRAP);
        case ENCODE_TYPE_HEX:
            return XStringUtils.hexDecode(keyString);
        default:
            return keyString.getBytes();
        }
    }
}
