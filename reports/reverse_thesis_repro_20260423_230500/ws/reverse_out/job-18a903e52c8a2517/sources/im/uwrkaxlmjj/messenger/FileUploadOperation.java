package im.uwrkaxlmjj.messenger;

import android.content.SharedPreferences;
import android.net.Uri;
import android.util.SparseArray;
import android.util.SparseIntArray;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.NativeByteBuffer;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.WriteToSocketDelegate;
import java.io.File;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes2.dex */
public class FileUploadOperation {
    private static final int initialRequestsCount = 8;
    private static final int initialRequestsSlowNetworkCount = 1;
    private static final int maxUploadingKBytes = 2048;
    private static final int maxUploadingSlowNetworkKBytes = 32;
    private static final int minUploadChunkSize = 128;
    private static final int minUploadChunkSlowNetworkSize = 32;
    private long availableSize;
    private int currentAccount;
    private long currentFileId;
    private int currentPartNum;
    private int currentType;
    private int currentUploadRequetsCount;
    private FileUploadOperationDelegate delegate;
    private int estimatedSize;
    private String fileKey;
    private int fingerprint;
    private ArrayList<byte[]> freeRequestIvs;
    private boolean isBigFile;
    private boolean isEncrypted;
    private boolean isLastPart;
    private byte[] iv;
    private byte[] ivChange;
    private byte[] key;
    private int lastSavedPartNum;
    private int maxRequestsCount;
    private boolean nextPartFirst;
    private int operationGuid;
    private SharedPreferences preferences;
    private byte[] readBuffer;
    private long readBytesCount;
    private int requestNum;
    private int saveInfoTimes;
    private boolean slowNetwork;
    private boolean started;
    private int state;
    private RandomAccessFile stream;
    private long totalFileSize;
    private int totalPartsCount;
    private boolean uploadFirstPartLater;
    private int uploadStartTime;
    private long uploadedBytesCount;
    private String uploadingFilePath;
    private int uploadChunkSize = 65536;
    private SparseIntArray requestTokens = new SparseIntArray();
    private SparseArray<UploadCachedResult> cachedResults = new SparseArray<>();

    public interface FileUploadOperationDelegate {
        void didChangedUploadProgress(FileUploadOperation fileUploadOperation, float f);

        void didFailedUploadingFile(FileUploadOperation fileUploadOperation);

        void didFinishUploadingFile(FileUploadOperation fileUploadOperation, TLRPC.InputFile inputFile, TLRPC.InputEncryptedFile inputEncryptedFile, byte[] bArr, byte[] bArr2);
    }

    private class UploadCachedResult {
        private long bytesOffset;
        private byte[] iv;

        private UploadCachedResult() {
        }
    }

    public FileUploadOperation(int instance, String location, boolean encrypted, int estimated, int type) {
        this.currentAccount = instance;
        this.uploadingFilePath = location;
        this.isEncrypted = encrypted;
        this.estimatedSize = estimated;
        this.currentType = type;
        this.uploadFirstPartLater = (estimated == 0 || encrypted) ? false : true;
    }

    public long getTotalFileSize() {
        return this.totalFileSize;
    }

    public void setDelegate(FileUploadOperationDelegate fileUploadOperationDelegate) {
        this.delegate = fileUploadOperationDelegate;
    }

    public void start() {
        if (this.state != 0) {
            return;
        }
        this.state = 1;
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileUploadOperation$x9XH34JcfM9SZ6lt-0Pvz6M0zXg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$start$0$FileUploadOperation();
            }
        });
    }

    public /* synthetic */ void lambda$start$0$FileUploadOperation() {
        this.preferences = ApplicationLoader.applicationContext.getSharedPreferences("uploadinfo", 0);
        this.slowNetwork = ApplicationLoader.isConnectionSlow();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("start upload on slow network = " + this.slowNetwork);
        }
        int count = this.slowNetwork ? 1 : 8;
        for (int a = 0; a < count; a++) {
            startUploadRequest();
        }
    }

    protected void onNetworkChanged(final boolean slow) {
        if (this.state != 1) {
            return;
        }
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileUploadOperation$oucNt9t6iifjQLceQ5XIt9V7ZJg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onNetworkChanged$1$FileUploadOperation(slow);
            }
        });
    }

    public /* synthetic */ void lambda$onNetworkChanged$1$FileUploadOperation(boolean slow) {
        if (this.slowNetwork != slow) {
            this.slowNetwork = slow;
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("network changed to slow = " + this.slowNetwork);
            }
            int a = 0;
            while (true) {
                if (a >= this.requestTokens.size()) {
                    break;
                }
                ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.requestTokens.valueAt(a), true);
                a++;
            }
            this.requestTokens.clear();
            cleanup();
            this.isLastPart = false;
            this.nextPartFirst = false;
            this.requestNum = 0;
            this.currentPartNum = 0;
            this.readBytesCount = 0L;
            this.uploadedBytesCount = 0L;
            this.saveInfoTimes = 0;
            this.key = null;
            this.iv = null;
            this.ivChange = null;
            this.currentUploadRequetsCount = 0;
            this.lastSavedPartNum = 0;
            this.uploadFirstPartLater = false;
            this.cachedResults.clear();
            this.operationGuid++;
            int count = this.slowNetwork ? 1 : 8;
            for (int a2 = 0; a2 < count; a2++) {
                startUploadRequest();
            }
        }
    }

    public void cancel() {
        if (this.state == 3) {
            return;
        }
        this.state = 2;
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileUploadOperation$iXSmB89HyB4-ua9gBRpYW0GFUiY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$cancel$2$FileUploadOperation();
            }
        });
        this.delegate.didFailedUploadingFile(this);
        cleanup();
    }

    public /* synthetic */ void lambda$cancel$2$FileUploadOperation() {
        for (int a = 0; a < this.requestTokens.size(); a++) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.requestTokens.valueAt(a), true);
        }
    }

    private void cleanup() {
        if (this.preferences == null) {
            this.preferences = ApplicationLoader.applicationContext.getSharedPreferences("uploadinfo", 0);
        }
        this.preferences.edit().remove(this.fileKey + "_time").remove(this.fileKey + "_size").remove(this.fileKey + "_uploaded").remove(this.fileKey + "_id").remove(this.fileKey + "_iv").remove(this.fileKey + "_key").remove(this.fileKey + "_ivc").commit();
        try {
            if (this.stream != null) {
                this.stream.close();
                this.stream = null;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    protected void checkNewDataAvailable(final long newAvailableSize, final long finalSize) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileUploadOperation$MErZE-rVTWUhJnbOak4qjioYiD0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$checkNewDataAvailable$3$FileUploadOperation(finalSize, newAvailableSize);
            }
        });
    }

    public /* synthetic */ void lambda$checkNewDataAvailable$3$FileUploadOperation(long finalSize, long newAvailableSize) {
        if (this.estimatedSize != 0 && finalSize != 0) {
            this.estimatedSize = 0;
            this.totalFileSize = finalSize;
            calcTotalPartsCount();
            if (!this.uploadFirstPartLater && this.started) {
                storeFileUploadInfo();
            }
        }
        this.availableSize = finalSize > 0 ? finalSize : newAvailableSize;
        if (this.currentUploadRequetsCount < this.maxRequestsCount) {
            startUploadRequest();
        }
    }

    private void storeFileUploadInfo() {
        SharedPreferences.Editor editor = this.preferences.edit();
        editor.putInt(this.fileKey + "_time", this.uploadStartTime);
        editor.putLong(this.fileKey + "_size", this.totalFileSize);
        editor.putLong(this.fileKey + "_id", this.currentFileId);
        editor.remove(this.fileKey + "_uploaded");
        if (this.isEncrypted) {
            editor.putString(this.fileKey + "_iv", Utilities.bytesToHex(this.iv));
            editor.putString(this.fileKey + "_ivc", Utilities.bytesToHex(this.ivChange));
            editor.putString(this.fileKey + "_key", Utilities.bytesToHex(this.key));
        }
        editor.commit();
    }

    private void calcTotalPartsCount() {
        if (this.uploadFirstPartLater) {
            if (this.isBigFile) {
                long j = this.totalFileSize;
                int i = this.uploadChunkSize;
                this.totalPartsCount = (((int) (((j - ((long) i)) + ((long) i)) - 1)) / i) + 1;
                return;
            } else {
                long j2 = this.totalFileSize - 1024;
                int i2 = this.uploadChunkSize;
                this.totalPartsCount = (((int) ((j2 + ((long) i2)) - 1)) / i2) + 1;
                return;
            }
        }
        long j3 = this.totalFileSize;
        int i3 = this.uploadChunkSize;
        this.totalPartsCount = ((int) ((j3 + ((long) i3)) - 1)) / i3;
    }

    private void startUploadRequest() {
        int currentRequestBytes;
        byte[] currentRequestIv;
        TLObject finalRequest;
        int currentRequestPartNum;
        int connectionType;
        int i;
        boolean rewrite;
        if (this.state != 1) {
            return;
        }
        try {
            this.started = true;
            if (this.stream == null) {
                File cacheFile = new File(this.uploadingFilePath);
                if (!AndroidUtilities.isInternalUri(Uri.fromFile(cacheFile))) {
                    this.stream = new RandomAccessFile(cacheFile, "r");
                    if (this.estimatedSize != 0) {
                        this.totalFileSize = this.estimatedSize;
                    } else {
                        this.totalFileSize = cacheFile.length();
                    }
                    if (this.totalFileSize > 10485760) {
                        this.isBigFile = true;
                    }
                    int iMax = (int) Math.max(this.slowNetwork ? 32L : 128L, ((this.totalFileSize + 3072000) - 1) / 3072000);
                    this.uploadChunkSize = iMax;
                    if (1024 % iMax != 0) {
                        int chunkSize = 64;
                        while (this.uploadChunkSize > chunkSize) {
                            chunkSize *= 2;
                        }
                        this.uploadChunkSize = chunkSize;
                    }
                    this.maxRequestsCount = Math.max(1, (this.slowNetwork ? 32 : 2048) / this.uploadChunkSize);
                    if (this.isEncrypted) {
                        this.freeRequestIvs = new ArrayList<>(this.maxRequestsCount);
                        for (int a = 0; a < this.maxRequestsCount; a++) {
                            this.freeRequestIvs.add(new byte[32]);
                        }
                    }
                    int a2 = this.uploadChunkSize;
                    this.uploadChunkSize = a2 * 1024;
                    calcTotalPartsCount();
                    this.readBuffer = new byte[this.uploadChunkSize];
                    StringBuilder sb = new StringBuilder();
                    sb.append(this.uploadingFilePath);
                    sb.append(this.isEncrypted ? "enc" : "");
                    this.fileKey = Utilities.MD5(sb.toString());
                    long fileSize = this.preferences.getLong(this.fileKey + "_size", 0L);
                    this.uploadStartTime = (int) (System.currentTimeMillis() / 1000);
                    boolean rewrite2 = false;
                    if (!this.uploadFirstPartLater && !this.nextPartFirst && this.estimatedSize == 0 && fileSize == this.totalFileSize) {
                        this.currentFileId = this.preferences.getLong(this.fileKey + "_id", 0L);
                        int date = this.preferences.getInt(this.fileKey + "_time", 0);
                        long uploadedSize = this.preferences.getLong(this.fileKey + "_uploaded", 0L);
                        if (this.isEncrypted) {
                            String ivString = this.preferences.getString(this.fileKey + "_iv", null);
                            String keyString = this.preferences.getString(this.fileKey + "_key", null);
                            if (ivString != null && keyString != null) {
                                this.key = Utilities.hexToBytes(keyString);
                                byte[] bArrHexToBytes = Utilities.hexToBytes(ivString);
                                this.iv = bArrHexToBytes;
                                if (this.key != null && bArrHexToBytes != null && this.key.length == 32 && bArrHexToBytes.length == 32) {
                                    byte[] bArr = new byte[32];
                                    this.ivChange = bArr;
                                    System.arraycopy(bArrHexToBytes, 0, bArr, 0, 32);
                                } else {
                                    rewrite2 = true;
                                }
                            } else {
                                rewrite2 = true;
                            }
                        }
                        if (!rewrite2 && date != 0) {
                            if (this.isBigFile && date < this.uploadStartTime - 86400) {
                                date = 0;
                            } else if (!this.isBigFile && date < this.uploadStartTime - 5400.0f) {
                                date = 0;
                            }
                            if (date != 0) {
                                if (uploadedSize > 0) {
                                    this.readBytesCount = uploadedSize;
                                    this.currentPartNum = (int) (uploadedSize / ((long) this.uploadChunkSize));
                                    if (!this.isBigFile) {
                                        for (int b = 0; b < this.readBytesCount / ((long) this.uploadChunkSize); b++) {
                                            int bytesRead = this.stream.read(this.readBuffer);
                                            int toAdd = 0;
                                            if (this.isEncrypted && bytesRead % 16 != 0) {
                                                toAdd = 0 + (16 - (bytesRead % 16));
                                            }
                                            NativeByteBuffer sendBuffer = new NativeByteBuffer(bytesRead + toAdd);
                                            if (bytesRead != this.uploadChunkSize || this.totalPartsCount == this.currentPartNum + 1) {
                                                this.isLastPart = true;
                                            }
                                            sendBuffer.writeBytes(this.readBuffer, 0, bytesRead);
                                            if (this.isEncrypted) {
                                                for (int a3 = 0; a3 < toAdd; a3++) {
                                                    sendBuffer.writeByte(0);
                                                }
                                                Utilities.aesIgeEncryption(sendBuffer.buffer, this.key, this.ivChange, true, true, 0, bytesRead + toAdd);
                                            }
                                            sendBuffer.reuse();
                                        }
                                    } else {
                                        this.stream.seek(uploadedSize);
                                        if (this.isEncrypted) {
                                            String ivcString = this.preferences.getString(this.fileKey + "_ivc", null);
                                            if (ivcString != null) {
                                                byte[] bArrHexToBytes2 = Utilities.hexToBytes(ivcString);
                                                this.ivChange = bArrHexToBytes2;
                                                if (bArrHexToBytes2 == null || bArrHexToBytes2.length != 32) {
                                                    rewrite2 = true;
                                                    this.readBytesCount = 0L;
                                                    this.currentPartNum = 0;
                                                }
                                            } else {
                                                rewrite2 = true;
                                                this.readBytesCount = 0L;
                                                this.currentPartNum = 0;
                                            }
                                        }
                                    }
                                } else {
                                    rewrite2 = true;
                                }
                            }
                        } else {
                            rewrite2 = true;
                        }
                        rewrite = rewrite2;
                    } else {
                        rewrite = true;
                    }
                    if (rewrite) {
                        if (this.isEncrypted) {
                            this.iv = new byte[32];
                            this.key = new byte[32];
                            this.ivChange = new byte[32];
                            Utilities.random.nextBytes(this.iv);
                            Utilities.random.nextBytes(this.key);
                            System.arraycopy(this.iv, 0, this.ivChange, 0, 32);
                        }
                        this.currentFileId = Utilities.random.nextLong();
                        if (!this.nextPartFirst && !this.uploadFirstPartLater && this.estimatedSize == 0) {
                            storeFileUploadInfo();
                        }
                    }
                    if (this.isEncrypted) {
                        try {
                            MessageDigest md = MessageDigest.getInstance("MD5");
                            byte[] arr = new byte[64];
                            System.arraycopy(this.key, 0, arr, 0, 32);
                            System.arraycopy(this.iv, 0, arr, 32, 32);
                            byte[] digest = md.digest(arr);
                            for (int a4 = 0; a4 < 4; a4++) {
                                this.fingerprint |= ((digest[a4] ^ digest[a4 + 4]) & 255) << (a4 * 8);
                            }
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    }
                    this.uploadedBytesCount = this.readBytesCount;
                    this.lastSavedPartNum = this.currentPartNum;
                    if (this.uploadFirstPartLater) {
                        if (this.isBigFile) {
                            this.stream.seek(this.uploadChunkSize);
                            this.readBytesCount = this.uploadChunkSize;
                        } else {
                            this.stream.seek(1024L);
                            this.readBytesCount = 1024L;
                        }
                        this.currentPartNum = 1;
                    }
                } else {
                    throw new Exception("trying to upload internal file");
                }
            }
            if (this.estimatedSize != 0 && this.readBytesCount + ((long) this.uploadChunkSize) > this.availableSize) {
                return;
            }
            if (!this.nextPartFirst) {
                currentRequestBytes = this.stream.read(this.readBuffer);
            } else {
                this.stream.seek(0L);
                if (this.isBigFile) {
                    currentRequestBytes = this.stream.read(this.readBuffer);
                    i = 0;
                } else {
                    i = 0;
                    currentRequestBytes = this.stream.read(this.readBuffer, 0, 1024);
                }
                this.currentPartNum = i;
            }
            if (currentRequestBytes == -1) {
                return;
            }
            int toAdd2 = 0;
            if (this.isEncrypted && currentRequestBytes % 16 != 0) {
                toAdd2 = 0 + (16 - (currentRequestBytes % 16));
            }
            NativeByteBuffer sendBuffer2 = new NativeByteBuffer(currentRequestBytes + toAdd2);
            if (this.nextPartFirst || currentRequestBytes != this.uploadChunkSize || (this.estimatedSize == 0 && this.totalPartsCount == this.currentPartNum + 1)) {
                if (this.uploadFirstPartLater) {
                    this.nextPartFirst = true;
                    this.uploadFirstPartLater = false;
                } else {
                    this.isLastPart = true;
                }
            }
            sendBuffer2.writeBytes(this.readBuffer, 0, currentRequestBytes);
            if (this.isEncrypted) {
                for (int a5 = 0; a5 < toAdd2; a5++) {
                    sendBuffer2.writeByte(0);
                }
                Utilities.aesIgeEncryption(sendBuffer2.buffer, this.key, this.ivChange, true, true, 0, currentRequestBytes + toAdd2);
                byte[] currentRequestIv2 = this.freeRequestIvs.get(0);
                System.arraycopy(this.ivChange, 0, currentRequestIv2, 0, 32);
                this.freeRequestIvs.remove(0);
                currentRequestIv = currentRequestIv2;
            } else {
                currentRequestIv = null;
            }
            if (this.isBigFile) {
                TLRPC.TL_upload_saveBigFilePart req = new TLRPC.TL_upload_saveBigFilePart();
                int currentRequestPartNum2 = this.currentPartNum;
                req.file_part = currentRequestPartNum2;
                req.file_id = this.currentFileId;
                if (this.estimatedSize != 0) {
                    req.file_total_parts = -1;
                } else {
                    req.file_total_parts = this.totalPartsCount;
                }
                req.bytes = sendBuffer2;
                finalRequest = req;
                currentRequestPartNum = currentRequestPartNum2;
            } else {
                TLRPC.TL_upload_saveFilePart req2 = new TLRPC.TL_upload_saveFilePart();
                int currentRequestPartNum3 = this.currentPartNum;
                req2.file_part = currentRequestPartNum3;
                req2.file_id = this.currentFileId;
                req2.bytes = sendBuffer2;
                finalRequest = req2;
                currentRequestPartNum = currentRequestPartNum3;
            }
            if (this.isLastPart && this.nextPartFirst) {
                this.nextPartFirst = false;
                this.currentPartNum = this.totalPartsCount - 1;
                this.stream.seek(this.totalFileSize);
            }
            this.readBytesCount += (long) currentRequestBytes;
            this.currentPartNum++;
            this.currentUploadRequetsCount++;
            final int requestNumFinal = this.requestNum;
            this.requestNum = requestNumFinal + 1;
            final long j = currentRequestPartNum + currentRequestBytes;
            final int requestSize = finalRequest.getObjectSize() + 4;
            final int currentOperationGuid = this.operationGuid;
            if (this.slowNetwork) {
                connectionType = 4;
            } else {
                int connectionType2 = requestNumFinal % 4;
                connectionType = (connectionType2 << 16) | 4;
            }
            final byte[] bArr2 = currentRequestIv;
            final int i2 = currentRequestBytes;
            final int currentOperationGuid2 = currentRequestPartNum;
            final TLObject tLObject = finalRequest;
            int requestToken = ConnectionsManager.getInstance(this.currentAccount).sendRequest(finalRequest, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileUploadOperation$aHvTHCl-5Ogtvn1M1X66LDXmmFY
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject2, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$startUploadRequest$4$FileUploadOperation(currentOperationGuid, requestSize, bArr2, requestNumFinal, i2, currentOperationGuid2, j, tLObject, tLObject2, tL_error);
                }
            }, null, new WriteToSocketDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileUploadOperation$4cw_eMUcVNUwNbcEYNaxE4APH74
                @Override // im.uwrkaxlmjj.tgnet.WriteToSocketDelegate
                public final void run() {
                    this.f$0.lambda$startUploadRequest$6$FileUploadOperation();
                }
            }, 10, Integer.MAX_VALUE, connectionType, true);
            this.requestTokens.put(requestNumFinal, requestToken);
        } catch (Exception e2) {
            FileLog.e(e2);
            this.state = 4;
            this.delegate.didFailedUploadingFile(this);
            cleanup();
        }
    }

    public /* synthetic */ void lambda$startUploadRequest$4$FileUploadOperation(int currentOperationGuid, int requestSize, byte[] currentRequestIv, int requestNumFinal, int currentRequestBytes, int currentRequestPartNum, long currentRequestBytesOffset, TLObject finalRequest, TLObject response, TLRPC.TL_error error) {
        long size;
        int i;
        TLRPC.InputEncryptedFile result;
        TLRPC.InputFile result2;
        if (currentOperationGuid != this.operationGuid) {
            return;
        }
        int networkType = response != null ? response.networkType : ApplicationLoader.getCurrentNetworkType();
        int i2 = this.currentType;
        if (i2 == 50331648) {
            StatsController.getInstance(this.currentAccount).incrementSentBytesCount(networkType, 3, requestSize);
        } else if (i2 == 33554432) {
            StatsController.getInstance(this.currentAccount).incrementSentBytesCount(networkType, 2, requestSize);
        } else if (i2 == 16777216) {
            StatsController.getInstance(this.currentAccount).incrementSentBytesCount(networkType, 4, requestSize);
        } else if (i2 == 67108864) {
            StatsController.getInstance(this.currentAccount).incrementSentBytesCount(networkType, 5, requestSize);
        }
        if (currentRequestIv != null) {
            this.freeRequestIvs.add(currentRequestIv);
        }
        this.requestTokens.delete(requestNumFinal);
        if (response instanceof TLRPC.TL_boolTrue) {
            if (this.state == 1) {
                this.uploadedBytesCount += (long) currentRequestBytes;
                int i3 = this.estimatedSize;
                if (i3 != 0) {
                    size = Math.max(this.availableSize, i3);
                } else {
                    long size2 = this.totalFileSize;
                    size = size2;
                }
                this.delegate.didChangedUploadProgress(this, this.uploadedBytesCount / size);
                int i4 = this.currentUploadRequetsCount - 1;
                this.currentUploadRequetsCount = i4;
                if (!this.isLastPart || i4 != 0 || this.state != 1) {
                    if (this.currentUploadRequetsCount < this.maxRequestsCount) {
                        if (this.estimatedSize == 0 && !this.uploadFirstPartLater && !this.nextPartFirst) {
                            if (this.saveInfoTimes >= 4) {
                                this.saveInfoTimes = 0;
                            }
                            int i5 = this.lastSavedPartNum;
                            if (currentRequestPartNum == i5) {
                                this.lastSavedPartNum = i5 + 1;
                                long offsetToSave = currentRequestBytesOffset;
                                byte[] ivToSave = currentRequestIv;
                                while (true) {
                                    UploadCachedResult result3 = this.cachedResults.get(this.lastSavedPartNum);
                                    if (result3 == null) {
                                        break;
                                    }
                                    offsetToSave = result3.bytesOffset;
                                    ivToSave = result3.iv;
                                    this.cachedResults.remove(this.lastSavedPartNum);
                                    this.lastSavedPartNum++;
                                }
                                if ((this.isBigFile && offsetToSave % 1048576 == 0) || (!this.isBigFile && this.saveInfoTimes == 0)) {
                                    SharedPreferences.Editor editor = this.preferences.edit();
                                    editor.putLong(this.fileKey + "_uploaded", offsetToSave);
                                    if (this.isEncrypted) {
                                        editor.putString(this.fileKey + "_ivc", Utilities.bytesToHex(ivToSave));
                                    }
                                    editor.commit();
                                }
                            } else {
                                UploadCachedResult result4 = new UploadCachedResult();
                                result4.bytesOffset = currentRequestBytesOffset;
                                if (currentRequestIv != null) {
                                    result4.iv = new byte[32];
                                    System.arraycopy(currentRequestIv, 0, result4.iv, 0, 32);
                                }
                                this.cachedResults.put(currentRequestPartNum, result4);
                            }
                            this.saveInfoTimes++;
                        }
                        startUploadRequest();
                        return;
                    }
                    return;
                }
                this.state = 3;
                if (this.key != null) {
                    i = ConnectionsManager.FileTypeAudio;
                    if (this.isBigFile) {
                        result = new TLRPC.TL_inputEncryptedFileBigUploaded();
                    } else {
                        TLRPC.InputEncryptedFile result5 = new TLRPC.TL_inputEncryptedFileUploaded();
                        result5.md5_checksum = "";
                        result = result5;
                    }
                    result.parts = this.currentPartNum;
                    result.id = this.currentFileId;
                    result.key_fingerprint = this.fingerprint;
                    this.delegate.didFinishUploadingFile(this, null, result, this.key, this.iv);
                    cleanup();
                } else {
                    if (this.isBigFile) {
                        result2 = new TLRPC.TL_inputFileBig();
                    } else {
                        TLRPC.InputFile result6 = new TLRPC.TL_inputFile();
                        result6.md5_checksum = "";
                        result2 = result6;
                    }
                    result2.parts = this.currentPartNum;
                    result2.id = this.currentFileId;
                    String str = this.uploadingFilePath;
                    result2.name = str.substring(str.lastIndexOf("/") + 1);
                    i = ConnectionsManager.FileTypeAudio;
                    this.delegate.didFinishUploadingFile(this, result2, null, null, null);
                    cleanup();
                }
                int i6 = this.currentType;
                if (i6 == i) {
                    StatsController.getInstance(this.currentAccount).incrementSentItemsCount(ApplicationLoader.getCurrentNetworkType(), 3, 1);
                    return;
                }
                if (i6 == 33554432) {
                    StatsController.getInstance(this.currentAccount).incrementSentItemsCount(ApplicationLoader.getCurrentNetworkType(), 2, 1);
                    return;
                } else if (i6 == 16777216) {
                    StatsController.getInstance(this.currentAccount).incrementSentItemsCount(ApplicationLoader.getCurrentNetworkType(), 4, 1);
                    return;
                } else {
                    if (i6 == 67108864) {
                        StatsController.getInstance(this.currentAccount).incrementSentItemsCount(ApplicationLoader.getCurrentNetworkType(), 5, 1);
                        return;
                    }
                    return;
                }
            }
            return;
        }
        if (finalRequest != null) {
            FileLog.e("23123");
        }
        this.state = 4;
        this.delegate.didFailedUploadingFile(this);
        cleanup();
    }

    public /* synthetic */ void lambda$startUploadRequest$6$FileUploadOperation() {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$FileUploadOperation$JZQNSTTSqBKcXsHX3De1VrJeypk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$FileUploadOperation();
            }
        });
    }

    public /* synthetic */ void lambda$null$5$FileUploadOperation() {
        if (this.currentUploadRequetsCount < this.maxRequestsCount) {
            startUploadRequest();
        }
    }
}
