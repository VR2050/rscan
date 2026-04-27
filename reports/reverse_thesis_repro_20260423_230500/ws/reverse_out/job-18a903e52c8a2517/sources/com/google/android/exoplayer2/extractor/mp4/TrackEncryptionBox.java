package com.google.android.exoplayer2.extractor.mp4;

import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.extractor.TrackOutput;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Log;

/* JADX INFO: loaded from: classes2.dex */
public final class TrackEncryptionBox {
    private static final String TAG = "TrackEncryptionBox";
    public final TrackOutput.CryptoData cryptoData;
    public final byte[] defaultInitializationVector;
    public final boolean isEncrypted;
    public final int perSampleIvSize;
    public final String schemeType;

    public TrackEncryptionBox(boolean isEncrypted, String schemeType, int perSampleIvSize, byte[] keyId, int defaultEncryptedBlocks, int defaultClearBlocks, byte[] defaultInitializationVector) {
        Assertions.checkArgument((defaultInitializationVector == null) ^ (perSampleIvSize == 0));
        this.isEncrypted = isEncrypted;
        this.schemeType = schemeType;
        this.perSampleIvSize = perSampleIvSize;
        this.defaultInitializationVector = defaultInitializationVector;
        this.cryptoData = new TrackOutput.CryptoData(schemeToCryptoMode(schemeType), keyId, defaultEncryptedBlocks, defaultClearBlocks);
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    private static int schemeToCryptoMode(String schemeType) {
        if (schemeType == null) {
            return 1;
        }
        byte b = -1;
        switch (schemeType.hashCode()) {
            case 3046605:
                if (schemeType.equals(C.CENC_TYPE_cbc1)) {
                    b = 2;
                }
                break;
            case 3046671:
                if (schemeType.equals(C.CENC_TYPE_cbcs)) {
                    b = 3;
                }
                break;
            case 3049879:
                if (schemeType.equals(C.CENC_TYPE_cenc)) {
                    b = 0;
                }
                break;
            case 3049895:
                if (schemeType.equals(C.CENC_TYPE_cens)) {
                    b = 1;
                }
                break;
        }
        if (b == 0 || b == 1) {
            return 1;
        }
        if (b == 2 || b == 3) {
            return 2;
        }
        Log.w(TAG, "Unsupported protection scheme type '" + schemeType + "'. Assuming AES-CTR crypto mode.");
        return 1;
    }
}
