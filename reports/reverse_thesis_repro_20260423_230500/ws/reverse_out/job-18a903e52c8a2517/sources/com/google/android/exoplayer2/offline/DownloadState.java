package com.google.android.exoplayer2.offline;

import android.net.Uri;
import com.google.android.exoplayer2.util.Assertions;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/* JADX INFO: loaded from: classes2.dex */
public final class DownloadState {
    public static final int FAILURE_REASON_NONE = 0;
    public static final int FAILURE_REASON_UNKNOWN = 1;
    public static final int STATE_COMPLETED = 3;
    public static final int STATE_DOWNLOADING = 2;
    public static final int STATE_FAILED = 4;
    public static final int STATE_QUEUED = 0;
    public static final int STATE_REMOVED = 6;
    public static final int STATE_REMOVING = 5;
    public static final int STATE_RESTARTING = 7;
    public static final int STATE_STOPPED = 1;
    public static final int STOP_FLAG_DOWNLOAD_MANAGER_NOT_READY = 1;
    public static final int STOP_FLAG_STOPPED = 2;
    public final String cacheKey;
    public final byte[] customMetadata;
    public final float downloadPercentage;
    public final long downloadedBytes;
    public final int failureReason;
    public final String id;
    public final long startTimeMs;
    public final int state;
    public final int stopFlags;
    public final StreamKey[] streamKeys;
    public final long totalBytes;
    public final String type;
    public final long updateTimeMs;
    public final Uri uri;

    @Documented
    @Retention(RetentionPolicy.SOURCE)
    public @interface FailureReason {
    }

    @Documented
    @Retention(RetentionPolicy.SOURCE)
    public @interface State {
    }

    @Documented
    @Retention(RetentionPolicy.SOURCE)
    public @interface StopFlags {
    }

    public static String getStateString(int state) {
        switch (state) {
            case 0:
                return "QUEUED";
            case 1:
                return "STOPPED";
            case 2:
                return "DOWNLOADING";
            case 3:
                return "COMPLETED";
            case 4:
                return "FAILED";
            case 5:
                return "REMOVING";
            case 6:
                return "REMOVED";
            case 7:
                return "RESTARTING";
            default:
                throw new IllegalStateException();
        }
    }

    public static String getFailureString(int failureReason) {
        if (failureReason == 0) {
            return "NO_REASON";
        }
        if (failureReason == 1) {
            return "UNKNOWN_REASON";
        }
        throw new IllegalStateException();
    }

    DownloadState(String id, String type, Uri uri, String cacheKey, int state, float downloadPercentage, long downloadedBytes, long totalBytes, int failureReason, int stopFlags, long startTimeMs, long updateTimeMs, StreamKey[] streamKeys, byte[] customMetadata) {
        this.stopFlags = stopFlags;
        boolean z = true;
        if (failureReason != 0 ? state != 4 : state == 4) {
            z = false;
        }
        Assertions.checkState(z);
        this.id = id;
        this.type = type;
        this.uri = uri;
        this.cacheKey = cacheKey;
        this.streamKeys = streamKeys;
        this.customMetadata = customMetadata;
        this.state = state;
        this.downloadPercentage = downloadPercentage;
        this.downloadedBytes = downloadedBytes;
        this.totalBytes = totalBytes;
        this.failureReason = failureReason;
        this.startTimeMs = startTimeMs;
        this.updateTimeMs = updateTimeMs;
    }
}
