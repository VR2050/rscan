package org.webrtc.mozi;

import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class VideoDumpUtils {
    private static native int nativeAddOrUpdateRemoteVideoStreamInfo(String str, String str2);

    private static native int nativeRemoveRemoteVideoStreamInfo(String str);

    private static native int nativeStartVideoDump(String str, int i, int i2, List<String> list);

    private static native int nativeStopVideoDump();

    public enum VideoDumpType {
        LOCAL_CAPTURE(1),
        LOCAL_ENCODED(2),
        REMOTE_ENCODED(4),
        REMOTE_RENDER(8);

        private final int val;

        VideoDumpType(int val) {
            this.val = val;
        }

        public int getValue() {
            return this.val;
        }
    }

    public static int StartVideoDump(String dirPath, int maxRawDataFileSize, int maxEncodedDataFileSize, List<String> filterRemoteStreams) {
        if (dirPath == null || maxRawDataFileSize <= 0 || maxEncodedDataFileSize <= 0) {
            throw new IllegalArgumentException("invaild dump params.");
        }
        return nativeStartVideoDump(dirPath, maxRawDataFileSize, maxEncodedDataFileSize, filterRemoteStreams);
    }

    public static int StopVideoDump() {
        return nativeStopVideoDump();
    }

    public static int AddOrUpdateRemoteVideoStreamInfo(String streamId, String videoSsrc) {
        return nativeAddOrUpdateRemoteVideoStreamInfo(streamId, videoSsrc);
    }

    public static int RemoveRemoteVideoStreamInfo(String streamId) {
        return nativeRemoveRemoteVideoStreamInfo(streamId);
    }
}
