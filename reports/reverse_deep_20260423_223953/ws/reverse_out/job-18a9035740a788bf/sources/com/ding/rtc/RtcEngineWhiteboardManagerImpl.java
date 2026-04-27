package com.ding.rtc;

import android.content.Context;
import com.ding.rtc.api.DingRtcWhiteBoardTypes;
import java.io.File;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* JADX INFO: loaded from: classes.dex */
public class RtcEngineWhiteboardManagerImpl implements DingRtcEngineWhiteboardManager {
    private final long mNativePtr;
    private final RtcWhiteboardManagerListener mWbManagerListener;
    private final Map<String, DingRtcEngineWhiteboard> mWhiteBoardMap = new ConcurrentHashMap();

    native int nativeCreateWhiteboard(long instance, String whiteboardId, int width, int height, int mode);

    native long nativeGetWhiteboard(long instance, String whiteboardId);

    native int nativeSetWbManagerListener(long instance, RtcWhiteboardManagerListener wbManagerListener);

    native int nativeSetWhiteboardCacheDir(long instance, String cacheDir);

    RtcEngineWhiteboardManagerImpl(Context context, long nativePtr) {
        this.mNativePtr = nativePtr;
        RtcWhiteboardManagerListener rtcWhiteboardManagerListener = new RtcWhiteboardManagerListener();
        this.mWbManagerListener = rtcWhiteboardManagerListener;
        nativeSetWbManagerListener(this.mNativePtr, rtcWhiteboardManagerListener);
        setupWhiteboardCachePath(context.getApplicationContext());
    }

    private void setupWhiteboardCachePath(Context context) {
        if (this.mNativePtr == 0) {
            return;
        }
        File extPath = context.getExternalCacheDir();
        if (extPath == null) {
            extPath = context.getCacheDir();
        }
        String cachePath = extPath.getAbsolutePath();
        if (cachePath != null) {
            String cachePath2 = cachePath + "/mango/";
            File folder = new File(cachePath2);
            boolean success = true;
            if (!folder.exists()) {
                success = folder.mkdir();
            }
            if (!success) {
                return;
            }
            nativeSetWhiteboardCacheDir(this.mNativePtr, cachePath2);
        }
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboardManager
    public int setWhiteboardManagerEventListener(DingRtcEngineWhiteboardManagerListener listener) {
        this.mWbManagerListener.setWhiteboardManagerListener(listener);
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboardManager
    public DingRtcEngineWhiteboard createWhiteboard(String whiteboardId, DingRtcWhiteBoardTypes.DingRtcWBConfig config) {
        int ret = nativeCreateWhiteboard(this.mNativePtr, whiteboardId, config.width, config.height, config.mode.getValue());
        if (ret == 0) {
            long nativeWhiteBoardPtr = nativeGetWhiteboard(this.mNativePtr, whiteboardId);
            if (nativeWhiteBoardPtr != 0) {
                RtcWhiteboardImpl whiteBoard = new RtcWhiteboardImpl(nativeWhiteBoardPtr, whiteboardId);
                this.mWhiteBoardMap.put(whiteboardId, whiteBoard);
                return whiteBoard;
            }
            return null;
        }
        return null;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboardManager
    public DingRtcEngineWhiteboard getWhiteboard(String whiteboardId) {
        if (this.mWhiteBoardMap.containsKey(whiteboardId)) {
            return this.mWhiteBoardMap.get(whiteboardId);
        }
        long nativeWhiteBoardPtr = nativeGetWhiteboard(this.mNativePtr, whiteboardId);
        if (nativeWhiteBoardPtr != 0) {
            RtcWhiteboardImpl whiteBoard = new RtcWhiteboardImpl(nativeWhiteBoardPtr, whiteboardId);
            this.mWhiteBoardMap.put(whiteboardId, whiteBoard);
            return whiteBoard;
        }
        return null;
    }
}
