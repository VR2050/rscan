package com.ding.rtc;

import android.util.Log;
import com.ding.rtc.api.DingRtcWhiteBoardTypes;
import org.webrtc.mozi.Logging;

/* JADX INFO: loaded from: classes.dex */
public class RtcWhiteboardImpl extends RtcWhiteboardBaseImpl implements DingRtcEngineWhiteboard {
    private static final String TAG = RtcWhiteboardImpl.class.getSimpleName();
    private final RtcWhiteboardEventListener mWbEventListener;
    protected String mWhiteboardId;

    native int nativeAddImageFile(long instance, String imageUrl);

    native int nativeClearContents(long instance, boolean curPage, int mode);

    native int nativeDestroy(long instance);

    native int nativeResetVision(long instance);

    native int nativeSaveDocToThumbnails(long instance, String docId, String outputDir);

    native int nativeSetBackgroundColor(long instance, float r, float g, float b, float a);

    native int nativeSetBackgroundImage(long instance, String imageUrl, int pageNo);

    native int nativeSetBooleanOption(long instance, int option, boolean param);

    native int nativeSetEventListener(long instance, RtcWhiteboardEventListener listener);

    native int nativeSetFloatOption(long instance, int option, float param);

    native int nativeSetIntOption(long instance, int option, int param);

    native int nativeSetStringOption(long instance, int option, String param);

    native int nativeSnapshot(long instance, int mode, String outputDir);

    native int nativeStartFollowVision(long instance);

    native int nativeStartShareVision(long instance);

    native int nativeStopFollowVision(long instance);

    native int nativeStopShareVision(long instance);

    public RtcWhiteboardImpl(long nativePtr, String whiteboardId) {
        super(0, nativePtr);
        this.mWhiteboardId = whiteboardId;
        this.mWbEventListener = new RtcWhiteboardEventListener(this);
        nativeSetEventListener(getNativePtr(), this.mWbEventListener);
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int setEventListener(DingRtcEngineWhiteboardEventListener listener) {
        this.mWbEventListener.setWbEventListener(listener);
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int setIntOption(DingRtcWhiteBoardTypes.DingRtcWBOption option, int param) {
        Logging.i(TAG, "setIntOption, option: " + option.getValue() + ", param: " + param);
        synchronized (this.mWhiteBoardLock) {
            if (isNativeValid()) {
                nativeSetIntOption(getNativePtr(), option.getValue(), param);
                return 0;
            }
            return -1;
        }
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int setBooleanOption(DingRtcWhiteBoardTypes.DingRtcWBOption option, boolean param) {
        Logging.i(TAG, "setBooleanOption, option: " + option.getValue() + ", param: " + param);
        synchronized (this.mWhiteBoardLock) {
            if (!isNativeValid()) {
                return 0;
            }
            nativeSetBooleanOption(getNativePtr(), option.getValue(), param);
            return 0;
        }
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int setFloatOption(DingRtcWhiteBoardTypes.DingRtcWBOption option, float param) {
        Logging.i(TAG, "setFloatOption, option: " + option.getValue() + ", param: " + param);
        synchronized (this.mWhiteBoardLock) {
            if (!isNativeValid()) {
                return 0;
            }
            nativeSetFloatOption(getNativePtr(), option.getValue(), param);
            return 0;
        }
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int setStringOption(DingRtcWhiteBoardTypes.DingRtcWBOption option, String param) {
        Logging.i(TAG, "setStringOption, option: " + option.getValue() + ", param: " + param);
        synchronized (this.mWhiteBoardLock) {
            if (!isNativeValid()) {
                return 0;
            }
            nativeSetStringOption(getNativePtr(), option.getValue(), param);
            return 0;
        }
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int clearContents(DingRtcWhiteBoardTypes.DingRtcWBClearParam param) {
        Logging.i(TAG, "clearContents.");
        synchronized (this.mWhiteBoardLock) {
            if (isNativeValid()) {
                return nativeClearContents(getNativePtr(), param.curPage, param.mode.getValue());
            }
            return -1;
        }
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int startShareVision() {
        Logging.i(TAG, "startShareVision.");
        if (isNativeValid()) {
            return nativeStartShareVision(getNativePtr());
        }
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int stopShareVision() {
        Logging.i(TAG, "stopShareVision.");
        if (isNativeValid()) {
            return nativeStopShareVision(getNativePtr());
        }
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int startFollowVision() {
        Logging.i(TAG, "startFollowVision.");
        if (isNativeValid()) {
            return nativeStartFollowVision(getNativePtr());
        }
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int stopFollowVision() {
        Logging.i(TAG, "stopFollowVision.");
        if (isNativeValid()) {
            return nativeStopFollowVision(getNativePtr());
        }
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int resetVision() {
        Logging.i(TAG, "resetVision.");
        if (isNativeValid()) {
            return nativeResetVision(getNativePtr());
        }
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int snapshot(DingRtcWhiteBoardTypes.DingRtcWBSnapshotMode mode, String outputDir) {
        Logging.i(TAG, "snapshot.");
        if (isNativeValid()) {
            return nativeSnapshot(getNativePtr(), mode.getValue(), outputDir);
        }
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int setBackgroundColor(DingRtcWhiteBoardTypes.DingRtcWBColor color) {
        Logging.i(TAG, "setBackgroundColor.");
        if (isNativeValid()) {
            return nativeSetBackgroundColor(getNativePtr(), color.r, color.g, color.b, color.a);
        }
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int setBackgroundImage(String imageUrl, int pageNo) {
        Logging.i(TAG, "SetBackgroundImage.");
        if (isNativeValid()) {
            return nativeSetBackgroundImage(getNativePtr(), imageUrl, pageNo);
        }
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int addImageFile(String imageUrl) {
        Logging.i(TAG, "setBackgroundColor.");
        if (isNativeValid()) {
            return nativeAddImageFile(getNativePtr(), imageUrl);
        }
        return 0;
    }

    @Override // com.ding.rtc.DingRtcEngineWhiteboard
    public int saveDocToThumbnails(String docId, String outputDir) {
        Logging.i(TAG, "saveDocToThumbnails.");
        if (isNativeValid()) {
            return nativeSaveDocToThumbnails(getNativePtr(), docId, outputDir);
        }
        return 0;
    }

    @Override // com.ding.rtc.RtcWhiteboardBaseImpl, com.ding.rtc.DingRtcEngineWhiteboard
    public void destroy() {
        Logging.i(TAG, "destroy.");
        synchronized (this.mWhiteBoardLock) {
            if (checkNativeInvalid()) {
                return;
            }
            if (this.mWbEventListener != null) {
                this.mWbEventListener.setWbEventListener(null);
            }
            nativeDestroy(getNativePtr());
            super.destroy();
        }
    }

    boolean isNativeValid() {
        if (getNativePtr() == 0) {
            Log.w(TAG, "native ptr null");
            return false;
        }
        return true;
    }
}
