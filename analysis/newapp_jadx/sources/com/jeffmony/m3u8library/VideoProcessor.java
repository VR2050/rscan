package com.jeffmony.m3u8library;

import androidx.annotation.NonNull;
import com.jeffmony.m3u8library.listener.IVideoTransformProgressListener;

/* loaded from: classes2.dex */
public class VideoProcessor {
    private static volatile boolean mIsLibLoaded = false;
    private IVideoTransformProgressListener mListener;

    public VideoProcessor() {
        loadLibrariesOnce();
    }

    public static native void initFFmpegOptions();

    public static void loadLibrariesOnce() {
        synchronized (VideoProcessor.class) {
            if (!mIsLibLoaded) {
                System.loadLibrary("jeffmony");
                System.loadLibrary("avcodec");
                System.loadLibrary("avformat");
                System.loadLibrary("avutil");
                System.loadLibrary("swresample");
                System.loadLibrary("swscale");
                mIsLibLoaded = true;
                initFFmpegOptions();
            }
        }
    }

    public void invokeVideoTransformProgress(float f2) {
        IVideoTransformProgressListener iVideoTransformProgressListener = this.mListener;
        if (iVideoTransformProgressListener != null) {
            iVideoTransformProgressListener.onTransformProgress(f2);
        }
    }

    public void setOnVideoTransformProgressListener(@NonNull IVideoTransformProgressListener iVideoTransformProgressListener) {
        this.mListener = iVideoTransformProgressListener;
    }

    public native int transformVideo(String str, String str2);
}
