package com.jeffmony.m3u8library;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import com.jeffmony.m3u8library.listener.IVideoTransformListener;
import com.jeffmony.m3u8library.listener.IVideoTransformProgressListener;
import com.jeffmony.m3u8library.thread.VideoProcessThreadHandler;
import java.io.File;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class VideoProcessManager {
    private static volatile VideoProcessManager sInstance;

    public static VideoProcessManager getInstance() {
        if (sInstance == null) {
            synchronized (VideoProcessManager.class) {
                if (sInstance == null) {
                    sInstance = new VideoProcessManager();
                }
            }
        }
        return sInstance;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyOnMergeFailed(@NonNull final IVideoTransformListener iVideoTransformListener, final int i2) {
        VideoProcessThreadHandler.runOnUiThread(new Runnable() { // from class: com.jeffmony.m3u8library.VideoProcessManager.4
            @Override // java.lang.Runnable
            public void run() {
                IVideoTransformListener iVideoTransformListener2 = iVideoTransformListener;
                StringBuilder m586H = C1499a.m586H("mergeVideo failed, result=");
                m586H.append(i2);
                iVideoTransformListener2.onTransformFailed(new Exception(m586H.toString()));
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyOnTransformFinished(@NonNull final IVideoTransformListener iVideoTransformListener) {
        VideoProcessThreadHandler.runOnUiThread(new Runnable() { // from class: com.jeffmony.m3u8library.VideoProcessManager.3
            @Override // java.lang.Runnable
            public void run() {
                iVideoTransformListener.onTransformFinished();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyOnTransformProgress(@NonNull final IVideoTransformListener iVideoTransformListener, final float f2) {
        VideoProcessThreadHandler.runOnUiThread(new Runnable() { // from class: com.jeffmony.m3u8library.VideoProcessManager.2
            @Override // java.lang.Runnable
            public void run() {
                iVideoTransformListener.onTransformProgress(f2);
            }
        });
    }

    public void transformM3U8ToMp4(final String str, final String str2, @NonNull final IVideoTransformListener iVideoTransformListener) {
        if (TextUtils.isEmpty(str) || TextUtils.isEmpty(str2)) {
            iVideoTransformListener.onTransformFailed(new Exception("Input or output File is empty"));
        } else if (new File(str).exists()) {
            VideoProcessThreadHandler.submitRunnableTask(new Runnable() { // from class: com.jeffmony.m3u8library.VideoProcessManager.1
                @Override // java.lang.Runnable
                public void run() {
                    VideoProcessor videoProcessor = new VideoProcessor();
                    videoProcessor.setOnVideoTransformProgressListener(new IVideoTransformProgressListener() { // from class: com.jeffmony.m3u8library.VideoProcessManager.1.1
                        @Override // com.jeffmony.m3u8library.listener.IVideoTransformProgressListener
                        public void onTransformProgress(float f2) {
                            RunnableC39161 runnableC39161 = RunnableC39161.this;
                            VideoProcessManager.this.notifyOnTransformProgress(iVideoTransformListener, f2);
                        }
                    });
                    int transformVideo = videoProcessor.transformVideo(str, str2);
                    if (transformVideo == 1) {
                        VideoProcessManager.this.notifyOnTransformFinished(iVideoTransformListener);
                    } else {
                        VideoProcessManager.this.notifyOnMergeFailed(iVideoTransformListener, transformVideo);
                    }
                }
            });
        } else {
            iVideoTransformListener.onTransformFailed(new Exception("Input file is not existing"));
        }
    }
}
