package com.google.android.exoplayer2.video;

import android.graphics.SurfaceTexture;

/* JADX INFO: loaded from: classes2.dex */
public interface VideoListener {
    void onRenderedFirstFrame();

    boolean onSurfaceDestroyed(SurfaceTexture surfaceTexture);

    void onSurfaceSizeChanged(int i, int i2);

    void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture);

    void onVideoSizeChanged(int i, int i2, int i3, float f);

    /* JADX INFO: renamed from: com.google.android.exoplayer2.video.VideoListener$-CC, reason: invalid class name */
    public final /* synthetic */ class CC {
        public static void $default$onVideoSizeChanged(VideoListener _this, int width, int height, int unappliedRotationDegrees, float pixelWidthHeightRatio) {
        }

        public static void $default$onSurfaceSizeChanged(VideoListener _this, int width, int height) {
        }

        public static void $default$onRenderedFirstFrame(VideoListener _this) {
        }
    }
}
