package com.shuyu.gsyvideoplayer.video.base;

import android.content.Context;
import android.view.Surface;
import java.io.File;
import java.util.Map;
import p005b.p362y.p363a.p366f.InterfaceC2925a;
import p005b.p362y.p363a.p368h.InterfaceC2937c;

/* loaded from: classes2.dex */
public interface GSYVideoViewBridge {
    boolean cachePreview(Context context, File file, String str);

    void clearCache(Context context, File file, String str);

    int getBufferedPercentage();

    long getCurrentPosition();

    int getCurrentVideoHeight();

    int getCurrentVideoWidth();

    long getDuration();

    int getLastState();

    long getNetSpeed();

    int getPlayPosition();

    String getPlayTag();

    InterfaceC2937c getPlayer();

    int getRotateInfoFlag();

    int getVideoHeight();

    int getVideoSarDen();

    int getVideoSarNum();

    int getVideoWidth();

    boolean isCacheFile();

    boolean isPlaying();

    boolean isSurfaceSupportLockCanvas();

    InterfaceC2925a lastListener();

    InterfaceC2925a listener();

    void pause();

    void prepare(String str, Map<String, String> map, boolean z, float f2, boolean z2, File file);

    void prepare(String str, Map<String, String> map, boolean z, float f2, boolean z2, File file, String str2);

    void releaseMediaPlayer();

    void releaseSurface(Surface surface);

    void seekTo(long j2);

    void setCurrentVideoHeight(int i2);

    void setCurrentVideoWidth(int i2);

    void setDisplay(Surface surface);

    void setLastListener(InterfaceC2925a interfaceC2925a);

    void setLastState(int i2);

    void setListener(InterfaceC2925a interfaceC2925a);

    void setPlayPosition(int i2);

    void setPlayTag(String str);

    void setSpeed(float f2, boolean z);

    void setSpeedPlaying(float f2, boolean z);

    void start();

    void stop();
}
