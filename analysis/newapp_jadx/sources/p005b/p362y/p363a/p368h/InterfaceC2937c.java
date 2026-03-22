package p005b.p362y.p363a.p368h;

import android.content.Context;
import android.os.Message;
import java.util.List;
import p005b.p362y.p363a.p365e.InterfaceC2922a;
import p005b.p362y.p363a.p367g.C2934c;
import tv.danmaku.ijk.media.player.IMediaPlayer;

/* renamed from: b.y.a.h.c */
/* loaded from: classes2.dex */
public interface InterfaceC2937c {
    int getBufferedPercentage();

    long getCurrentPosition();

    long getDuration();

    IMediaPlayer getMediaPlayer();

    long getNetSpeed();

    int getVideoHeight();

    int getVideoSarDen();

    int getVideoSarNum();

    int getVideoWidth();

    void initVideoPlayer(Context context, Message message, List<C2934c> list, InterfaceC2922a interfaceC2922a);

    boolean isPlaying();

    boolean isSurfaceSupportLockCanvas();

    void pause();

    void release();

    void releaseSurface();

    void seekTo(long j2);

    void setNeedMute(boolean z);

    void setSpeed(float f2, boolean z);

    void setSpeedPlaying(float f2, boolean z);

    void showDisplay(Message message);

    void start();

    void stop();
}
