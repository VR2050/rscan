package tv.danmaku.ijk.media.exo2;

import android.content.Context;
import android.net.TrafficStats;
import android.net.Uri;
import android.os.Message;
import android.view.Surface;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.video.DummySurface;
import java.util.List;
import java.util.Map;
import p005b.p199l.p200a.p201a.C2400v0;
import p005b.p362y.p363a.p365e.InterfaceC2922a;
import p005b.p362y.p363a.p367g.C2932a;
import p005b.p362y.p363a.p367g.C2934c;
import p005b.p362y.p363a.p368h.AbstractC2935a;
import tv.danmaku.ijk.media.player.IMediaPlayer;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* loaded from: classes3.dex */
public class Exo2PlayerManager extends AbstractC2935a {
    private Context context;
    private DummySurface dummySurface;
    private IjkExo2MediaPlayer mediaPlayer;
    private Surface surface;
    private long lastTotalRxBytes = 0;
    private long lastTimeStamp = 0;

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public int getBufferedPercentage() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            return ijkExo2MediaPlayer.getBufferedPercentage();
        }
        return 0;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public long getCurrentPosition() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            return ijkExo2MediaPlayer.getCurrentPosition();
        }
        return 0L;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public long getDuration() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            return ijkExo2MediaPlayer.getDuration();
        }
        return 0L;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public IMediaPlayer getMediaPlayer() {
        return this.mediaPlayer;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public long getNetSpeed() {
        if (this.mediaPlayer != null) {
            return getNetSpeed(this.context);
        }
        return 0L;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public int getVideoHeight() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            return ijkExo2MediaPlayer.getVideoHeight();
        }
        return 0;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public int getVideoSarDen() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            return ijkExo2MediaPlayer.getVideoSarDen();
        }
        return 1;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public int getVideoSarNum() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            return ijkExo2MediaPlayer.getVideoSarNum();
        }
        return 1;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public int getVideoWidth() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            return ijkExo2MediaPlayer.getVideoWidth();
        }
        return 0;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void initVideoPlayer(Context context, Message message, List<C2934c> list, InterfaceC2922a interfaceC2922a) {
        this.context = context.getApplicationContext();
        IjkExo2MediaPlayer ijkExo2MediaPlayer = new IjkExo2MediaPlayer(context);
        this.mediaPlayer = ijkExo2MediaPlayer;
        ijkExo2MediaPlayer.setAudioStreamType(3);
        boolean z = false;
        if (this.dummySurface == null) {
            this.dummySurface = DummySurface.m4130k(context, false);
        }
        C2932a c2932a = (C2932a) message.obj;
        try {
            this.mediaPlayer.setLooping(c2932a.f8035e);
            IjkExo2MediaPlayer ijkExo2MediaPlayer2 = this.mediaPlayer;
            Map<String, String> map = c2932a.f8033c;
            if (map != null && map.size() > 0) {
                z = true;
            }
            ijkExo2MediaPlayer2.setPreview(z);
            boolean z2 = c2932a.f8036f;
            if (!z2 || interfaceC2922a == null) {
                this.mediaPlayer.setCache(z2);
                this.mediaPlayer.setCacheDir(c2932a.f8032b);
                this.mediaPlayer.setOverrideExtension(c2932a.f8037g);
                this.mediaPlayer.setDataSource(context, Uri.parse(c2932a.f8031a), c2932a.f8033c);
            } else {
                interfaceC2922a.doCacheLogic(context, this.mediaPlayer, c2932a.f8031a, c2932a.f8033c, c2932a.f8032b);
            }
            float f2 = c2932a.f8034d;
            if (f2 != 1.0f && f2 > 0.0f) {
                this.mediaPlayer.setSpeed(f2, 1.0f);
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        initSuccess(c2932a);
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public boolean isPlaying() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            return ijkExo2MediaPlayer.isPlaying();
        }
        return false;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public boolean isSurfaceSupportLockCanvas() {
        return false;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void pause() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            ijkExo2MediaPlayer.pause();
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void release() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            ijkExo2MediaPlayer.setSurface(null);
            this.mediaPlayer.release();
        }
        DummySurface dummySurface = this.dummySurface;
        if (dummySurface != null) {
            dummySurface.release();
            this.dummySurface = null;
        }
        this.lastTotalRxBytes = 0L;
        this.lastTimeStamp = 0L;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void releaseSurface() {
        if (this.surface != null) {
            this.surface = null;
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void seekTo(long j2) {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            ijkExo2MediaPlayer.seekTo(j2);
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void setNeedMute(boolean z) {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            if (z) {
                ijkExo2MediaPlayer.setVolume(0.0f, 0.0f);
            } else {
                ijkExo2MediaPlayer.setVolume(1.0f, 1.0f);
            }
        }
    }

    public void setSeekParameter(@Nullable C2400v0 c2400v0) {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            ijkExo2MediaPlayer.setSeekParameter(c2400v0);
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void setSpeed(float f2, boolean z) {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            try {
                ijkExo2MediaPlayer.setSpeed(f2, 1.0f);
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void setSpeedPlaying(float f2, boolean z) {
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void showDisplay(Message message) {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer == null) {
            return;
        }
        Object obj = message.obj;
        if (obj == null) {
            ijkExo2MediaPlayer.setSurface(this.dummySurface);
            return;
        }
        Surface surface = (Surface) obj;
        this.surface = surface;
        ijkExo2MediaPlayer.setSurface(surface);
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void start() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            ijkExo2MediaPlayer.start();
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void stop() {
        IjkExo2MediaPlayer ijkExo2MediaPlayer = this.mediaPlayer;
        if (ijkExo2MediaPlayer != null) {
            ijkExo2MediaPlayer.stop();
        }
    }

    private long getNetSpeed(Context context) {
        if (context == null) {
            return 0L;
        }
        long totalRxBytes = TrafficStats.getUidRxBytes(context.getApplicationInfo().uid) == -1 ? 0L : TrafficStats.getTotalRxBytes() / IjkMediaMeta.AV_CH_SIDE_RIGHT;
        long currentTimeMillis = System.currentTimeMillis();
        long j2 = currentTimeMillis - this.lastTimeStamp;
        if (j2 == 0) {
            return j2;
        }
        long j3 = ((totalRxBytes - this.lastTotalRxBytes) * 1000) / j2;
        this.lastTimeStamp = currentTimeMillis;
        this.lastTotalRxBytes = totalRxBytes;
        return j3;
    }
}
