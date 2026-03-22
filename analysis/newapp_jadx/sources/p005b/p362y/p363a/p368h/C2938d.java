package p005b.p362y.p363a.p368h;

import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.os.Message;
import android.text.TextUtils;
import android.view.Surface;
import com.shuyu.gsyvideoplayer.utils.Debuger;
import com.shuyu.gsyvideoplayer.utils.GSYVideoType;
import com.shuyu.gsyvideoplayer.utils.RawDataSourceProvider;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import p005b.p362y.p363a.p365e.InterfaceC2922a;
import p005b.p362y.p363a.p367g.C2932a;
import p005b.p362y.p363a.p367g.C2934c;
import tv.danmaku.ijk.media.player.IMediaPlayer;
import tv.danmaku.ijk.media.player.IjkMediaPlayer;

/* renamed from: b.y.a.h.d */
/* loaded from: classes2.dex */
public class C2938d extends AbstractC2935a {

    /* renamed from: a */
    public IjkMediaPlayer f8043a;

    /* renamed from: b */
    public List<C2934c> f8044b;

    /* renamed from: c */
    public Surface f8045c;

    /* renamed from: b.y.a.h.d$a */
    public class a implements IjkMediaPlayer.OnNativeInvokeListener {
        public a(C2938d c2938d) {
        }

        @Override // tv.danmaku.ijk.media.player.IjkMediaPlayer.OnNativeInvokeListener
        public boolean onNativeInvoke(int i2, Bundle bundle) {
            return true;
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public int getBufferedPercentage() {
        return -1;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public long getCurrentPosition() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            return ijkMediaPlayer.getCurrentPosition();
        }
        return 0L;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public long getDuration() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            return ijkMediaPlayer.getDuration();
        }
        return 0L;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public IMediaPlayer getMediaPlayer() {
        return this.f8043a;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public long getNetSpeed() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            return ijkMediaPlayer.getTcpSpeed();
        }
        return 0L;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public int getVideoHeight() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            return ijkMediaPlayer.getVideoHeight();
        }
        return 0;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public int getVideoSarDen() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            return ijkMediaPlayer.getVideoSarDen();
        }
        return 1;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public int getVideoSarNum() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            return ijkMediaPlayer.getVideoSarNum();
        }
        return 1;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public int getVideoWidth() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            return ijkMediaPlayer.getVideoWidth();
        }
        return 0;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void initVideoPlayer(Context context, Message message, List<C2934c> list, InterfaceC2922a interfaceC2922a) {
        IjkMediaPlayer ijkMediaPlayer = new IjkMediaPlayer();
        this.f8043a = ijkMediaPlayer;
        ijkMediaPlayer.setAudioStreamType(3);
        this.f8043a.setOnNativeInvokeListener(new a(this));
        C2932a c2932a = (C2932a) message.obj;
        String str = c2932a.f8031a;
        try {
            if (GSYVideoType.isMediaCodec()) {
                Debuger.printfLog("enable mediaCodec");
                this.f8043a.setOption(4, "mediacodec", 1L);
                this.f8043a.setOption(4, "mediacodec-auto-rotate", 1L);
                this.f8043a.setOption(4, "mediacodec-handle-resolution-change", 1L);
            }
            if (c2932a.f8036f && interfaceC2922a != null) {
                interfaceC2922a.doCacheLogic(context, this.f8043a, str, c2932a.f8033c, c2932a.f8032b);
            } else if (TextUtils.isEmpty(str)) {
                this.f8043a.setDataSource(str, c2932a.f8033c);
            } else {
                Uri parse = Uri.parse(str);
                if (parse.getScheme().equals("android.resource")) {
                    this.f8043a.setDataSource(RawDataSourceProvider.create(context, parse));
                } else {
                    this.f8043a.setDataSource(str, c2932a.f8033c);
                }
            }
            this.f8043a.setLooping(c2932a.f8035e);
            float f2 = c2932a.f8034d;
            if (f2 != 1.0f && f2 > 0.0f) {
                this.f8043a.setSpeed(f2);
            }
            IjkMediaPlayer.native_setLogLevel(1);
            IjkMediaPlayer ijkMediaPlayer2 = this.f8043a;
            if (list != null && list.size() > 0) {
                for (C2934c c2934c : list) {
                    if (c2934c.f8038a == 0) {
                        ijkMediaPlayer2.setOption(c2934c.f8039b, c2934c.f8041d, c2934c.f8040c);
                    } else {
                        ijkMediaPlayer2.setOption(c2934c.f8039b, c2934c.f8041d, c2934c.f8042e);
                    }
                }
            }
        } catch (IOException e2) {
            e2.printStackTrace();
        }
        initSuccess(c2932a);
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public boolean isPlaying() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            return ijkMediaPlayer.isPlaying();
        }
        return false;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public boolean isSurfaceSupportLockCanvas() {
        return true;
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void pause() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            ijkMediaPlayer.pause();
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void release() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            ijkMediaPlayer.release();
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void releaseSurface() {
        if (this.f8045c != null) {
            this.f8045c = null;
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void seekTo(long j2) {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            ijkMediaPlayer.seekTo(j2);
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void setNeedMute(boolean z) {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            if (z) {
                ijkMediaPlayer.setVolume(0.0f, 0.0f);
            } else {
                ijkMediaPlayer.setVolume(1.0f, 1.0f);
            }
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void setSpeed(float f2, boolean z) {
        List<C2934c> list;
        if (f2 > 0.0f) {
            try {
                IjkMediaPlayer ijkMediaPlayer = this.f8043a;
                if (ijkMediaPlayer != null) {
                    ijkMediaPlayer.setSpeed(f2);
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            if (z) {
                C2934c c2934c = new C2934c(4, "soundtouch", 1);
                List<C2934c> list2 = this.f8044b;
                if (list2 != null) {
                    list2.add(c2934c);
                    list = list2;
                } else {
                    ArrayList arrayList = new ArrayList();
                    arrayList.add(c2934c);
                    list = arrayList;
                }
                this.f8044b = list;
            }
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void setSpeedPlaying(float f2, boolean z) {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            ijkMediaPlayer.setSpeed(f2);
            this.f8043a.setOption(4, "soundtouch", z ? 1L : 0L);
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void showDisplay(Message message) {
        IjkMediaPlayer ijkMediaPlayer;
        Object obj = message.obj;
        if (obj == null && (ijkMediaPlayer = this.f8043a) != null) {
            ijkMediaPlayer.setSurface(null);
            return;
        }
        Surface surface = (Surface) obj;
        this.f8045c = surface;
        if (this.f8043a == null || !surface.isValid()) {
            return;
        }
        this.f8043a.setSurface(surface);
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void start() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            ijkMediaPlayer.start();
        }
    }

    @Override // p005b.p362y.p363a.p368h.InterfaceC2937c
    public void stop() {
        IjkMediaPlayer ijkMediaPlayer = this.f8043a;
        if (ijkMediaPlayer != null) {
            ijkMediaPlayer.stop();
        }
    }
}
