package p005b.p362y.p363a;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.text.TextUtils;
import android.view.Surface;
import com.shuyu.gsyvideoplayer.utils.Debuger;
import com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge;
import java.io.File;
import java.lang.ref.WeakReference;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p362y.p363a.p365e.C2923b;
import p005b.p362y.p363a.p365e.InterfaceC2922a;
import p005b.p362y.p363a.p366f.InterfaceC2925a;
import p005b.p362y.p363a.p367g.C2932a;
import p005b.p362y.p363a.p367g.C2934c;
import p005b.p362y.p363a.p368h.InterfaceC2937c;
import tv.danmaku.ijk.media.player.IMediaPlayer;

/* renamed from: b.y.a.b */
/* loaded from: classes2.dex */
public abstract class AbstractC2919b implements IMediaPlayer.OnPreparedListener, IMediaPlayer.OnCompletionListener, IMediaPlayer.OnBufferingUpdateListener, IMediaPlayer.OnSeekCompleteListener, IMediaPlayer.OnErrorListener, IMediaPlayer.OnVideoSizeChangedListener, IMediaPlayer.OnInfoListener, InterfaceC2922a.a, GSYVideoViewBridge {

    /* renamed from: a */
    public Context f7991a;

    /* renamed from: b */
    public i f7992b;

    /* renamed from: c */
    public Handler f7993c;

    /* renamed from: d */
    public WeakReference<InterfaceC2925a> f7994d;

    /* renamed from: e */
    public WeakReference<InterfaceC2925a> f7995e;

    /* renamed from: f */
    public List<C2934c> f7996f;

    /* renamed from: h */
    public InterfaceC2937c f7998h;

    /* renamed from: i */
    public InterfaceC2922a f7999i;

    /* renamed from: l */
    public int f8002l;

    /* renamed from: n */
    public int f8004n;

    /* renamed from: g */
    public String f7997g = "";

    /* renamed from: j */
    public int f8000j = 0;

    /* renamed from: k */
    public int f8001k = 0;

    /* renamed from: m */
    public int f8003m = -22;

    /* renamed from: o */
    public boolean f8005o = false;

    /* renamed from: p */
    public Runnable f8006p = new h();

    /* renamed from: b.y.a.b$a */
    public class a implements Runnable {
        public a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            Objects.requireNonNull(AbstractC2919b.this);
            Debuger.printfError("cancelTimeOutBuffer");
            if (AbstractC2919b.this.listener() != null) {
                AbstractC2919b.this.listener().onPrepared();
            }
        }
    }

    /* renamed from: b.y.a.b$b */
    public class b implements Runnable {
        public b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            Objects.requireNonNull(AbstractC2919b.this);
            Debuger.printfError("cancelTimeOutBuffer");
            if (AbstractC2919b.this.listener() != null) {
                AbstractC2919b.this.listener().onAutoCompletion();
            }
        }
    }

    /* renamed from: b.y.a.b$c */
    public class c implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ int f8009c;

        public c(int i2) {
            this.f8009c = i2;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (AbstractC2919b.this.listener() != null) {
                int i2 = this.f8009c;
                AbstractC2919b abstractC2919b = AbstractC2919b.this;
                if (i2 > abstractC2919b.f8004n) {
                    abstractC2919b.listener().onBufferingUpdate(this.f8009c);
                } else {
                    abstractC2919b.listener().onBufferingUpdate(AbstractC2919b.this.f8004n);
                }
            }
        }
    }

    /* renamed from: b.y.a.b$d */
    public class d implements Runnable {
        public d() {
        }

        @Override // java.lang.Runnable
        public void run() {
            Objects.requireNonNull(AbstractC2919b.this);
            Debuger.printfError("cancelTimeOutBuffer");
            if (AbstractC2919b.this.listener() != null) {
                AbstractC2919b.this.listener().onSeekComplete();
            }
        }
    }

    /* renamed from: b.y.a.b$e */
    public class e implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ int f8012c;

        /* renamed from: e */
        public final /* synthetic */ int f8013e;

        public e(int i2, int i3) {
            this.f8012c = i2;
            this.f8013e = i3;
        }

        @Override // java.lang.Runnable
        public void run() {
            Objects.requireNonNull(AbstractC2919b.this);
            Debuger.printfError("cancelTimeOutBuffer");
            if (AbstractC2919b.this.listener() != null) {
                AbstractC2919b.this.listener().onError(this.f8012c, this.f8013e);
            }
        }
    }

    /* renamed from: b.y.a.b$f */
    public class f implements Runnable {

        /* renamed from: c */
        public final /* synthetic */ int f8015c;

        /* renamed from: e */
        public final /* synthetic */ int f8016e;

        public f(int i2, int i3) {
            this.f8015c = i2;
            this.f8016e = i3;
        }

        @Override // java.lang.Runnable
        public void run() {
            Objects.requireNonNull(AbstractC2919b.this);
            if (AbstractC2919b.this.listener() != null) {
                AbstractC2919b.this.listener().onInfo(this.f8015c, this.f8016e);
            }
        }
    }

    /* renamed from: b.y.a.b$g */
    public class g implements Runnable {
        public g() {
        }

        @Override // java.lang.Runnable
        public void run() {
            if (AbstractC2919b.this.listener() != null) {
                AbstractC2919b.this.listener().onVideoSizeChanged();
            }
        }
    }

    /* renamed from: b.y.a.b$h */
    public class h implements Runnable {
        public h() {
        }

        @Override // java.lang.Runnable
        public void run() {
            if (AbstractC2919b.this.f7994d != null) {
                Debuger.printfError("time out for error listener");
                AbstractC2919b.this.listener().onError(-192, -192);
            }
        }
    }

    /* renamed from: b.y.a.b$i */
    public class i extends Handler {
        public i(Looper looper) {
            super(looper);
        }

        /* JADX WARN: Removed duplicated region for block: B:41:0x0083 A[Catch: Exception -> 0x00ca, TryCatch #1 {Exception -> 0x00ca, blocks: (B:30:0x0052, B:32:0x005a, B:33:0x005d, B:35:0x0061, B:38:0x0066, B:39:0x0079, B:41:0x0083, B:42:0x0086, B:44:0x008c, B:45:0x0091, B:47:0x00a4, B:48:0x00a7, B:53:0x0070, B:56:0x0075), top: B:29:0x0052, inners: #3 }] */
        /* JADX WARN: Removed duplicated region for block: B:44:0x008c A[Catch: Exception -> 0x00ca, TryCatch #1 {Exception -> 0x00ca, blocks: (B:30:0x0052, B:32:0x005a, B:33:0x005d, B:35:0x0061, B:38:0x0066, B:39:0x0079, B:41:0x0083, B:42:0x0086, B:44:0x008c, B:45:0x0091, B:47:0x00a4, B:48:0x00a7, B:53:0x0070, B:56:0x0075), top: B:29:0x0052, inners: #3 }] */
        /* JADX WARN: Removed duplicated region for block: B:47:0x00a4 A[Catch: Exception -> 0x00ca, TryCatch #1 {Exception -> 0x00ca, blocks: (B:30:0x0052, B:32:0x005a, B:33:0x005d, B:35:0x0061, B:38:0x0066, B:39:0x0079, B:41:0x0083, B:42:0x0086, B:44:0x008c, B:45:0x0091, B:47:0x00a4, B:48:0x00a7, B:53:0x0070, B:56:0x0075), top: B:29:0x0052, inners: #3 }] */
        @Override // android.os.Handler
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void handleMessage(android.os.Message r6) {
            /*
                r5 = this;
                super.handleMessage(r6)
                int r0 = r6.what
                r1 = 0
                if (r0 == 0) goto L4d
                r2 = 2
                if (r0 == r2) goto L22
                r1 = 3
                if (r0 == r1) goto L10
                goto Lce
            L10:
                b.y.a.b r0 = p005b.p362y.p363a.AbstractC2919b.this
                java.util.Objects.requireNonNull(r0)
                java.lang.Object r6 = r6.obj
                if (r6 == 0) goto Lce
                b.y.a.h.c r6 = r0.f7998h
                if (r6 == 0) goto Lce
                r6.releaseSurface()
                goto Lce
            L22:
                b.y.a.b r6 = p005b.p362y.p363a.AbstractC2919b.this
                b.y.a.h.c r6 = r6.f7998h
                if (r6 == 0) goto L2b
                r6.release()
            L2b:
                b.y.a.b r6 = p005b.p362y.p363a.AbstractC2919b.this
                b.y.a.e.a r6 = r6.f7999i
                if (r6 == 0) goto L34
                r6.release()
            L34:
                b.y.a.b r6 = p005b.p362y.p363a.AbstractC2919b.this
                r6.f8004n = r1
                r6.f8005o = r1
                b.y.a.h.c r6 = r6.f7998h
                if (r6 == 0) goto L41
                r6.setNeedMute(r1)
            L41:
                b.y.a.b r6 = p005b.p362y.p363a.AbstractC2919b.this
                java.util.Objects.requireNonNull(r6)
                java.lang.String r6 = "cancelTimeOutBuffer"
                com.shuyu.gsyvideoplayer.utils.Debuger.printfError(r6)
                goto Lce
            L4d:
                b.y.a.b r0 = p005b.p362y.p363a.AbstractC2919b.this
                java.util.Objects.requireNonNull(r0)
                r0.f8000j = r1     // Catch: java.lang.Exception -> Lca
                r0.f8001k = r1     // Catch: java.lang.Exception -> Lca
                b.y.a.h.c r1 = r0.f7998h     // Catch: java.lang.Exception -> Lca
                if (r1 == 0) goto L5d
                r1.release()     // Catch: java.lang.Exception -> Lca
            L5d:
                java.lang.Class<? extends b.y.a.h.c> r1 = p005b.p199l.p200a.p201a.p250p1.C2354n.f6089c     // Catch: java.lang.Exception -> Lca
                if (r1 != 0) goto L65
                java.lang.Class<b.y.a.h.d> r1 = p005b.p362y.p363a.p368h.C2938d.class
                p005b.p199l.p200a.p201a.p250p1.C2354n.f6089c = r1     // Catch: java.lang.Exception -> Lca
            L65:
                r1 = 0
                java.lang.Class<? extends b.y.a.h.c> r2 = p005b.p199l.p200a.p201a.p250p1.C2354n.f6089c     // Catch: java.lang.IllegalAccessException -> L6f java.lang.InstantiationException -> L74 java.lang.Exception -> Lca
                java.lang.Object r2 = r2.newInstance()     // Catch: java.lang.IllegalAccessException -> L6f java.lang.InstantiationException -> L74 java.lang.Exception -> Lca
                b.y.a.h.c r2 = (p005b.p362y.p363a.p368h.InterfaceC2937c) r2     // Catch: java.lang.IllegalAccessException -> L6f java.lang.InstantiationException -> L74 java.lang.Exception -> Lca
                goto L79
            L6f:
                r2 = move-exception
                r2.printStackTrace()     // Catch: java.lang.Exception -> Lca
                goto L78
            L74:
                r2 = move-exception
                r2.printStackTrace()     // Catch: java.lang.Exception -> Lca
            L78:
                r2 = r1
            L79:
                r0.f7998h = r2     // Catch: java.lang.Exception -> Lca
                b.y.a.e.a r2 = r0.m3392a()     // Catch: java.lang.Exception -> Lca
                r0.f7999i = r2     // Catch: java.lang.Exception -> Lca
                if (r2 == 0) goto L86
                r2.setCacheAvailableListener(r0)     // Catch: java.lang.Exception -> Lca
            L86:
                b.y.a.h.c r2 = r0.f7998h     // Catch: java.lang.Exception -> Lca
                boolean r3 = r2 instanceof p005b.p362y.p363a.p368h.AbstractC2935a     // Catch: java.lang.Exception -> Lca
                if (r3 == 0) goto L91
                b.y.a.h.a r2 = (p005b.p362y.p363a.p368h.AbstractC2935a) r2     // Catch: java.lang.Exception -> Lca
                r2.setPlayerInitSuccessListener(r1)     // Catch: java.lang.Exception -> Lca
            L91:
                b.y.a.h.c r1 = r0.f7998h     // Catch: java.lang.Exception -> Lca
                android.content.Context r2 = r0.f7991a     // Catch: java.lang.Exception -> Lca
                java.util.List<b.y.a.g.c> r3 = r0.f7996f     // Catch: java.lang.Exception -> Lca
                b.y.a.e.a r4 = r0.f7999i     // Catch: java.lang.Exception -> Lca
                r1.initVideoPlayer(r2, r6, r3, r4)     // Catch: java.lang.Exception -> Lca
                boolean r6 = r0.f8005o     // Catch: java.lang.Exception -> Lca
                r0.f8005o = r6     // Catch: java.lang.Exception -> Lca
                b.y.a.h.c r1 = r0.f7998h     // Catch: java.lang.Exception -> Lca
                if (r1 == 0) goto La7
                r1.setNeedMute(r6)     // Catch: java.lang.Exception -> Lca
            La7:
                b.y.a.h.c r6 = r0.f7998h     // Catch: java.lang.Exception -> Lca
                tv.danmaku.ijk.media.player.IMediaPlayer r6 = r6.getMediaPlayer()     // Catch: java.lang.Exception -> Lca
                r6.setOnCompletionListener(r0)     // Catch: java.lang.Exception -> Lca
                r6.setOnBufferingUpdateListener(r0)     // Catch: java.lang.Exception -> Lca
                r1 = 1
                r6.setScreenOnWhilePlaying(r1)     // Catch: java.lang.Exception -> Lca
                r6.setOnPreparedListener(r0)     // Catch: java.lang.Exception -> Lca
                r6.setOnSeekCompleteListener(r0)     // Catch: java.lang.Exception -> Lca
                r6.setOnErrorListener(r0)     // Catch: java.lang.Exception -> Lca
                r6.setOnInfoListener(r0)     // Catch: java.lang.Exception -> Lca
                r6.setOnVideoSizeChangedListener(r0)     // Catch: java.lang.Exception -> Lca
                r6.prepareAsync()     // Catch: java.lang.Exception -> Lca
                goto Lce
            Lca:
                r6 = move-exception
                r6.printStackTrace()
            Lce:
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p362y.p363a.AbstractC2919b.i.handleMessage(android.os.Message):void");
        }
    }

    /* renamed from: a */
    public InterfaceC2922a m3392a() {
        if (C2354n.f6088b == null) {
            C2354n.f6088b = C2923b.class;
        }
        try {
            return C2354n.f6088b.newInstance();
        } catch (IllegalAccessException e2) {
            e2.printStackTrace();
            return null;
        } catch (InstantiationException e3) {
            e3.printStackTrace();
            return null;
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public boolean cachePreview(Context context, File file, String str) {
        if (m3392a() != null) {
            return m3392a().cachePreview(context, file, str);
        }
        return false;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void clearCache(Context context, File file, String str) {
        InterfaceC2922a interfaceC2922a = this.f7999i;
        if (interfaceC2922a != null) {
            interfaceC2922a.clearCache(context, file, str);
        } else if (m3392a() != null) {
            m3392a().clearCache(context, file, str);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public int getBufferedPercentage() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            return interfaceC2937c.getBufferedPercentage();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public long getCurrentPosition() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            return interfaceC2937c.getCurrentPosition();
        }
        return 0L;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public int getCurrentVideoHeight() {
        return this.f8001k;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public int getCurrentVideoWidth() {
        return this.f8000j;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public long getDuration() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            return interfaceC2937c.getDuration();
        }
        return 0L;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public int getLastState() {
        return this.f8002l;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public long getNetSpeed() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            return interfaceC2937c.getNetSpeed();
        }
        return 0L;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public int getPlayPosition() {
        return this.f8003m;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public String getPlayTag() {
        return this.f7997g;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public InterfaceC2937c getPlayer() {
        return this.f7998h;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public int getRotateInfoFlag() {
        return 10001;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public int getVideoHeight() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            return interfaceC2937c.getVideoHeight();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public int getVideoSarDen() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            return interfaceC2937c.getVideoSarDen();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public int getVideoSarNum() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            return interfaceC2937c.getVideoSarNum();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public int getVideoWidth() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            return interfaceC2937c.getVideoWidth();
        }
        return 0;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public boolean isCacheFile() {
        InterfaceC2922a interfaceC2922a = this.f7999i;
        return interfaceC2922a != null && interfaceC2922a.hadCached();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public boolean isPlaying() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            return interfaceC2937c.isPlaying();
        }
        return false;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public boolean isSurfaceSupportLockCanvas() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            return interfaceC2937c.isSurfaceSupportLockCanvas();
        }
        return false;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public InterfaceC2925a lastListener() {
        WeakReference<InterfaceC2925a> weakReference = this.f7995e;
        if (weakReference == null) {
            return null;
        }
        return weakReference.get();
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public InterfaceC2925a listener() {
        WeakReference<InterfaceC2925a> weakReference = this.f7994d;
        if (weakReference == null) {
            return null;
        }
        return weakReference.get();
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer.OnBufferingUpdateListener
    public void onBufferingUpdate(IMediaPlayer iMediaPlayer, int i2) {
        this.f7993c.post(new c(i2));
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer.OnCompletionListener
    public void onCompletion(IMediaPlayer iMediaPlayer) {
        this.f7993c.post(new b());
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer.OnErrorListener
    public boolean onError(IMediaPlayer iMediaPlayer, int i2, int i3) {
        this.f7993c.post(new e(i2, i3));
        return true;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer.OnInfoListener
    public boolean onInfo(IMediaPlayer iMediaPlayer, int i2, int i3) {
        this.f7993c.post(new f(i2, i3));
        return false;
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer.OnPreparedListener
    public void onPrepared(IMediaPlayer iMediaPlayer) {
        this.f7993c.post(new a());
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer.OnSeekCompleteListener
    public void onSeekComplete(IMediaPlayer iMediaPlayer) {
        this.f7993c.post(new d());
    }

    @Override // tv.danmaku.ijk.media.player.IMediaPlayer.OnVideoSizeChangedListener
    public void onVideoSizeChanged(IMediaPlayer iMediaPlayer, int i2, int i3, int i4, int i5) {
        this.f8000j = iMediaPlayer.getVideoWidth();
        this.f8001k = iMediaPlayer.getVideoHeight();
        this.f7993c.post(new g());
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void pause() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            interfaceC2937c.pause();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void prepare(String str, Map<String, String> map, boolean z, float f2, boolean z2, File file) {
        prepare(str, map, z, f2, z2, file, null);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void releaseMediaPlayer() {
        Message message = new Message();
        message.what = 2;
        this.f7992b.sendMessage(message);
        this.f7997g = "";
        this.f8003m = -22;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void releaseSurface(Surface surface) {
        Message message = new Message();
        message.what = 3;
        message.obj = surface;
        this.f7992b.sendMessage(message);
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void seekTo(long j2) {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            interfaceC2937c.seekTo(j2);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void setCurrentVideoHeight(int i2) {
        this.f8001k = i2;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void setCurrentVideoWidth(int i2) {
        this.f8000j = i2;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void setDisplay(Surface surface) {
        Message message = new Message();
        message.what = 1;
        message.obj = surface;
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            interfaceC2937c.showDisplay(message);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void setLastListener(InterfaceC2925a interfaceC2925a) {
        if (interfaceC2925a == null) {
            this.f7995e = null;
        } else {
            this.f7995e = new WeakReference<>(interfaceC2925a);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void setLastState(int i2) {
        this.f8002l = i2;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void setListener(InterfaceC2925a interfaceC2925a) {
        if (interfaceC2925a == null) {
            this.f7994d = null;
        } else {
            this.f7994d = new WeakReference<>(interfaceC2925a);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void setPlayPosition(int i2) {
        this.f8003m = i2;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void setPlayTag(String str) {
        this.f7997g = str;
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void setSpeed(float f2, boolean z) {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            interfaceC2937c.setSpeed(f2, z);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void setSpeedPlaying(float f2, boolean z) {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            interfaceC2937c.setSpeedPlaying(f2, z);
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void start() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            interfaceC2937c.start();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void stop() {
        InterfaceC2937c interfaceC2937c = this.f7998h;
        if (interfaceC2937c != null) {
            interfaceC2937c.stop();
        }
    }

    @Override // com.shuyu.gsyvideoplayer.video.base.GSYVideoViewBridge
    public void prepare(String str, Map<String, String> map, boolean z, float f2, boolean z2, File file, String str2) {
        if (TextUtils.isEmpty(str)) {
            return;
        }
        Message message = new Message();
        message.what = 0;
        message.obj = new C2932a(str, map, z, f2, z2, file, str2);
        this.f7992b.sendMessage(message);
    }
}
