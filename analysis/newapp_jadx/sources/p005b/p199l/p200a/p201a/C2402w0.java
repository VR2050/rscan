package p005b.p199l.p200a.p201a;

import android.graphics.Rect;
import android.graphics.SurfaceTexture;
import android.os.Handler;
import android.os.Looper;
import android.view.Surface;
import android.view.SurfaceHolder;
import android.view.TextureView;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArraySet;
import p005b.p199l.p200a.p201a.AbstractC2395t;
import p005b.p199l.p200a.p201a.C2391r;
import p005b.p199l.p200a.p201a.C2393s;
import p005b.p199l.p200a.p201a.InterfaceC2368q0;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1919k;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m;
import p005b.p199l.p200a.p201a.p204c1.C1944d;
import p005b.p199l.p200a.p201a.p220h1.InterfaceC2082e;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2216k;
import p005b.p199l.p200a.p201a.p245m1.C2258g;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2380l;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2382n;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2385q;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r;
import p005b.p199l.p200a.p201a.p251q1.p252s.InterfaceC2387a;
import p005b.p199l.p200a.p201a.p253z0.C2408a;
import p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.w0 */
/* loaded from: classes.dex */
public class C2402w0 extends AbstractC2395t implements InterfaceC2368q0, InterfaceC2368q0.c, InterfaceC2368q0.b {

    /* renamed from: A */
    @Nullable
    public InterfaceC2382n f6336A;

    /* renamed from: B */
    @Nullable
    public InterfaceC2387a f6337B;

    /* renamed from: C */
    public boolean f6338C;

    /* renamed from: D */
    public boolean f6339D;

    /* renamed from: b */
    public final InterfaceC2396t0[] f6340b;

    /* renamed from: c */
    public final C1940c0 f6341c;

    /* renamed from: d */
    public final Handler f6342d;

    /* renamed from: e */
    public final b f6343e;

    /* renamed from: f */
    public final CopyOnWriteArraySet<InterfaceC2385q> f6344f;

    /* renamed from: g */
    public final CopyOnWriteArraySet<InterfaceC1919k> f6345g;

    /* renamed from: h */
    public final CopyOnWriteArraySet<InterfaceC2216k> f6346h;

    /* renamed from: i */
    public final CopyOnWriteArraySet<InterfaceC2082e> f6347i;

    /* renamed from: j */
    public final CopyOnWriteArraySet<InterfaceC2386r> f6348j;

    /* renamed from: k */
    public final CopyOnWriteArraySet<InterfaceC1921m> f6349k;

    /* renamed from: l */
    public final InterfaceC2292g f6350l;

    /* renamed from: m */
    public final C2408a f6351m;

    /* renamed from: n */
    public final C2391r f6352n;

    /* renamed from: o */
    public final C2393s f6353o;

    /* renamed from: p */
    public final C2406y0 f6354p;

    /* renamed from: q */
    @Nullable
    public Surface f6355q;

    /* renamed from: r */
    public boolean f6356r;

    /* renamed from: s */
    @Nullable
    public SurfaceHolder f6357s;

    /* renamed from: t */
    @Nullable
    public TextureView f6358t;

    /* renamed from: u */
    public int f6359u;

    /* renamed from: v */
    public int f6360v;

    /* renamed from: w */
    public int f6361w;

    /* renamed from: x */
    public float f6362x;

    /* renamed from: y */
    @Nullable
    public InterfaceC2202y f6363y;

    /* renamed from: z */
    public List<C2207b> f6364z;

    /* renamed from: b.l.a.a.w0$b */
    public final class b implements InterfaceC2386r, InterfaceC1921m, InterfaceC2216k, InterfaceC2082e, SurfaceHolder.Callback, TextureView.SurfaceTextureListener, C2393s.b, C2391r.b, InterfaceC2368q0.a {
        public b(a aVar) {
        }

        /* renamed from: a */
        public void m2685a(int i2) {
            C2402w0 c2402w0 = C2402w0.this;
            c2402w0.m2683T(c2402w0.mo1361h(), i2);
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
        public void onAudioDecoderInitialized(String str, long j2, long j3) {
            Iterator<InterfaceC1921m> it = C2402w0.this.f6349k.iterator();
            while (it.hasNext()) {
                it.next().onAudioDecoderInitialized(str, j2, j3);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
        public void onAudioDisabled(C1944d c1944d) {
            Iterator<InterfaceC1921m> it = C2402w0.this.f6349k.iterator();
            while (it.hasNext()) {
                it.next().onAudioDisabled(c1944d);
            }
            Objects.requireNonNull(C2402w0.this);
            Objects.requireNonNull(C2402w0.this);
            C2402w0.this.f6361w = 0;
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
        public void onAudioEnabled(C1944d c1944d) {
            Objects.requireNonNull(C2402w0.this);
            Iterator<InterfaceC1921m> it = C2402w0.this.f6349k.iterator();
            while (it.hasNext()) {
                it.next().onAudioEnabled(c1944d);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
        public void onAudioInputFormatChanged(Format format) {
            Objects.requireNonNull(C2402w0.this);
            Iterator<InterfaceC1921m> it = C2402w0.this.f6349k.iterator();
            while (it.hasNext()) {
                it.next().onAudioInputFormatChanged(format);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
        public void onAudioSessionId(int i2) {
            C2402w0 c2402w0 = C2402w0.this;
            if (c2402w0.f6361w == i2) {
                return;
            }
            c2402w0.f6361w = i2;
            Iterator<InterfaceC1919k> it = c2402w0.f6345g.iterator();
            while (it.hasNext()) {
                InterfaceC1919k next = it.next();
                if (!C2402w0.this.f6349k.contains(next)) {
                    next.onAudioSessionId(i2);
                }
            }
            Iterator<InterfaceC1921m> it2 = C2402w0.this.f6349k.iterator();
            while (it2.hasNext()) {
                it2.next().onAudioSessionId(i2);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
        public void onAudioSinkUnderrun(int i2, long j2, long j3) {
            Iterator<InterfaceC1921m> it = C2402w0.this.f6349k.iterator();
            while (it.hasNext()) {
                it.next().onAudioSinkUnderrun(i2, j2, j3);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2216k
        public void onCues(List<C2207b> list) {
            C2402w0 c2402w0 = C2402w0.this;
            c2402w0.f6364z = list;
            Iterator<InterfaceC2216k> it = c2402w0.f6346h.iterator();
            while (it.hasNext()) {
                it.next().onCues(list);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
        public void onDroppedFrames(int i2, long j2) {
            Iterator<InterfaceC2386r> it = C2402w0.this.f6348j.iterator();
            while (it.hasNext()) {
                it.next().onDroppedFrames(i2, j2);
            }
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onIsPlayingChanged(boolean z) {
            C2336p0.m2285a(this, z);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public void onLoadingChanged(boolean z) {
            Objects.requireNonNull(C2402w0.this);
        }

        @Override // p005b.p199l.p200a.p201a.p220h1.InterfaceC2082e
        public void onMetadata(Metadata metadata) {
            Iterator<InterfaceC2082e> it = C2402w0.this.f6347i.iterator();
            while (it.hasNext()) {
                it.next().onMetadata(metadata);
            }
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onPlaybackParametersChanged(C2262n0 c2262n0) {
            C2336p0.m2287c(this, c2262n0);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onPlaybackSuppressionReasonChanged(int i2) {
            C2336p0.m2288d(this, i2);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onPlayerError(C1936b0 c1936b0) {
            C2336p0.m2289e(this, c1936b0);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public void onPlayerStateChanged(boolean z, int i2) {
            if (i2 != 1) {
                if (i2 == 2 || i2 == 3) {
                    C2402w0.this.f6354p.f6395a = z;
                    return;
                } else if (i2 != 4) {
                    return;
                }
            }
            C2402w0.this.f6354p.f6395a = false;
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onPositionDiscontinuity(int i2) {
            C2336p0.m2290f(this, i2);
        }

        @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
        public void onRenderedFirstFrame(Surface surface) {
            C2402w0 c2402w0 = C2402w0.this;
            if (c2402w0.f6355q == surface) {
                Iterator<InterfaceC2385q> it = c2402w0.f6344f.iterator();
                while (it.hasNext()) {
                    it.next().mo2640b();
                }
            }
            Iterator<InterfaceC2386r> it2 = C2402w0.this.f6348j.iterator();
            while (it2.hasNext()) {
                it2.next().onRenderedFirstFrame(surface);
            }
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onRepeatModeChanged(int i2) {
            C2336p0.m2291g(this, i2);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onSeekProcessed() {
            C2336p0.m2292h(this);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onShuffleModeEnabledChanged(boolean z) {
            C2336p0.m2293i(this, z);
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureAvailable(SurfaceTexture surfaceTexture, int i2, int i3) {
            C2402w0.this.m2680Q(new Surface(surfaceTexture), true);
            C2402w0.this.m2672I(i2, i3);
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public boolean onSurfaceTextureDestroyed(SurfaceTexture surfaceTexture) {
            C2402w0.this.m2680Q(null, true);
            C2402w0.this.m2672I(0, 0);
            return true;
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureSizeChanged(SurfaceTexture surfaceTexture, int i2, int i3) {
            C2402w0.this.m2672I(i2, i3);
        }

        @Override // android.view.TextureView.SurfaceTextureListener
        public void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onTimelineChanged(AbstractC2404x0 abstractC2404x0, int i2) {
            C2336p0.m2294j(this, abstractC2404x0, i2);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onTimelineChanged(AbstractC2404x0 abstractC2404x0, Object obj, int i2) {
            C2336p0.m2295k(this, abstractC2404x0, obj, i2);
        }

        @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
        public /* synthetic */ void onTracksChanged(TrackGroupArray trackGroupArray, C2258g c2258g) {
            C2336p0.m2296l(this, trackGroupArray, c2258g);
        }

        @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
        public void onVideoDecoderInitialized(String str, long j2, long j3) {
            Iterator<InterfaceC2386r> it = C2402w0.this.f6348j.iterator();
            while (it.hasNext()) {
                it.next().onVideoDecoderInitialized(str, j2, j3);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
        public void onVideoDisabled(C1944d c1944d) {
            Iterator<InterfaceC2386r> it = C2402w0.this.f6348j.iterator();
            while (it.hasNext()) {
                it.next().onVideoDisabled(c1944d);
            }
            Objects.requireNonNull(C2402w0.this);
            Objects.requireNonNull(C2402w0.this);
        }

        @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
        public void onVideoEnabled(C1944d c1944d) {
            Objects.requireNonNull(C2402w0.this);
            Iterator<InterfaceC2386r> it = C2402w0.this.f6348j.iterator();
            while (it.hasNext()) {
                it.next().onVideoEnabled(c1944d);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
        public void onVideoInputFormatChanged(Format format) {
            Objects.requireNonNull(C2402w0.this);
            Iterator<InterfaceC2386r> it = C2402w0.this.f6348j.iterator();
            while (it.hasNext()) {
                it.next().onVideoInputFormatChanged(format);
            }
        }

        @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
        public void onVideoSizeChanged(int i2, int i3, int i4, float f2) {
            Iterator<InterfaceC2385q> it = C2402w0.this.f6344f.iterator();
            while (it.hasNext()) {
                InterfaceC2385q next = it.next();
                if (!C2402w0.this.f6348j.contains(next)) {
                    next.onVideoSizeChanged(i2, i3, i4, f2);
                }
            }
            Iterator<InterfaceC2386r> it2 = C2402w0.this.f6348j.iterator();
            while (it2.hasNext()) {
                it2.next().onVideoSizeChanged(i2, i3, i4, f2);
            }
        }

        @Override // android.view.SurfaceHolder.Callback
        public void surfaceChanged(SurfaceHolder surfaceHolder, int i2, int i3, int i4) {
            C2402w0.this.m2672I(i3, i4);
        }

        @Override // android.view.SurfaceHolder.Callback
        public void surfaceCreated(SurfaceHolder surfaceHolder) {
            C2402w0.this.m2680Q(surfaceHolder.getSurface(), false);
        }

        @Override // android.view.SurfaceHolder.Callback
        public void surfaceDestroyed(SurfaceHolder surfaceHolder) {
            C2402w0.this.m2680Q(null, false);
            C2402w0.this.m2672I(0, 0);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0166  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x02bb  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0306  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0326  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x01be  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x017a  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0177  */
    @java.lang.Deprecated
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C2402w0(android.content.Context r29, p005b.p199l.p200a.p201a.C1906a0 r30, p005b.p199l.p200a.p201a.p245m1.AbstractC2259h r31, p005b.p199l.p200a.p201a.InterfaceC2077h0 r32, @androidx.annotation.Nullable p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e<p005b.p199l.p200a.p201a.p205d1.C1957h> r33, p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g r34, p005b.p199l.p200a.p201a.p253z0.C2408a r35, p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f r36, android.os.Looper r37) {
        /*
            Method dump skipped, instructions count: 812
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C2402w0.<init>(android.content.Context, b.l.a.a.a0, b.l.a.a.m1.h, b.l.a.a.h0, b.l.a.a.d1.e, b.l.a.a.o1.g, b.l.a.a.z0.a, b.l.a.a.p1.f, android.os.Looper):void");
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: A */
    public boolean mo1340A() {
        m2684U();
        return this.f6341c.f3263o;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: B */
    public long mo1341B() {
        m2684U();
        return this.f6341c.mo1341B();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: C */
    public C2258g mo1342C() {
        m2684U();
        return this.f6341c.f3270v.f5618j.f5665c;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: D */
    public int mo1343D(int i2) {
        m2684U();
        return this.f6341c.f3251c[i2].getTrackType();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    @Nullable
    /* renamed from: E */
    public InterfaceC2368q0.b mo1344E() {
        return this;
    }

    /* renamed from: G */
    public void m2670G() {
        m2684U();
        m2677N(null);
    }

    /* renamed from: H */
    public void m2671H(@Nullable Surface surface) {
        m2684U();
        if (surface == null || surface != this.f6355q) {
            return;
        }
        m2684U();
        m2674K();
        m2680Q(null, false);
        m2672I(0, 0);
    }

    /* renamed from: I */
    public final void m2672I(int i2, int i3) {
        if (i2 == this.f6359u && i3 == this.f6360v) {
            return;
        }
        this.f6359u = i2;
        this.f6360v = i3;
        Iterator<InterfaceC2385q> it = this.f6344f.iterator();
        while (it.hasNext()) {
            it.next().mo2641c(i2, i3);
        }
    }

    /* renamed from: J */
    public void m2673J() {
        m2684U();
        C2391r c2391r = this.f6352n;
        Objects.requireNonNull(c2391r);
        if (c2391r.f6290c) {
            c2391r.f6288a.unregisterReceiver(c2391r.f6289b);
            c2391r.f6290c = false;
        }
        this.f6353o.m2649a(true);
        this.f6354p.f6395a = false;
        C1940c0 c1940c0 = this.f6341c;
        Objects.requireNonNull(c1940c0);
        Integer.toHexString(System.identityHashCode(c1940c0));
        String str = C2344d0.f6039e;
        HashSet<String> hashSet = C1960e0.f3387a;
        synchronized (C1960e0.class) {
            String str2 = C1960e0.f3388b;
        }
        C1949d0 c1949d0 = c1940c0.f3254f;
        synchronized (c1949d0) {
            if (!c1949d0.f3364z && c1949d0.f3349k.isAlive()) {
                c1949d0.f3348j.m2299c(7);
                boolean z = false;
                while (!c1949d0.f3364z) {
                    try {
                        c1949d0.wait();
                    } catch (InterruptedException unused) {
                        z = true;
                    }
                }
                if (z) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        c1940c0.f3253e.removeCallbacksAndMessages(null);
        c1940c0.f3270v = c1940c0.m1346H(false, false, false, 1);
        m2674K();
        Surface surface = this.f6355q;
        if (surface != null) {
            if (this.f6356r) {
                surface.release();
            }
            this.f6355q = null;
        }
        InterfaceC2202y interfaceC2202y = this.f6363y;
        if (interfaceC2202y != null) {
            interfaceC2202y.mo1994d(this.f6351m);
            this.f6363y = null;
        }
        if (this.f6339D) {
            Objects.requireNonNull(null);
            throw null;
        }
        this.f6350l.mo2197d(this.f6351m);
        this.f6364z = Collections.emptyList();
    }

    /* renamed from: K */
    public final void m2674K() {
        TextureView textureView = this.f6358t;
        if (textureView != null) {
            if (textureView.getSurfaceTextureListener() == this.f6343e) {
                this.f6358t.setSurfaceTextureListener(null);
            }
            this.f6358t = null;
        }
        SurfaceHolder surfaceHolder = this.f6357s;
        if (surfaceHolder != null) {
            surfaceHolder.removeCallback(this.f6343e);
            this.f6357s = null;
        }
    }

    /* renamed from: L */
    public final void m2675L() {
        float f2 = this.f6362x * this.f6353o.f6308e;
        for (InterfaceC2396t0 interfaceC2396t0 : this.f6340b) {
            if (interfaceC2396t0.getTrackType() == 1) {
                C2392r0 m1345G = this.f6341c.m1345G(interfaceC2396t0);
                m1345G.m2648e(2);
                m1345G.m2647d(Float.valueOf(f2));
                m1345G.m2646c();
            }
        }
    }

    /* renamed from: M */
    public void m2676M(@Nullable final C2262n0 c2262n0) {
        m2684U();
        C1940c0 c1940c0 = this.f6341c;
        Objects.requireNonNull(c1940c0);
        if (c2262n0 == null) {
            c2262n0 = C2262n0.f5668a;
        }
        if (c1940c0.f3268t.equals(c2262n0)) {
            return;
        }
        c1940c0.f3267s++;
        c1940c0.f3268t = c2262n0;
        c1940c0.f3254f.f3348j.m2298b(4, c2262n0).sendToTarget();
        c1940c0.m1347J(new AbstractC2395t.b() { // from class: b.l.a.a.n
            @Override // p005b.p199l.p200a.p201a.AbstractC2395t.b
            /* renamed from: a */
            public final void mo1338a(InterfaceC2368q0.a aVar) {
                aVar.onPlaybackParametersChanged(C2262n0.this);
            }
        });
    }

    /* renamed from: N */
    public final void m2677N(@Nullable InterfaceC2380l interfaceC2380l) {
        for (InterfaceC2396t0 interfaceC2396t0 : this.f6340b) {
            if (interfaceC2396t0.getTrackType() == 2) {
                C2392r0 m1345G = this.f6341c.m1345G(interfaceC2396t0);
                m1345G.m2648e(8);
                C4195m.m4771I(!m1345G.f6301h);
                m1345G.f6298e = interfaceC2380l;
                m1345G.m2646c();
            }
        }
    }

    /* renamed from: O */
    public void m2678O(@Nullable Surface surface) {
        m2684U();
        m2674K();
        if (surface != null) {
            m2670G();
        }
        m2680Q(surface, false);
        int i2 = surface != null ? -1 : 0;
        m2672I(i2, i2);
    }

    /* renamed from: P */
    public void m2679P(@Nullable SurfaceHolder surfaceHolder) {
        m2684U();
        m2674K();
        if (surfaceHolder != null) {
            m2670G();
        }
        this.f6357s = surfaceHolder;
        if (surfaceHolder == null) {
            m2680Q(null, false);
            m2672I(0, 0);
            return;
        }
        surfaceHolder.addCallback(this.f6343e);
        Surface surface = surfaceHolder.getSurface();
        if (surface == null || !surface.isValid()) {
            m2680Q(null, false);
            m2672I(0, 0);
        } else {
            m2680Q(surface, false);
            Rect surfaceFrame = surfaceHolder.getSurfaceFrame();
            m2672I(surfaceFrame.width(), surfaceFrame.height());
        }
    }

    /* renamed from: Q */
    public final void m2680Q(@Nullable Surface surface, boolean z) {
        ArrayList arrayList = new ArrayList();
        for (InterfaceC2396t0 interfaceC2396t0 : this.f6340b) {
            if (interfaceC2396t0.getTrackType() == 2) {
                C2392r0 m1345G = this.f6341c.m1345G(interfaceC2396t0);
                m1345G.m2648e(1);
                C4195m.m4771I(true ^ m1345G.f6301h);
                m1345G.f6298e = surface;
                m1345G.m2646c();
                arrayList.add(m1345G);
            }
        }
        Surface surface2 = this.f6355q;
        if (surface2 != null && surface2 != surface) {
            try {
                Iterator it = arrayList.iterator();
                while (it.hasNext()) {
                    C2392r0 c2392r0 = (C2392r0) it.next();
                    synchronized (c2392r0) {
                        C4195m.m4771I(c2392r0.f6301h);
                        C4195m.m4771I(c2392r0.f6299f.getLooper().getThread() != Thread.currentThread());
                        while (!c2392r0.f6303j) {
                            c2392r0.wait();
                        }
                    }
                }
            } catch (InterruptedException unused) {
                Thread.currentThread().interrupt();
            }
            if (this.f6356r) {
                this.f6355q.release();
            }
        }
        this.f6355q = surface;
        this.f6356r = z;
    }

    /* renamed from: R */
    public void m2681R(@Nullable TextureView textureView) {
        m2684U();
        m2674K();
        if (textureView != null) {
            m2670G();
        }
        this.f6358t = textureView;
        if (textureView == null) {
            m2680Q(null, true);
            m2672I(0, 0);
            return;
        }
        textureView.getSurfaceTextureListener();
        textureView.setSurfaceTextureListener(this.f6343e);
        SurfaceTexture surfaceTexture = textureView.isAvailable() ? textureView.getSurfaceTexture() : null;
        if (surfaceTexture == null) {
            m2680Q(null, true);
            m2672I(0, 0);
        } else {
            m2680Q(new Surface(surfaceTexture), true);
            m2672I(textureView.getWidth(), textureView.getHeight());
        }
    }

    /* renamed from: S */
    public void m2682S(boolean z) {
        m2684U();
        this.f6341c.m1352O(z);
        InterfaceC2202y interfaceC2202y = this.f6363y;
        if (interfaceC2202y != null) {
            interfaceC2202y.mo1994d(this.f6351m);
            this.f6351m.m2708j();
            if (z) {
                this.f6363y = null;
            }
        }
        this.f6353o.m2649a(true);
        this.f6364z = Collections.emptyList();
    }

    /* renamed from: T */
    public final void m2683T(boolean z, int i2) {
        int i3 = 0;
        boolean z2 = z && i2 != -1;
        if (z2 && i2 != 1) {
            i3 = 1;
        }
        this.f6341c.m1350M(z2, i3);
    }

    /* renamed from: U */
    public final void m2684U() {
        if (Looper.myLooper() != mo1376z()) {
            if (!this.f6338C) {
                new IllegalStateException();
            }
            this.f6338C = true;
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: a */
    public int mo1354a() {
        m2684U();
        return this.f6341c.f3270v.f5614f;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: b */
    public C2262n0 mo1355b() {
        m2684U();
        return this.f6341c.f3268t;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: c */
    public boolean mo1356c() {
        m2684U();
        return this.f6341c.mo1356c();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: d */
    public void mo1357d(int i2) {
        m2684U();
        this.f6341c.mo1357d(i2);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: e */
    public int mo1358e() {
        m2684U();
        return this.f6341c.f3262n;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: f */
    public long mo1359f() {
        m2684U();
        return C2399v.m2669b(this.f6341c.f3270v.f5621m);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: g */
    public void mo1360g(int i2, long j2) {
        m2684U();
        C2408a c2408a = this.f6351m;
        if (!c2408a.f6405g.f6417h) {
            InterfaceC2409b.a m2706h = c2408a.m2706h();
            c2408a.f6405g.f6417h = true;
            Iterator<InterfaceC2409b> it = c2408a.f6402c.iterator();
            while (it.hasNext()) {
                it.next().onSeekStarted(m2706h);
            }
        }
        this.f6341c.mo1360g(i2, j2);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    public long getCurrentPosition() {
        m2684U();
        return this.f6341c.getCurrentPosition();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    public long getDuration() {
        m2684U();
        return this.f6341c.getDuration();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: h */
    public boolean mo1361h() {
        m2684U();
        return this.f6341c.f3260l;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: i */
    public void mo1362i(boolean z) {
        m2684U();
        this.f6341c.mo1362i(z);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    @Nullable
    /* renamed from: j */
    public C1936b0 mo1363j() {
        m2684U();
        return this.f6341c.f3270v.f5615g;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: l */
    public void mo1364l(InterfaceC2368q0.a aVar) {
        m2684U();
        this.f6341c.f3256h.addIfAbsent(new AbstractC2395t.a(aVar));
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: m */
    public int mo1365m() {
        m2684U();
        C1940c0 c1940c0 = this.f6341c;
        if (c1940c0.mo1356c()) {
            return c1940c0.f3270v.f5611c.f5249c;
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: n */
    public void mo1366n(InterfaceC2368q0.a aVar) {
        m2684U();
        this.f6341c.mo1366n(aVar);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: o */
    public int mo1367o() {
        m2684U();
        return this.f6341c.mo1367o();
    }

    /* JADX WARN: Code restructure failed: missing block: B:9:0x0017, code lost:
    
        if (r5 != false) goto L8;
     */
    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: p */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1368p(boolean r5) {
        /*
            r4 = this;
            r4.m2684U()
            b.l.a.a.s r0 = r4.f6353o
            int r1 = r4.mo1354a()
            java.util.Objects.requireNonNull(r0)
            r2 = -1
            if (r5 != 0) goto L14
            r1 = 0
            r0.m2649a(r1)
            goto L23
        L14:
            r3 = 1
            if (r1 != r3) goto L1b
            if (r5 == 0) goto L23
        L19:
            r2 = 1
            goto L23
        L1b:
            int r1 = r0.f6307d
            if (r1 == 0) goto L19
            r0.m2649a(r3)
            goto L19
        L23:
            r4.m2683T(r5, r2)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.C2402w0.mo1368p(boolean):void");
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    @Nullable
    /* renamed from: q */
    public InterfaceC2368q0.c mo1369q() {
        return this;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: r */
    public long mo1370r() {
        m2684U();
        return this.f6341c.mo1370r();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: t */
    public long mo1371t() {
        m2684U();
        return this.f6341c.mo1371t();
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: u */
    public int mo1372u() {
        m2684U();
        C1940c0 c1940c0 = this.f6341c;
        if (c1940c0.mo1356c()) {
            return c1940c0.f3270v.f5611c.f5248b;
        }
        return -1;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: w */
    public int mo1373w() {
        m2684U();
        return this.f6341c.f3261m;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: x */
    public TrackGroupArray mo1374x() {
        m2684U();
        return this.f6341c.f3270v.f5617i;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: y */
    public AbstractC2404x0 mo1375y() {
        m2684U();
        return this.f6341c.f3270v.f5610b;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0
    /* renamed from: z */
    public Looper mo1376z() {
        return this.f6341c.mo1376z();
    }
}
