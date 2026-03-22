package p005b.p199l.p200a.p201a.p253z0;

import android.view.Surface;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArraySet;
import org.checkerframework.checker.nullness.qual.RequiresNonNull;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.C1936b0;
import p005b.p199l.p200a.p201a.C2262n0;
import p005b.p199l.p200a.p201a.C2336p0;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.InterfaceC2368q0;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1919k;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m;
import p005b.p199l.p200a.p201a.p204c1.C1944d;
import p005b.p199l.p200a.p201a.p220h1.InterfaceC2082e;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p245m1.C2258g;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2292g;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2385q;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r;
import p005b.p199l.p200a.p201a.p253z0.InterfaceC2409b;

/* renamed from: b.l.a.a.z0.a */
/* loaded from: classes.dex */
public class C2408a implements InterfaceC2368q0.a, InterfaceC2082e, InterfaceC1921m, InterfaceC2386r, InterfaceC2203z, InterfaceC2292g.a, InterfaceC2385q, InterfaceC1919k {

    /* renamed from: e */
    public final InterfaceC2346f f6403e;

    /* renamed from: h */
    public InterfaceC2368q0 f6406h;

    /* renamed from: c */
    public final CopyOnWriteArraySet<InterfaceC2409b> f6402c = new CopyOnWriteArraySet<>();

    /* renamed from: g */
    public final b f6405g = new b();

    /* renamed from: f */
    public final AbstractC2404x0.c f6404f = new AbstractC2404x0.c();

    /* renamed from: b.l.a.a.z0.a$a */
    public static final class a {

        /* renamed from: a */
        public final InterfaceC2202y.a f6407a;

        /* renamed from: b */
        public final AbstractC2404x0 f6408b;

        /* renamed from: c */
        public final int f6409c;

        public a(InterfaceC2202y.a aVar, AbstractC2404x0 abstractC2404x0, int i2) {
            this.f6407a = aVar;
            this.f6408b = abstractC2404x0;
            this.f6409c = i2;
        }
    }

    /* renamed from: b.l.a.a.z0.a$b */
    public static final class b {

        /* renamed from: d */
        @Nullable
        public a f6413d;

        /* renamed from: e */
        @Nullable
        public a f6414e;

        /* renamed from: f */
        @Nullable
        public a f6415f;

        /* renamed from: h */
        public boolean f6417h;

        /* renamed from: a */
        public final ArrayList<a> f6410a = new ArrayList<>();

        /* renamed from: b */
        public final HashMap<InterfaceC2202y.a, a> f6411b = new HashMap<>();

        /* renamed from: c */
        public final AbstractC2404x0.b f6412c = new AbstractC2404x0.b();

        /* renamed from: g */
        public AbstractC2404x0 f6416g = AbstractC2404x0.f6366a;

        /* renamed from: a */
        public final a m2709a(a aVar, AbstractC2404x0 abstractC2404x0) {
            int mo1831b = abstractC2404x0.mo1831b(aVar.f6407a.f5247a);
            if (mo1831b == -1) {
                return aVar;
            }
            return new a(aVar.f6407a, abstractC2404x0, abstractC2404x0.m2687f(mo1831b, this.f6412c).f6368b);
        }
    }

    public C2408a(InterfaceC2346f interfaceC2346f) {
        this.f6403e = interfaceC2346f;
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1919k
    /* renamed from: a */
    public void mo1267a(float f2) {
        InterfaceC2409b.a m2707i = m2707i();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onVolumeChanged(m2707i, f2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2385q
    /* renamed from: b */
    public final void mo2640b() {
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2385q
    /* renamed from: c */
    public void mo2641c(int i2, int i3) {
        InterfaceC2409b.a m2707i = m2707i();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onSurfaceSizeChanged(m2707i, i2, i3);
        }
    }

    @RequiresNonNull({"player"})
    /* renamed from: d */
    public InterfaceC2409b.a m2702d(AbstractC2404x0 abstractC2404x0, int i2, @Nullable InterfaceC2202y.a aVar) {
        long m2669b;
        if (abstractC2404x0.m2691q()) {
            aVar = null;
        }
        InterfaceC2202y.a aVar2 = aVar;
        long mo2354c = this.f6403e.mo2354c();
        boolean z = false;
        boolean z2 = abstractC2404x0 == this.f6406h.mo1375y() && i2 == this.f6406h.mo1367o();
        long j2 = 0;
        if (aVar2 == null || !aVar2.m2024a()) {
            if (z2) {
                m2669b = this.f6406h.mo1370r();
            } else if (!abstractC2404x0.m2691q()) {
                m2669b = C2399v.m2669b(abstractC2404x0.mo1835o(i2, this.f6404f, 0L).f6380i);
            }
            j2 = m2669b;
        } else {
            if (z2 && this.f6406h.mo1372u() == aVar2.f5248b && this.f6406h.mo1365m() == aVar2.f5249c) {
                z = true;
            }
            if (z) {
                m2669b = this.f6406h.getCurrentPosition();
                j2 = m2669b;
            }
        }
        return new InterfaceC2409b.a(mo2354c, abstractC2404x0, i2, aVar2, j2, this.f6406h.getCurrentPosition(), this.f6406h.mo1359f());
    }

    /* renamed from: e */
    public final InterfaceC2409b.a m2703e(@Nullable a aVar) {
        Objects.requireNonNull(this.f6406h);
        if (aVar == null) {
            int mo1367o = this.f6406h.mo1367o();
            b bVar = this.f6405g;
            a aVar2 = null;
            int i2 = 0;
            while (true) {
                if (i2 >= bVar.f6410a.size()) {
                    break;
                }
                a aVar3 = bVar.f6410a.get(i2);
                int mo1831b = bVar.f6416g.mo1831b(aVar3.f6407a.f5247a);
                if (mo1831b != -1 && bVar.f6416g.m2687f(mo1831b, bVar.f6412c).f6368b == mo1367o) {
                    if (aVar2 != null) {
                        aVar2 = null;
                        break;
                    }
                    aVar2 = aVar3;
                }
                i2++;
            }
            if (aVar2 == null) {
                AbstractC2404x0 mo1375y = this.f6406h.mo1375y();
                if (!(mo1367o < mo1375y.mo1836p())) {
                    mo1375y = AbstractC2404x0.f6366a;
                }
                return m2702d(mo1375y, mo1367o, null);
            }
            aVar = aVar2;
        }
        return m2702d(aVar.f6408b, aVar.f6409c, aVar.f6407a);
    }

    /* renamed from: f */
    public final InterfaceC2409b.a m2704f() {
        return m2703e(this.f6405g.f6414e);
    }

    /* renamed from: g */
    public final InterfaceC2409b.a m2705g(int i2, @Nullable InterfaceC2202y.a aVar) {
        Objects.requireNonNull(this.f6406h);
        if (aVar != null) {
            a aVar2 = this.f6405g.f6411b.get(aVar);
            return aVar2 != null ? m2703e(aVar2) : m2702d(AbstractC2404x0.f6366a, i2, aVar);
        }
        AbstractC2404x0 mo1375y = this.f6406h.mo1375y();
        if (!(i2 < mo1375y.mo1836p())) {
            mo1375y = AbstractC2404x0.f6366a;
        }
        return m2702d(mo1375y, i2, null);
    }

    /* renamed from: h */
    public final InterfaceC2409b.a m2706h() {
        b bVar = this.f6405g;
        return m2703e((bVar.f6410a.isEmpty() || bVar.f6416g.m2691q() || bVar.f6417h) ? null : bVar.f6410a.get(0));
    }

    /* renamed from: i */
    public final InterfaceC2409b.a m2707i() {
        return m2703e(this.f6405g.f6415f);
    }

    /* renamed from: j */
    public final void m2708j() {
        Iterator it = new ArrayList(this.f6405g.f6410a).iterator();
        while (it.hasNext()) {
            a aVar = (a) it.next();
            onMediaPeriodReleased(aVar.f6409c, aVar.f6407a);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public final void onAudioDecoderInitialized(String str, long j2, long j3) {
        InterfaceC2409b.a m2707i = m2707i();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onDecoderInitialized(m2707i, 1, str, j3);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public final void onAudioDisabled(C1944d c1944d) {
        InterfaceC2409b.a m2704f = m2704f();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onDecoderDisabled(m2704f, 1, c1944d);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public final void onAudioEnabled(C1944d c1944d) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onDecoderEnabled(m2706h, 1, c1944d);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public final void onAudioInputFormatChanged(Format format) {
        InterfaceC2409b.a m2707i = m2707i();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onDecoderInputFormatChanged(m2707i, 1, format);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public final void onAudioSessionId(int i2) {
        InterfaceC2409b.a m2707i = m2707i();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onAudioSessionId(m2707i, i2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m
    public final void onAudioSinkUnderrun(int i2, long j2, long j3) {
        InterfaceC2409b.a m2707i = m2707i();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onAudioUnderrun(m2707i, i2, j2, j3);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public final void onDownstreamFormatChanged(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.c cVar) {
        InterfaceC2409b.a m2705g = m2705g(i2, aVar);
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onDownstreamFormatChanged(m2705g, cVar);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public final void onDroppedFrames(int i2, long j2) {
        InterfaceC2409b.a m2704f = m2704f();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onDroppedVideoFrames(m2704f, i2, j2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onIsPlayingChanged(boolean z) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onIsPlayingChanged(m2706h, z);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public final void onLoadCanceled(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
        InterfaceC2409b.a m2705g = m2705g(i2, aVar);
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onLoadCanceled(m2705g, bVar, cVar);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public final void onLoadCompleted(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
        InterfaceC2409b.a m2705g = m2705g(i2, aVar);
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onLoadCompleted(m2705g, bVar, cVar);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public final void onLoadError(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar, IOException iOException, boolean z) {
        InterfaceC2409b.a m2705g = m2705g(i2, aVar);
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onLoadError(m2705g, bVar, cVar, iOException, z);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public final void onLoadStarted(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.b bVar, InterfaceC2203z.c cVar) {
        InterfaceC2409b.a m2705g = m2705g(i2, aVar);
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onLoadStarted(m2705g, bVar, cVar);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public final void onLoadingChanged(boolean z) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onLoadingChanged(m2706h, z);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public final void onMediaPeriodCreated(int i2, InterfaceC2202y.a aVar) {
        b bVar = this.f6405g;
        int mo1831b = bVar.f6416g.mo1831b(aVar.f5247a);
        boolean z = mo1831b != -1;
        a aVar2 = new a(aVar, z ? bVar.f6416g : AbstractC2404x0.f6366a, z ? bVar.f6416g.m2687f(mo1831b, bVar.f6412c).f6368b : i2);
        bVar.f6410a.add(aVar2);
        bVar.f6411b.put(aVar, aVar2);
        bVar.f6413d = bVar.f6410a.get(0);
        if (bVar.f6410a.size() == 1 && !bVar.f6416g.m2691q()) {
            bVar.f6414e = bVar.f6413d;
        }
        InterfaceC2409b.a m2705g = m2705g(i2, aVar);
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onMediaPeriodCreated(m2705g);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public final void onMediaPeriodReleased(int i2, InterfaceC2202y.a aVar) {
        InterfaceC2409b.a m2705g = m2705g(i2, aVar);
        b bVar = this.f6405g;
        a remove = bVar.f6411b.remove(aVar);
        boolean z = false;
        if (remove != null) {
            bVar.f6410a.remove(remove);
            a aVar2 = bVar.f6415f;
            if (aVar2 != null && aVar.equals(aVar2.f6407a)) {
                bVar.f6415f = bVar.f6410a.isEmpty() ? null : bVar.f6410a.get(0);
            }
            if (!bVar.f6410a.isEmpty()) {
                bVar.f6413d = bVar.f6410a.get(0);
            }
            z = true;
        }
        if (z) {
            Iterator<InterfaceC2409b> it = this.f6402c.iterator();
            while (it.hasNext()) {
                it.next().onMediaPeriodReleased(m2705g);
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p220h1.InterfaceC2082e
    public final void onMetadata(Metadata metadata) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onMetadata(m2706h, metadata);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public final void onPlaybackParametersChanged(C2262n0 c2262n0) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onPlaybackParametersChanged(m2706h, c2262n0);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public void onPlaybackSuppressionReasonChanged(int i2) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onPlaybackSuppressionReasonChanged(m2706h, i2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public final void onPlayerError(C1936b0 c1936b0) {
        InterfaceC2409b.a m2704f = m2704f();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onPlayerError(m2704f, c1936b0);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public final void onPlayerStateChanged(boolean z, int i2) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onPlayerStateChanged(m2706h, z, i2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public final void onPositionDiscontinuity(int i2) {
        b bVar = this.f6405g;
        bVar.f6414e = bVar.f6413d;
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onPositionDiscontinuity(m2706h, i2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public final void onReadingStarted(int i2, InterfaceC2202y.a aVar) {
        b bVar = this.f6405g;
        bVar.f6415f = bVar.f6411b.get(aVar);
        InterfaceC2409b.a m2705g = m2705g(i2, aVar);
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onReadingStarted(m2705g);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public final void onRenderedFirstFrame(@Nullable Surface surface) {
        InterfaceC2409b.a m2707i = m2707i();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onRenderedFirstFrame(m2707i, surface);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public final void onRepeatModeChanged(int i2) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onRepeatModeChanged(m2706h, i2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public final void onSeekProcessed() {
        b bVar = this.f6405g;
        if (bVar.f6417h) {
            bVar.f6417h = false;
            bVar.f6414e = bVar.f6413d;
            InterfaceC2409b.a m2706h = m2706h();
            Iterator<InterfaceC2409b> it = this.f6402c.iterator();
            while (it.hasNext()) {
                it.next().onSeekProcessed(m2706h);
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public final void onShuffleModeEnabledChanged(boolean z) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onShuffleModeChanged(m2706h, z);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public final void onTimelineChanged(AbstractC2404x0 abstractC2404x0, int i2) {
        b bVar = this.f6405g;
        for (int i3 = 0; i3 < bVar.f6410a.size(); i3++) {
            a m2709a = bVar.m2709a(bVar.f6410a.get(i3), abstractC2404x0);
            bVar.f6410a.set(i3, m2709a);
            bVar.f6411b.put(m2709a.f6407a, m2709a);
        }
        a aVar = bVar.f6415f;
        if (aVar != null) {
            bVar.f6415f = bVar.m2709a(aVar, abstractC2404x0);
        }
        bVar.f6416g = abstractC2404x0;
        bVar.f6414e = bVar.f6413d;
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onTimelineChanged(m2706h, i2);
        }
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public /* synthetic */ void onTimelineChanged(AbstractC2404x0 abstractC2404x0, Object obj, int i2) {
        C2336p0.m2295k(this, abstractC2404x0, obj, i2);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2368q0.a
    public final void onTracksChanged(TrackGroupArray trackGroupArray, C2258g c2258g) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onTracksChanged(m2706h, trackGroupArray, c2258g);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z
    public final void onUpstreamDiscarded(int i2, @Nullable InterfaceC2202y.a aVar, InterfaceC2203z.c cVar) {
        InterfaceC2409b.a m2705g = m2705g(i2, aVar);
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onUpstreamDiscarded(m2705g, cVar);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public final void onVideoDecoderInitialized(String str, long j2, long j3) {
        InterfaceC2409b.a m2707i = m2707i();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onDecoderInitialized(m2707i, 2, str, j3);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public final void onVideoDisabled(C1944d c1944d) {
        InterfaceC2409b.a m2704f = m2704f();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onDecoderDisabled(m2704f, 2, c1944d);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public final void onVideoEnabled(C1944d c1944d) {
        InterfaceC2409b.a m2706h = m2706h();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onDecoderEnabled(m2706h, 2, c1944d);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public final void onVideoInputFormatChanged(Format format) {
        InterfaceC2409b.a m2707i = m2707i();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onDecoderInputFormatChanged(m2707i, 2, format);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r
    public final void onVideoSizeChanged(int i2, int i3, int i4, float f2) {
        InterfaceC2409b.a m2707i = m2707i();
        Iterator<InterfaceC2409b> it = this.f6402c.iterator();
        while (it.hasNext()) {
            it.next().onVideoSizeChanged(m2707i, i2, i3, i4, f2);
        }
    }
}
