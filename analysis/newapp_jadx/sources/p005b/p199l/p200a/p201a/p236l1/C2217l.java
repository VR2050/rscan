package p005b.p199l.p200a.p201a.p236l1;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p200a.p201a.AbstractC2397u;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2213h;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2357q;

/* renamed from: b.l.a.a.l1.l */
/* loaded from: classes.dex */
public final class C2217l extends AbstractC2397u implements Handler.Callback {

    /* renamed from: A */
    public int f5294A;

    /* renamed from: o */
    @Nullable
    public final Handler f5295o;

    /* renamed from: p */
    public final InterfaceC2216k f5296p;

    /* renamed from: q */
    public final InterfaceC2213h f5297q;

    /* renamed from: r */
    public final C1964f0 f5298r;

    /* renamed from: s */
    public boolean f5299s;

    /* renamed from: t */
    public boolean f5300t;

    /* renamed from: u */
    public int f5301u;

    /* renamed from: v */
    @Nullable
    public Format f5302v;

    /* renamed from: w */
    @Nullable
    public InterfaceC2211f f5303w;

    /* renamed from: x */
    @Nullable
    public C2214i f5304x;

    /* renamed from: y */
    @Nullable
    public AbstractC2215j f5305y;

    /* renamed from: z */
    @Nullable
    public AbstractC2215j f5306z;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2217l(InterfaceC2216k interfaceC2216k, @Nullable Looper looper) {
        super(3);
        Handler handler;
        InterfaceC2213h interfaceC2213h = InterfaceC2213h.f5290a;
        Objects.requireNonNull(interfaceC2216k);
        this.f5296p = interfaceC2216k;
        if (looper == null) {
            handler = null;
        } else {
            int i2 = C2344d0.f6035a;
            handler = new Handler(looper, this);
        }
        this.f5295o = handler;
        this.f5297q = interfaceC2213h;
        this.f5298r = new C1964f0();
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: C */
    public void mo1303C(Format[] formatArr, long j2) {
        Format format = formatArr[0];
        this.f5302v = format;
        if (this.f5303w != null) {
            this.f5301u = 1;
        } else {
            this.f5303w = ((InterfaceC2213h.a) this.f5297q).m2052a(format);
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: E */
    public int mo1661E(Format format) {
        Objects.requireNonNull((InterfaceC2213h.a) this.f5297q);
        String str = format.f9245l;
        if ("text/vtt".equals(str) || "text/x-ssa".equals(str) || "application/ttml+xml".equals(str) || "application/x-mp4-vtt".equals(str) || "application/x-subrip".equals(str) || "application/x-quicktime-tx3g".equals(str) || "application/cea-608".equals(str) || "application/x-mp4-cea-608".equals(str) || "application/cea-708".equals(str) || "application/dvbsubs".equals(str) || "application/pgs".equals(str)) {
            return (AbstractC2397u.m2664F(null, format.f9248o) ? 4 : 2) | 0 | 0;
        }
        return C2357q.m2546i(format.f9245l) ? 1 : 0;
    }

    /* renamed from: H */
    public final void m2053H() {
        List<C2207b> emptyList = Collections.emptyList();
        Handler handler = this.f5295o;
        if (handler != null) {
            handler.obtainMessage(0, emptyList).sendToTarget();
        } else {
            this.f5296p.onCues(emptyList);
        }
    }

    /* renamed from: I */
    public final long m2054I() {
        int i2 = this.f5294A;
        if (i2 != -1) {
            InterfaceC2210e interfaceC2210e = this.f5305y.f5292c;
            Objects.requireNonNull(interfaceC2210e);
            if (i2 < interfaceC2210e.mo2051d()) {
                AbstractC2215j abstractC2215j = this.f5305y;
                int i3 = this.f5294A;
                InterfaceC2210e interfaceC2210e2 = abstractC2215j.f5292c;
                Objects.requireNonNull(interfaceC2210e2);
                return interfaceC2210e2.mo2049b(i3) + abstractC2215j.f5293e;
            }
        }
        return Long.MAX_VALUE;
    }

    /* renamed from: J */
    public final void m2055J() {
        this.f5304x = null;
        this.f5294A = -1;
        AbstractC2215j abstractC2215j = this.f5305y;
        if (abstractC2215j != null) {
            abstractC2215j.release();
            this.f5305y = null;
        }
        AbstractC2215j abstractC2215j2 = this.f5306z;
        if (abstractC2215j2 != null) {
            abstractC2215j2.release();
            this.f5306z = null;
        }
    }

    /* renamed from: K */
    public final void m2056K() {
        m2055J();
        this.f5303w.release();
        this.f5303w = null;
        this.f5301u = 0;
        this.f5303w = ((InterfaceC2213h.a) this.f5297q).m2052a(this.f5302v);
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: c */
    public boolean mo1314c() {
        return this.f5300t;
    }

    @Override // android.os.Handler.Callback
    public boolean handleMessage(Message message) {
        if (message.what != 0) {
            throw new IllegalStateException();
        }
        this.f5296p.onCues((List) message.obj);
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    public boolean isReady() {
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: j */
    public void mo1680j(long j2, long j3) {
        boolean z;
        if (this.f5300t) {
            return;
        }
        if (this.f5306z == null) {
            this.f5303w.mo2046a(j2);
            try {
                this.f5306z = this.f5303w.mo1377b();
            } catch (C2212g e2) {
                throw m2666u(e2, this.f5302v);
            }
        }
        if (this.f6318h != 2) {
            return;
        }
        if (this.f5305y != null) {
            long m2054I = m2054I();
            z = false;
            while (m2054I <= j2) {
                this.f5294A++;
                m2054I = m2054I();
                z = true;
            }
        } else {
            z = false;
        }
        AbstractC2215j abstractC2215j = this.f5306z;
        if (abstractC2215j != null) {
            if (abstractC2215j.isEndOfStream()) {
                if (!z && m2054I() == Long.MAX_VALUE) {
                    if (this.f5301u == 2) {
                        m2056K();
                    } else {
                        m2055J();
                        this.f5300t = true;
                    }
                }
            } else if (this.f5306z.timeUs <= j2) {
                AbstractC2215j abstractC2215j2 = this.f5305y;
                if (abstractC2215j2 != null) {
                    abstractC2215j2.release();
                }
                AbstractC2215j abstractC2215j3 = this.f5306z;
                this.f5305y = abstractC2215j3;
                this.f5306z = null;
                InterfaceC2210e interfaceC2210e = abstractC2215j3.f5292c;
                Objects.requireNonNull(interfaceC2210e);
                this.f5294A = interfaceC2210e.mo2048a(j2 - abstractC2215j3.f5293e);
                z = true;
            }
        }
        if (z) {
            AbstractC2215j abstractC2215j4 = this.f5305y;
            InterfaceC2210e interfaceC2210e2 = abstractC2215j4.f5292c;
            Objects.requireNonNull(interfaceC2210e2);
            List<C2207b> mo2050c = interfaceC2210e2.mo2050c(j2 - abstractC2215j4.f5293e);
            Handler handler = this.f5295o;
            if (handler != null) {
                handler.obtainMessage(0, mo2050c).sendToTarget();
            } else {
                this.f5296p.onCues(mo2050c);
            }
        }
        if (this.f5301u == 2) {
            return;
        }
        while (!this.f5299s) {
            try {
                if (this.f5304x == null) {
                    C2214i mo1378c = this.f5303w.mo1378c();
                    this.f5304x = mo1378c;
                    if (mo1378c == null) {
                        return;
                    }
                }
                if (this.f5301u == 1) {
                    this.f5304x.setFlags(4);
                    this.f5303w.mo1379d(this.f5304x);
                    this.f5304x = null;
                    this.f5301u = 2;
                    return;
                }
                int m2665D = m2665D(this.f5298r, this.f5304x, false);
                if (m2665D == -4) {
                    if (this.f5304x.isEndOfStream()) {
                        this.f5299s = true;
                    } else {
                        C2214i c2214i = this.f5304x;
                        c2214i.f5291i = this.f5298r.f3394c.f9249p;
                        c2214i.m1382g();
                    }
                    this.f5303w.mo1379d(this.f5304x);
                    this.f5304x = null;
                } else if (m2665D == -3) {
                    return;
                }
            } catch (C2212g e3) {
                throw m2666u(e3, this.f5302v);
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: w */
    public void mo1325w() {
        this.f5302v = null;
        m2053H();
        m2055J();
        this.f5303w.release();
        this.f5303w = null;
        this.f5301u = 0;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: y */
    public void mo1327y(long j2, boolean z) {
        m2053H();
        this.f5299s = false;
        this.f5300t = false;
        if (this.f5301u != 0) {
            m2056K();
        } else {
            m2055J();
            this.f5303w.flush();
        }
    }
}
