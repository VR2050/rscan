package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.NonNull;
import androidx.core.util.Pools;
import java.util.Objects;
import p005b.p143g.p144a.p170s.p171j.AbstractC1811d;
import p005b.p143g.p144a.p170s.p171j.C1808a;

/* renamed from: b.g.a.m.t.v */
/* loaded from: classes.dex */
public final class C1654v<Z> implements InterfaceC1655w<Z>, C1808a.d {

    /* renamed from: c */
    public static final Pools.Pool<C1654v<?>> f2313c = C1808a.m1153a(20, new a());

    /* renamed from: e */
    public final AbstractC1811d f2314e = new AbstractC1811d.b();

    /* renamed from: f */
    public InterfaceC1655w<Z> f2315f;

    /* renamed from: g */
    public boolean f2316g;

    /* renamed from: h */
    public boolean f2317h;

    /* renamed from: b.g.a.m.t.v$a */
    public class a implements C1808a.b<C1654v<?>> {
        @Override // p005b.p143g.p144a.p170s.p171j.C1808a.b
        public C1654v<?> create() {
            return new C1654v<>();
        }
    }

    @NonNull
    /* renamed from: c */
    public static <Z> C1654v<Z> m957c(InterfaceC1655w<Z> interfaceC1655w) {
        C1654v<Z> c1654v = (C1654v) f2313c.acquire();
        Objects.requireNonNull(c1654v, "Argument must not be null");
        c1654v.f2317h = false;
        c1654v.f2316g = true;
        c1654v.f2315f = interfaceC1655w;
        return c1654v;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    /* renamed from: a */
    public Class<Z> mo947a() {
        return this.f2315f.mo947a();
    }

    @Override // p005b.p143g.p144a.p170s.p171j.C1808a.d
    @NonNull
    /* renamed from: b */
    public AbstractC1811d mo903b() {
        return this.f2314e;
    }

    /* renamed from: d */
    public synchronized void m958d() {
        this.f2314e.mo1155a();
        if (!this.f2316g) {
            throw new IllegalStateException("Already unlocked");
        }
        this.f2316g = false;
        if (this.f2317h) {
            recycle();
        }
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    @NonNull
    public Z get() {
        return this.f2315f.get();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public int getSize() {
        return this.f2315f.getSize();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1655w
    public synchronized void recycle() {
        this.f2314e.mo1155a();
        this.f2317h = true;
        if (!this.f2316g) {
            this.f2315f.recycle();
            this.f2315f = null;
            f2313c.release(this);
        }
    }
}
