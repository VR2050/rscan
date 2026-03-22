package p005b.p143g.p144a.p147m.p150t;

import android.os.SystemClock;
import android.util.Log;
import java.util.Collections;
import java.util.List;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.InterfaceC1572d;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1639g;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p170s.C1803e;

/* renamed from: b.g.a.m.t.b0 */
/* loaded from: classes.dex */
public class C1609b0 implements InterfaceC1639g, InterfaceC1639g.a {

    /* renamed from: c */
    public final C1640h<?> f2051c;

    /* renamed from: e */
    public final InterfaceC1639g.a f2052e;

    /* renamed from: f */
    public int f2053f;

    /* renamed from: g */
    public C1624d f2054g;

    /* renamed from: h */
    public Object f2055h;

    /* renamed from: i */
    public volatile InterfaceC1672n.a<?> f2056i;

    /* renamed from: j */
    public C1636e f2057j;

    public C1609b0(C1640h<?> c1640h, InterfaceC1639g.a aVar) {
        this.f2051c = c1640h;
        this.f2052e = aVar;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g.a
    /* renamed from: a */
    public void mo853a(InterfaceC1579k interfaceC1579k, Exception exc, InterfaceC1590d<?> interfaceC1590d, EnumC1569a enumC1569a) {
        this.f2052e.mo853a(interfaceC1579k, exc, interfaceC1590d, this.f2056i.f2383c.getDataSource());
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g
    /* renamed from: b */
    public boolean mo854b() {
        Object obj = this.f2055h;
        if (obj != null) {
            this.f2055h = null;
            int i2 = C1803e.f2759b;
            long elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
            try {
                InterfaceC1572d<X> m910e = this.f2051c.m910e(obj);
                C1638f c1638f = new C1638f(m910e, obj, this.f2051c.f2157i);
                InterfaceC1579k interfaceC1579k = this.f2056i.f2381a;
                C1640h<?> c1640h = this.f2051c;
                this.f2057j = new C1636e(interfaceC1579k, c1640h.f2162n);
                c1640h.m907b().mo894a(this.f2057j, c1638f);
                if (Log.isLoggable("SourceGenerator", 2)) {
                    String str = "Finished encoding source to cache, key: " + this.f2057j + ", data: " + obj + ", encoder: " + m910e + ", duration: " + C1803e.m1138a(elapsedRealtimeNanos);
                }
                this.f2056i.f2383c.mo835b();
                this.f2054g = new C1624d(Collections.singletonList(this.f2056i.f2381a), this.f2051c, this);
            } catch (Throwable th) {
                this.f2056i.f2383c.mo835b();
                throw th;
            }
        }
        C1624d c1624d = this.f2054g;
        if (c1624d != null && c1624d.mo854b()) {
            return true;
        }
        this.f2054g = null;
        this.f2056i = null;
        boolean z = false;
        while (!z) {
            if (!(this.f2053f < this.f2051c.m908c().size())) {
                break;
            }
            List<InterfaceC1672n.a<?>> m908c = this.f2051c.m908c();
            int i3 = this.f2053f;
            this.f2053f = i3 + 1;
            this.f2056i = m908c.get(i3);
            if (this.f2056i != null && (this.f2051c.f2164p.mo929c(this.f2056i.f2383c.getDataSource()) || this.f2051c.m912g(this.f2056i.f2383c.mo832a()))) {
                this.f2056i.f2383c.mo837d(this.f2051c.f2163o, new C1607a0(this, this.f2056i));
                z = true;
            }
        }
        return z;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g.a
    /* renamed from: c */
    public void mo855c() {
        throw new UnsupportedOperationException();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g
    public void cancel() {
        InterfaceC1672n.a<?> aVar = this.f2056i;
        if (aVar != null) {
            aVar.f2383c.cancel();
        }
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g.a
    /* renamed from: d */
    public void mo856d(InterfaceC1579k interfaceC1579k, Object obj, InterfaceC1590d<?> interfaceC1590d, EnumC1569a enumC1569a, InterfaceC1579k interfaceC1579k2) {
        this.f2052e.mo856d(interfaceC1579k, obj, interfaceC1590d, this.f2056i.f2383c.getDataSource(), interfaceC1579k);
    }
}
