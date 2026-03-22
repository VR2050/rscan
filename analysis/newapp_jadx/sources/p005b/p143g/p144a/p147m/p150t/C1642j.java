package p005b.p143g.p144a.p147m.p150t;

import android.util.Log;
import androidx.annotation.NonNull;
import androidx.core.util.Pools;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1557g;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.EnumC1571c;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.InterfaceC1585q;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1591e;
import p005b.p143g.p144a.p147m.p150t.RunnableC1641i;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p147m.p156v.p162h.InterfaceC1744e;

/* renamed from: b.g.a.m.t.j */
/* loaded from: classes.dex */
public class C1642j<DataType, ResourceType, Transcode> {

    /* renamed from: a */
    public final Class<DataType> f2217a;

    /* renamed from: b */
    public final List<? extends InterfaceC1584p<DataType, ResourceType>> f2218b;

    /* renamed from: c */
    public final InterfaceC1744e<ResourceType, Transcode> f2219c;

    /* renamed from: d */
    public final Pools.Pool<List<Throwable>> f2220d;

    /* renamed from: e */
    public final String f2221e;

    /* renamed from: b.g.a.m.t.j$a */
    public interface a<ResourceType> {
    }

    public C1642j(Class<DataType> cls, Class<ResourceType> cls2, Class<Transcode> cls3, List<? extends InterfaceC1584p<DataType, ResourceType>> list, InterfaceC1744e<ResourceType, Transcode> interfaceC1744e, Pools.Pool<List<Throwable>> pool) {
        this.f2217a = cls;
        this.f2218b = list;
        this.f2219c = interfaceC1744e;
        this.f2220d = pool;
        StringBuilder m586H = C1499a.m586H("Failed DecodePath{");
        m586H.append(cls.getSimpleName());
        m586H.append("->");
        m586H.append(cls2.getSimpleName());
        m586H.append("->");
        m586H.append(cls3.getSimpleName());
        m586H.append("}");
        this.f2221e = m586H.toString();
    }

    /* renamed from: a */
    public InterfaceC1655w<Transcode> m925a(InterfaceC1591e<DataType> interfaceC1591e, int i2, int i3, @NonNull C1582n c1582n, a<ResourceType> aVar) {
        InterfaceC1655w<ResourceType> interfaceC1655w;
        InterfaceC1586r interfaceC1586r;
        EnumC1571c enumC1571c;
        InterfaceC1579k c1636e;
        List<Throwable> acquire = this.f2220d.acquire();
        Objects.requireNonNull(acquire, "Argument must not be null");
        List<Throwable> list = acquire;
        try {
            InterfaceC1655w<ResourceType> m926b = m926b(interfaceC1591e, i2, i3, c1582n, list);
            this.f2220d.release(list);
            RunnableC1641i.b bVar = (RunnableC1641i.b) aVar;
            RunnableC1641i runnableC1641i = RunnableC1641i.this;
            EnumC1569a enumC1569a = bVar.f2198a;
            Objects.requireNonNull(runnableC1641i);
            Class<?> cls = m926b.get().getClass();
            InterfaceC1585q interfaceC1585q = null;
            if (enumC1569a != EnumC1569a.RESOURCE_DISK_CACHE) {
                InterfaceC1586r m911f = runnableC1641i.f2175c.m911f(cls);
                interfaceC1586r = m911f;
                interfaceC1655w = m911f.transform(runnableC1641i.f2182k, m926b, runnableC1641i.f2186o, runnableC1641i.f2187p);
            } else {
                interfaceC1655w = m926b;
                interfaceC1586r = null;
            }
            if (!m926b.equals(interfaceC1655w)) {
                m926b.recycle();
            }
            boolean z = false;
            if (runnableC1641i.f2175c.f2151c.f1836c.f1853d.m1069a(interfaceC1655w.mo947a()) != null) {
                interfaceC1585q = runnableC1641i.f2175c.f2151c.f1836c.f1853d.m1069a(interfaceC1655w.mo947a());
                if (interfaceC1585q == null) {
                    throw new C1557g.d(interfaceC1655w.mo947a());
                }
                enumC1571c = interfaceC1585q.mo831b(runnableC1641i.f2189r);
            } else {
                enumC1571c = EnumC1571c.NONE;
            }
            InterfaceC1585q interfaceC1585q2 = interfaceC1585q;
            C1640h<R> c1640h = runnableC1641i.f2175c;
            InterfaceC1579k interfaceC1579k = runnableC1641i.f2167A;
            List<InterfaceC1672n.a<?>> m908c = c1640h.m908c();
            int size = m908c.size();
            int i4 = 0;
            while (true) {
                if (i4 >= size) {
                    break;
                }
                if (m908c.get(i4).f2381a.equals(interfaceC1579k)) {
                    z = true;
                    break;
                }
                i4++;
            }
            InterfaceC1655w<ResourceType> interfaceC1655w2 = interfaceC1655w;
            if (runnableC1641i.f2188q.mo930d(!z, enumC1569a, enumC1571c)) {
                if (interfaceC1585q2 == null) {
                    throw new C1557g.d(interfaceC1655w.get().getClass());
                }
                int ordinal = enumC1571c.ordinal();
                if (ordinal == 0) {
                    c1636e = new C1636e(runnableC1641i.f2167A, runnableC1641i.f2183l);
                } else {
                    if (ordinal != 1) {
                        throw new IllegalArgumentException("Unknown strategy: " + enumC1571c);
                    }
                    c1636e = new C1657y(runnableC1641i.f2175c.f2151c.f1835b, runnableC1641i.f2167A, runnableC1641i.f2183l, runnableC1641i.f2186o, runnableC1641i.f2187p, interfaceC1586r, cls, runnableC1641i.f2189r);
                }
                C1654v<Z> m957c = C1654v.m957c(interfaceC1655w);
                RunnableC1641i.c<?> cVar = runnableC1641i.f2180i;
                cVar.f2200a = c1636e;
                cVar.f2201b = interfaceC1585q2;
                cVar.f2202c = m957c;
                interfaceC1655w2 = m957c;
            }
            return this.f2219c.mo1037a(interfaceC1655w2, c1582n);
        } catch (Throwable th) {
            this.f2220d.release(list);
            throw th;
        }
    }

    @NonNull
    /* renamed from: b */
    public final InterfaceC1655w<ResourceType> m926b(InterfaceC1591e<DataType> interfaceC1591e, int i2, int i3, @NonNull C1582n c1582n, List<Throwable> list) {
        int size = this.f2218b.size();
        InterfaceC1655w<ResourceType> interfaceC1655w = null;
        for (int i4 = 0; i4 < size; i4++) {
            InterfaceC1584p<DataType, ResourceType> interfaceC1584p = this.f2218b.get(i4);
            try {
                if (interfaceC1584p.mo829a(interfaceC1591e.mo841a(), c1582n)) {
                    interfaceC1655w = interfaceC1584p.mo830b(interfaceC1591e.mo841a(), i2, i3, c1582n);
                }
            } catch (IOException | OutOfMemoryError | RuntimeException e2) {
                if (Log.isLoggable("DecodePath", 2)) {
                    String str = "Failed to decode data for " + interfaceC1584p;
                }
                list.add(e2);
            }
            if (interfaceC1655w != null) {
                break;
            }
        }
        if (interfaceC1655w != null) {
            return interfaceC1655w;
        }
        throw new C1650r(this.f2221e, new ArrayList(list));
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("DecodePath{ dataClass=");
        m586H.append(this.f2217a);
        m586H.append(", decoders=");
        m586H.append(this.f2218b);
        m586H.append(", transcoder=");
        m586H.append(this.f2219c);
        m586H.append('}');
        return m586H.toString();
    }
}
