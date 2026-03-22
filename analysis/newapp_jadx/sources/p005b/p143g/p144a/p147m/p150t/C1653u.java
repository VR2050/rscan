package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.NonNull;
import androidx.core.util.Pools;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1591e;
import p005b.p143g.p144a.p147m.p150t.C1642j;

/* renamed from: b.g.a.m.t.u */
/* loaded from: classes.dex */
public class C1653u<Data, ResourceType, Transcode> {

    /* renamed from: a */
    public final Pools.Pool<List<Throwable>> f2310a;

    /* renamed from: b */
    public final List<? extends C1642j<Data, ResourceType, Transcode>> f2311b;

    /* renamed from: c */
    public final String f2312c;

    public C1653u(Class<Data> cls, Class<ResourceType> cls2, Class<Transcode> cls3, List<C1642j<Data, ResourceType, Transcode>> list, Pools.Pool<List<Throwable>> pool) {
        this.f2310a = pool;
        if (list.isEmpty()) {
            throw new IllegalArgumentException("Must not be empty.");
        }
        this.f2311b = list;
        StringBuilder m586H = C1499a.m586H("Failed LoadPath{");
        m586H.append(cls.getSimpleName());
        m586H.append("->");
        m586H.append(cls2.getSimpleName());
        m586H.append("->");
        m586H.append(cls3.getSimpleName());
        m586H.append("}");
        this.f2312c = m586H.toString();
    }

    /* renamed from: a */
    public InterfaceC1655w<Transcode> m956a(InterfaceC1591e<Data> interfaceC1591e, @NonNull C1582n c1582n, int i2, int i3, C1642j.a<ResourceType> aVar) {
        List<Throwable> acquire = this.f2310a.acquire();
        Objects.requireNonNull(acquire, "Argument must not be null");
        List<Throwable> list = acquire;
        try {
            int size = this.f2311b.size();
            InterfaceC1655w<Transcode> interfaceC1655w = null;
            for (int i4 = 0; i4 < size; i4++) {
                try {
                    interfaceC1655w = this.f2311b.get(i4).m925a(interfaceC1591e, i2, i3, c1582n, aVar);
                } catch (C1650r e2) {
                    list.add(e2);
                }
                if (interfaceC1655w != null) {
                    break;
                }
            }
            if (interfaceC1655w != null) {
                return interfaceC1655w;
            }
            throw new C1650r(this.f2312c, new ArrayList(list));
        } finally {
            this.f2310a.release(list);
        }
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("LoadPath{decodePaths=");
        m586H.append(Arrays.toString(this.f2311b.toArray()));
        m586H.append('}');
        return m586H.toString();
    }
}
