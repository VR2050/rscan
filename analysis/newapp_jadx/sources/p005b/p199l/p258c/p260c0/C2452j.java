package p005b.p199l.p258c.p260c0;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.EnumSet;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p258c.C2486p;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: b.l.c.c0.j */
/* loaded from: classes2.dex */
public class C2452j<T> implements InterfaceC2462t<T> {

    /* renamed from: a */
    public final /* synthetic */ Type f6597a;

    public C2452j(C2449g c2449g, Type type) {
        this.f6597a = type;
    }

    @Override // p005b.p199l.p258c.p260c0.InterfaceC2462t
    /* renamed from: a */
    public T mo2810a() {
        Type type = this.f6597a;
        if (!(type instanceof ParameterizedType)) {
            StringBuilder m586H = C1499a.m586H("Invalid EnumSet type: ");
            m586H.append(this.f6597a.toString());
            throw new C2486p(m586H.toString());
        }
        Type type2 = ((ParameterizedType) type).getActualTypeArguments()[0];
        if (type2 instanceof Class) {
            return (T) EnumSet.noneOf((Class) type2);
        }
        StringBuilder m586H2 = C1499a.m586H("Invalid EnumSet type: ");
        m586H2.append(this.f6597a.toString());
        throw new C2486p(m586H2.toString());
    }
}
