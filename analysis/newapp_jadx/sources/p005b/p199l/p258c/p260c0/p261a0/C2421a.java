package p005b.p199l.p258c.p260c0.p261a0;

import java.lang.reflect.Array;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p260c0.C2420a;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* renamed from: b.l.c.c0.a0.a */
/* loaded from: classes2.dex */
public final class C2421a<E> extends AbstractC2496z<Object> {

    /* renamed from: a */
    public static final InterfaceC2415a0 f6459a = new a();

    /* renamed from: b */
    public final Class<E> f6460b;

    /* renamed from: c */
    public final AbstractC2496z<E> f6461c;

    /* renamed from: b.l.c.c0.a0.a$a */
    public static class a implements InterfaceC2415a0 {
        @Override // p005b.p199l.p258c.InterfaceC2415a0
        /* renamed from: a */
        public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
            Type type = c2470a.getType();
            boolean z = type instanceof GenericArrayType;
            if (!z && (!(type instanceof Class) || !((Class) type).isArray())) {
                return null;
            }
            Type genericComponentType = z ? ((GenericArrayType) type).getGenericComponentType() : ((Class) type).getComponentType();
            return new C2421a(c2480j, c2480j.m2850d(C2470a.get(genericComponentType)), C2420a.m2761e(genericComponentType));
        }
    }

    public C2421a(C2480j c2480j, AbstractC2496z<E> abstractC2496z, Class<E> cls) {
        this.f6461c = new C2434n(c2480j, abstractC2496z, cls);
        this.f6460b = cls;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: b */
    public Object mo2766b(C2472a c2472a) {
        if (c2472a.mo2777Z() == EnumC2473b.NULL) {
            c2472a.mo2775V();
            return null;
        }
        ArrayList arrayList = new ArrayList();
        c2472a.mo2778b();
        while (c2472a.mo2787t()) {
            arrayList.add(this.f6461c.mo2766b(c2472a));
        }
        c2472a.mo2785o();
        int size = arrayList.size();
        Object newInstance = Array.newInstance((Class<?>) this.f6460b, size);
        for (int i2 = 0; i2 < size; i2++) {
            Array.set(newInstance, i2, arrayList.get(i2));
        }
        return newInstance;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: c */
    public void mo2767c(C2474c c2474c, Object obj) {
        if (obj == null) {
            c2474c.mo2800v();
            return;
        }
        c2474c.mo2795d();
        int length = Array.getLength(obj);
        for (int i2 = 0; i2 < length; i2++) {
            this.f6461c.mo2767c(c2474c, Array.get(obj, i2));
        }
        c2474c.mo2797o();
    }
}
