package p005b.p199l.p258c.p260c0;

import java.lang.reflect.Constructor;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentNavigableMap;
import p005b.p199l.p258c.InterfaceC2481k;
import p005b.p199l.p258c.p260c0.p263b0.AbstractC2443b;
import p005b.p199l.p258c.p264d0.C2470a;

/* renamed from: b.l.c.c0.g */
/* loaded from: classes2.dex */
public final class C2449g {

    /* renamed from: a */
    public final Map<Type, InterfaceC2481k<?>> f6590a;

    /* renamed from: b */
    public final AbstractC2443b f6591b = AbstractC2443b.f6583a;

    /* JADX INFO: Add missing generic type declarations: [T] */
    /* renamed from: b.l.c.c0.g$a */
    public class a<T> implements InterfaceC2462t<T> {

        /* renamed from: a */
        public final /* synthetic */ InterfaceC2481k f6592a;

        /* renamed from: b */
        public final /* synthetic */ Type f6593b;

        public a(C2449g c2449g, InterfaceC2481k interfaceC2481k, Type type) {
            this.f6592a = interfaceC2481k;
            this.f6593b = type;
        }

        @Override // p005b.p199l.p258c.p260c0.InterfaceC2462t
        /* renamed from: a */
        public T mo2810a() {
            return (T) this.f6592a.m2857a(this.f6593b);
        }
    }

    /* JADX INFO: Add missing generic type declarations: [T] */
    /* renamed from: b.l.c.c0.g$b */
    public class b<T> implements InterfaceC2462t<T> {

        /* renamed from: a */
        public final /* synthetic */ InterfaceC2481k f6594a;

        /* renamed from: b */
        public final /* synthetic */ Type f6595b;

        public b(C2449g c2449g, InterfaceC2481k interfaceC2481k, Type type) {
            this.f6594a = interfaceC2481k;
            this.f6595b = type;
        }

        @Override // p005b.p199l.p258c.p260c0.InterfaceC2462t
        /* renamed from: a */
        public T mo2810a() {
            return (T) this.f6594a.m2857a(this.f6595b);
        }
    }

    public C2449g(Map<Type, InterfaceC2481k<?>> map) {
        this.f6590a = map;
    }

    /* renamed from: a */
    public <T> InterfaceC2462t<T> m2812a(C2470a<T> c2470a) {
        C2450h c2450h;
        Type type = c2470a.getType();
        Class<? super T> rawType = c2470a.getRawType();
        InterfaceC2481k<?> interfaceC2481k = this.f6590a.get(type);
        if (interfaceC2481k != null) {
            return new a(this, interfaceC2481k, type);
        }
        InterfaceC2481k<?> interfaceC2481k2 = this.f6590a.get(rawType);
        if (interfaceC2481k2 != null) {
            return new b(this, interfaceC2481k2, type);
        }
        InterfaceC2462t<T> interfaceC2462t = null;
        try {
            Constructor<? super T> declaredConstructor = rawType.getDeclaredConstructor(new Class[0]);
            if (!declaredConstructor.isAccessible()) {
                this.f6591b.mo2811a(declaredConstructor);
            }
            c2450h = new C2450h(this, declaredConstructor);
        } catch (NoSuchMethodException unused) {
            c2450h = null;
        }
        if (c2450h != null) {
            return c2450h;
        }
        if (Collection.class.isAssignableFrom(rawType)) {
            interfaceC2462t = SortedSet.class.isAssignableFrom(rawType) ? new C2451i<>(this) : EnumSet.class.isAssignableFrom(rawType) ? new C2452j<>(this, type) : Set.class.isAssignableFrom(rawType) ? new C2453k<>(this) : Queue.class.isAssignableFrom(rawType) ? new C2454l<>(this) : new C2455m<>(this);
        } else if (Map.class.isAssignableFrom(rawType)) {
            interfaceC2462t = ConcurrentNavigableMap.class.isAssignableFrom(rawType) ? new C2456n<>(this) : ConcurrentMap.class.isAssignableFrom(rawType) ? new C2441b<>(this) : SortedMap.class.isAssignableFrom(rawType) ? new C2445c<>(this) : (!(type instanceof ParameterizedType) || String.class.isAssignableFrom(C2470a.get(((ParameterizedType) type).getActualTypeArguments()[0]).getRawType())) ? new C2447e<>(this) : new C2446d<>(this);
        }
        return interfaceC2462t != null ? interfaceC2462t : new C2448f(this, rawType, type);
    }

    public String toString() {
        return this.f6590a.toString();
    }
}
