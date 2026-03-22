package p005b.p143g.p144a.p147m.p148s;

import androidx.annotation.NonNull;
import java.util.HashMap;
import java.util.Map;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1591e;

/* renamed from: b.g.a.m.s.f */
/* loaded from: classes.dex */
public class C1592f {

    /* renamed from: a */
    public static final InterfaceC1591e.a<?> f2006a = new a();

    /* renamed from: b */
    public final Map<Class<?>, InterfaceC1591e.a<?>> f2007b = new HashMap();

    /* renamed from: b.g.a.m.s.f$a */
    public class a implements InterfaceC1591e.a<Object> {
        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e.a
        @NonNull
        /* renamed from: a */
        public Class<Object> mo843a() {
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e.a
        @NonNull
        /* renamed from: b */
        public InterfaceC1591e<Object> mo844b(@NonNull Object obj) {
            return new b(obj);
        }
    }

    /* renamed from: b.g.a.m.s.f$b */
    public static final class b implements InterfaceC1591e<Object> {

        /* renamed from: a */
        public final Object f2008a;

        public b(@NonNull Object obj) {
            this.f2008a = obj;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e
        @NonNull
        /* renamed from: a */
        public Object mo841a() {
            return this.f2008a;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e
        /* renamed from: b */
        public void mo842b() {
        }
    }
}
