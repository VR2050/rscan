package p379c.p380a.p381a;

import java.util.Objects;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.InterfaceC3104u1;

/* renamed from: c.a.a.a */
/* loaded from: classes2.dex */
public final class C2952a {

    /* renamed from: a */
    public static final C2970s f8086a = new C2970s("ZERO");

    /* renamed from: b */
    public static final Function2<Object, CoroutineContext.Element, Object> f8087b = b.f8094c;

    /* renamed from: c */
    public static final Function2<InterfaceC3104u1<?>, CoroutineContext.Element, InterfaceC3104u1<?>> f8088c = c.f8095c;

    /* renamed from: d */
    public static final Function2<C2974w, CoroutineContext.Element, C2974w> f8089d = a.f8092e;

    /* renamed from: e */
    public static final Function2<C2974w, CoroutineContext.Element, C2974w> f8090e = a.f8091c;

    /* renamed from: c.a.a.a$a */
    /* loaded from: classes.dex */
    public static final class a extends Lambda implements Function2<C2974w, CoroutineContext.Element, C2974w> {

        /* renamed from: c */
        public static final a f8091c = new a(0);

        /* renamed from: e */
        public static final a f8092e = new a(1);

        /* renamed from: f */
        public final /* synthetic */ int f8093f;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(int i2) {
            super(2);
            this.f8093f = i2;
        }

        @Override // kotlin.jvm.functions.Function2
        public final C2974w invoke(C2974w c2974w, CoroutineContext.Element element) {
            int i2 = this.f8093f;
            if (i2 == 0) {
                C2974w c2974w2 = c2974w;
                CoroutineContext.Element element2 = element;
                if (element2 instanceof InterfaceC3104u1) {
                    CoroutineContext coroutineContext = c2974w2.f8140c;
                    Object[] objArr = c2974w2.f8138a;
                    int i3 = c2974w2.f8139b;
                    c2974w2.f8139b = i3 + 1;
                    ((InterfaceC3104u1) element2).m3639C(coroutineContext, objArr[i3]);
                }
                return c2974w2;
            }
            if (i2 != 1) {
                throw null;
            }
            C2974w c2974w3 = c2974w;
            CoroutineContext.Element element3 = element;
            if (element3 instanceof InterfaceC3104u1) {
                Object m3640P = ((InterfaceC3104u1) element3).m3640P(c2974w3.f8140c);
                Object[] objArr2 = c2974w3.f8138a;
                int i4 = c2974w3.f8139b;
                c2974w3.f8139b = i4 + 1;
                objArr2[i4] = m3640P;
            }
            return c2974w3;
        }
    }

    /* renamed from: c.a.a.a$b */
    public static final class b extends Lambda implements Function2<Object, CoroutineContext.Element, Object> {

        /* renamed from: c */
        public static final b f8094c = new b();

        public b() {
            super(2);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(Object obj, CoroutineContext.Element element) {
            CoroutineContext.Element element2 = element;
            if (!(element2 instanceof InterfaceC3104u1)) {
                return obj;
            }
            if (!(obj instanceof Integer)) {
                obj = null;
            }
            Integer num = (Integer) obj;
            int intValue = num != null ? num.intValue() : 1;
            return intValue == 0 ? element2 : Integer.valueOf(intValue + 1);
        }
    }

    /* renamed from: c.a.a.a$c */
    public static final class c extends Lambda implements Function2<InterfaceC3104u1<?>, CoroutineContext.Element, InterfaceC3104u1<?>> {

        /* renamed from: c */
        public static final c f8095c = new c();

        public c() {
            super(2);
        }

        @Override // kotlin.jvm.functions.Function2
        public InterfaceC3104u1<?> invoke(InterfaceC3104u1<?> interfaceC3104u1, CoroutineContext.Element element) {
            InterfaceC3104u1<?> interfaceC3104u12 = interfaceC3104u1;
            CoroutineContext.Element element2 = element;
            if (interfaceC3104u12 != null) {
                return interfaceC3104u12;
            }
            if (!(element2 instanceof InterfaceC3104u1)) {
                element2 = null;
            }
            return (InterfaceC3104u1) element2;
        }
    }

    /* renamed from: a */
    public static final void m3412a(@NotNull CoroutineContext coroutineContext, @Nullable Object obj) {
        if (obj == f8086a) {
            return;
        }
        if (obj instanceof C2974w) {
            ((C2974w) obj).f8139b = 0;
            coroutineContext.fold(obj, f8090e);
        } else {
            Object fold = coroutineContext.fold(null, f8088c);
            Objects.requireNonNull(fold, "null cannot be cast to non-null type kotlinx.coroutines.ThreadContextElement<kotlin.Any?>");
            ((InterfaceC3104u1) fold).m3639C(coroutineContext, obj);
        }
    }

    @NotNull
    /* renamed from: b */
    public static final Object m3413b(@NotNull CoroutineContext coroutineContext) {
        Object fold = coroutineContext.fold(0, f8087b);
        Intrinsics.checkNotNull(fold);
        return fold;
    }

    @Nullable
    /* renamed from: c */
    public static final Object m3414c(@NotNull CoroutineContext coroutineContext, @Nullable Object obj) {
        if (obj == null) {
            obj = m3413b(coroutineContext);
        }
        if (obj == 0) {
            return f8086a;
        }
        if (obj instanceof Integer) {
            return coroutineContext.fold(new C2974w(coroutineContext, ((Number) obj).intValue()), f8089d);
        }
        Objects.requireNonNull(obj, "null cannot be cast to non-null type kotlinx.coroutines.ThreadContextElement<kotlin.Any?>");
        return ((InterfaceC3104u1) obj).m3640P(coroutineContext);
    }
}
