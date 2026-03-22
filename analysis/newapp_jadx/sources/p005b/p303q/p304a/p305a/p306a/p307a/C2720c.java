package p005b.p303q.p304a.p305a.p306a.p307a;

import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.C3099t;
import p379c.p380a.InterfaceC3067i0;
import p505n.C4984d0;
import p505n.C5030y;
import p505n.C5031z;
import p505n.InterfaceC4983d;
import p505n.InterfaceC4985e;

/* renamed from: b.q.a.a.a.a.c */
/* loaded from: classes2.dex */
public final class C2720c extends InterfaceC4985e.a {

    /* renamed from: b.q.a.a.a.a.c$a */
    public static final class a<T> implements InterfaceC4985e<T, InterfaceC3067i0<? extends T>> {

        /* renamed from: a */
        public final Type f7392a;

        public a(@NotNull Type responseType) {
            Intrinsics.checkParameterIsNotNull(responseType, "responseType");
            this.f7392a = responseType;
        }

        @Override // p505n.InterfaceC4985e
        @NotNull
        /* renamed from: a */
        public Type mo277a() {
            return this.f7392a;
        }

        @Override // p505n.InterfaceC4985e
        /* renamed from: b */
        public Object mo278b(InterfaceC4983d call) {
            Intrinsics.checkParameterIsNotNull(call, "call");
            C3099t c3099t = new C3099t(null);
            c3099t.mo3552o(false, true, new C2718a(c3099t, call));
            call.mo5652o(new C2719b(c3099t));
            return c3099t;
        }
    }

    /* renamed from: b.q.a.a.a.a.c$b */
    public static final class b<T> implements InterfaceC4985e<T, InterfaceC3067i0<? extends C5030y<T>>> {

        /* renamed from: a */
        public final Type f7393a;

        public b(@NotNull Type responseType) {
            Intrinsics.checkParameterIsNotNull(responseType, "responseType");
            this.f7393a = responseType;
        }

        @Override // p505n.InterfaceC4985e
        @NotNull
        /* renamed from: a */
        public Type mo277a() {
            return this.f7393a;
        }

        @Override // p505n.InterfaceC4985e
        /* renamed from: b */
        public Object mo278b(InterfaceC4983d call) {
            Intrinsics.checkParameterIsNotNull(call, "call");
            C3099t c3099t = new C3099t(null);
            c3099t.mo3552o(false, true, new C2721d(c3099t, call));
            call.mo5652o(new C2722e(c3099t));
            return c3099t;
        }
    }

    public C2720c(DefaultConstructorMarker defaultConstructorMarker) {
    }

    @Override // p505n.InterfaceC4985e.a
    @Nullable
    /* renamed from: a */
    public InterfaceC4985e<?, ?> mo279a(@NotNull Type returnType, @NotNull Annotation[] annotations, @NotNull C5031z retrofit) {
        Intrinsics.checkParameterIsNotNull(returnType, "returnType");
        Intrinsics.checkParameterIsNotNull(annotations, "annotations");
        Intrinsics.checkParameterIsNotNull(retrofit, "retrofit");
        if (!Intrinsics.areEqual(InterfaceC3067i0.class, C4984d0.m5659f(returnType))) {
            return null;
        }
        if (!(returnType instanceof ParameterizedType)) {
            throw new IllegalStateException("Deferred return type must be parameterized as Deferred<Foo> or Deferred<out Foo>");
        }
        Type responseType = C4984d0.m5658e(0, (ParameterizedType) returnType);
        if (!Intrinsics.areEqual(C4984d0.m5659f(responseType), C5030y.class)) {
            Intrinsics.checkExpressionValueIsNotNull(responseType, "responseType");
            return new a(responseType);
        }
        if (!(responseType instanceof ParameterizedType)) {
            throw new IllegalStateException("Response must be parameterized as Response<Foo> or Response<out Foo>");
        }
        Type m5658e = C4984d0.m5658e(0, (ParameterizedType) responseType);
        Intrinsics.checkExpressionValueIsNotNull(m5658e, "getParameterUpperBound(0, responseType)");
        return new b(m5658e);
    }
}
