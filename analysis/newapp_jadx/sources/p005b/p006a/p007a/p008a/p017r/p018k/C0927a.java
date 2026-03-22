package p005b.p006a.p007a.p008a.p017r.p018k;

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.p264d0.C2470a;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;
import p505n.C5031z;
import p505n.InterfaceC5013h;

/* renamed from: b.a.a.a.r.k.a */
/* loaded from: classes2.dex */
public final class C0927a extends InterfaceC5013h.a {

    /* renamed from: a */
    @NotNull
    public final Lazy f445a = LazyKt__LazyJVMKt.lazy(a.f446c);

    /* renamed from: b.a.a.a.r.k.a$a */
    public static final class a extends Lambda implements Function0<C2480j> {

        /* renamed from: c */
        public static final a f446c = new a();

        public a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public C2480j invoke() {
            return new C2480j();
        }
    }

    /* renamed from: a */
    public final C2480j m274a() {
        return (C2480j) this.f445a.getValue();
    }

    @Override // p505n.InterfaceC5013h.a
    @NotNull
    public InterfaceC5013h<?, AbstractC4387j0> requestBodyConverter(@NotNull Type type, @NotNull Annotation[] parameterAnnotations, @NotNull Annotation[] methodAnnotations, @NotNull C5031z retrofit) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(parameterAnnotations, "parameterAnnotations");
        Intrinsics.checkNotNullParameter(methodAnnotations, "methodAnnotations");
        Intrinsics.checkNotNullParameter(retrofit, "retrofit");
        AbstractC2496z m2850d = m274a().m2850d(C2470a.get(type));
        Intrinsics.checkNotNullExpressionValue(m2850d, "gson.getAdapter(TypeToken.get(type))");
        return new C0929c(m274a(), m2850d);
    }

    @Override // p505n.InterfaceC5013h.a
    @NotNull
    public InterfaceC5013h<AbstractC4393m0, ?> responseBodyConverter(@NotNull Type type, @NotNull Annotation[] annotations, @NotNull C5031z retrofit) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(annotations, "annotations");
        Intrinsics.checkNotNullParameter(retrofit, "retrofit");
        AbstractC2496z m2850d = m274a().m2850d(C2470a.get(type));
        Intrinsics.checkNotNullExpressionValue(m2850d, "gson.getAdapter(TypeToken.get(type))");
        return new C0930d(m2850d, type);
    }
}
