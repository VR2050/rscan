package p005b.p006a.p007a.p008a.p017r.p018k;

import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import kotlin.jvm.JvmClassMappingKt;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.p383b2.InterfaceC3006b;
import p505n.C4984d0;
import p505n.C5030y;
import p505n.C5031z;
import p505n.InterfaceC4985e;

/* renamed from: b.a.a.a.r.k.g */
/* loaded from: classes2.dex */
public final class C0933g extends InterfaceC4985e.a {
    public C0933g(DefaultConstructorMarker defaultConstructorMarker) {
    }

    @Override // p505n.InterfaceC4985e.a
    @Nullable
    /* renamed from: a */
    public InterfaceC4985e<?, ?> mo279a(@NotNull Type returnType, @NotNull Annotation[] annotations, @NotNull C5031z retrofit) {
        Intrinsics.checkNotNullParameter(returnType, "returnType");
        Intrinsics.checkNotNullParameter(annotations, "annotations");
        Intrinsics.checkNotNullParameter(retrofit, "retrofit");
        Class<?> m5659f = C4984d0.m5659f(returnType);
        Intrinsics.checkNotNullExpressionValue(m5659f, "getRawType(returnType)");
        if (!Intrinsics.areEqual(JvmClassMappingKt.getKotlinClass(m5659f), Reflection.getOrCreateKotlinClass(InterfaceC3006b.class))) {
            return null;
        }
        if (!(returnType instanceof ParameterizedType)) {
            throw new IllegalStateException("Flow return type must be parameterized as Flow<Foo> or Flow<out Foo>".toString());
        }
        Type responseType = C4984d0.m5658e(0, (ParameterizedType) returnType);
        Class<?> rawFlowType = C4984d0.m5659f(responseType);
        Intrinsics.checkNotNullExpressionValue(rawFlowType, "rawFlowType");
        if (!Intrinsics.areEqual(JvmClassMappingKt.getKotlinClass(rawFlowType), Reflection.getOrCreateKotlinClass(C5030y.class))) {
            Intrinsics.checkNotNullExpressionValue(responseType, "responseType");
            return new C0932f(responseType);
        }
        if (!(responseType instanceof ParameterizedType)) {
            throw new IllegalStateException("Response must be parameterized as Response<Foo> or Response<out Foo>".toString());
        }
        Type m5658e = C4984d0.m5658e(0, (ParameterizedType) responseType);
        Intrinsics.checkNotNullExpressionValue(m5658e, "getParameterUpperBound(0, responseType)");
        return new C0935i(m5658e);
    }
}
