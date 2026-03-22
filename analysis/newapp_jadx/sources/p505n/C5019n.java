package p505n;

import java.lang.reflect.Method;
import java.util.Objects;
import kotlin.KotlinNullPointerException;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.InterfaceC3066i;
import p458k.C4381g0;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: n.n */
/* loaded from: classes3.dex */
public final class C5019n<T> implements InterfaceC5011f<T> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3066i f12836a;

    public C5019n(InterfaceC3066i interfaceC3066i) {
        this.f12836a = interfaceC3066i;
    }

    @Override // p505n.InterfaceC5011f
    /* renamed from: a */
    public void mo275a(@NotNull InterfaceC4983d<T> call, @NotNull Throwable t) {
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(t, "t");
        InterfaceC3066i interfaceC3066i = this.f12836a;
        Result.Companion companion = Result.INSTANCE;
        interfaceC3066i.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(t)));
    }

    @Override // p505n.InterfaceC5011f
    /* renamed from: b */
    public void mo276b(@NotNull InterfaceC4983d<T> call, @NotNull C5030y<T> response) {
        Intrinsics.checkParameterIsNotNull(call, "call");
        Intrinsics.checkParameterIsNotNull(response, "response");
        if (!response.m5685a()) {
            InterfaceC3066i interfaceC3066i = this.f12836a;
            C5015j c5015j = new C5015j(response);
            Result.Companion companion = Result.INSTANCE;
            interfaceC3066i.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(c5015j)));
            return;
        }
        T t = response.f12958b;
        if (t != null) {
            InterfaceC3066i interfaceC3066i2 = this.f12836a;
            Result.Companion companion2 = Result.INSTANCE;
            interfaceC3066i2.resumeWith(Result.m6055constructorimpl(t));
            return;
        }
        C4381g0 mo5651e = call.mo5651e();
        Objects.requireNonNull(mo5651e);
        Intrinsics.checkParameterIsNotNull(C5017l.class, "type");
        Object cast = C5017l.class.cast(mo5651e.f11444f.get(C5017l.class));
        if (cast == null) {
            Intrinsics.throwNpe();
        }
        Intrinsics.checkExpressionValueIsNotNull(cast, "call.request().tag(Invocation::class.java)!!");
        Method method = ((C5017l) cast).f12833a;
        StringBuilder sb = new StringBuilder();
        sb.append("Response from ");
        Intrinsics.checkExpressionValueIsNotNull(method, "method");
        Class<?> declaringClass = method.getDeclaringClass();
        Intrinsics.checkExpressionValueIsNotNull(declaringClass, "method.declaringClass");
        sb.append(declaringClass.getName());
        sb.append('.');
        sb.append(method.getName());
        sb.append(" was null but response body type was declared as non-null");
        KotlinNullPointerException kotlinNullPointerException = new KotlinNullPointerException(sb.toString());
        InterfaceC3066i interfaceC3066i3 = this.f12836a;
        Result.Companion companion3 = Result.INSTANCE;
        interfaceC3066i3.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(kotlinNullPointerException)));
    }
}
