package p379c.p380a.p381a;

import java.util.concurrent.CancellationException;
import kotlin.Result;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.JvmField;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3091q0;
import p379c.p380a.C3107v1;
import p379c.p380a.C3111x;
import p379c.p380a.InterfaceC3053d1;

/* renamed from: c.a.a.g */
/* loaded from: classes2.dex */
public final class C2958g {

    /* renamed from: a */
    public static final C2970s f8108a = new C2970s("UNDEFINED");

    /* renamed from: b */
    @JvmField
    @NotNull
    public static final C2970s f8109b = new C2970s("REUSABLE_CLAIMED");

    /* renamed from: a */
    public static final <T> void m3421a(@NotNull Continuation<? super T> continuation, @NotNull Object obj, @Nullable Function1<? super Throwable, Unit> function1) {
        boolean z;
        if (!(continuation instanceof C2957f)) {
            continuation.resumeWith(obj);
            return;
        }
        C2957f c2957f = (C2957f) continuation;
        Object m2448Y1 = C2354n.m2448Y1(obj, function1);
        if (c2957f.f8106k.isDispatchNeeded(c2957f.get$context())) {
            c2957f.f8103h = m2448Y1;
            c2957f.f8428f = 1;
            c2957f.f8106k.dispatch(c2957f.get$context(), c2957f);
            return;
        }
        C3107v1 c3107v1 = C3107v1.f8468b;
        AbstractC3091q0 m3642a = C3107v1.m3642a();
        if (m3642a.m3630Y()) {
            c2957f.f8103h = m2448Y1;
            c2957f.f8428f = 1;
            m3642a.m3628W(c2957f);
            return;
        }
        m3642a.m3629X(true);
        try {
            InterfaceC3053d1 interfaceC3053d1 = (InterfaceC3053d1) c2957f.get$context().get(InterfaceC3053d1.f8393b);
            if (interfaceC3053d1 == null || interfaceC3053d1.mo3507b()) {
                z = false;
            } else {
                CancellationException mo3553q = interfaceC3053d1.mo3553q();
                if (m2448Y1 instanceof C3111x) {
                    ((C3111x) m2448Y1).f8474b.invoke(mo3553q);
                }
                Result.Companion companion = Result.INSTANCE;
                c2957f.resumeWith(Result.m6055constructorimpl(ResultKt.createFailure(mo3553q)));
                z = true;
            }
            if (!z) {
                CoroutineContext coroutineContext = c2957f.get$context();
                Object m3414c = C2952a.m3414c(coroutineContext, c2957f.f8105j);
                try {
                    c2957f.f8107l.resumeWith(obj);
                    Unit unit = Unit.INSTANCE;
                    C2952a.m3412a(coroutineContext, m3414c);
                } catch (Throwable th) {
                    C2952a.m3412a(coroutineContext, m3414c);
                    throw th;
                }
            }
            while (m3642a.m3632a0()) {
            }
        } finally {
            try {
            } finally {
            }
        }
    }

    /* renamed from: b */
    public static /* synthetic */ void m3422b(Continuation continuation, Object obj, Function1 function1, int i2) {
        int i3 = i2 & 2;
        m3421a(continuation, obj, null);
    }
}
