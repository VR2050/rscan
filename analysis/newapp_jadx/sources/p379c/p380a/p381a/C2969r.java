package p379c.p380a.p381a;

import kotlin.Result;
import kotlin.ResultKt;

/* renamed from: c.a.a.r */
/* loaded from: classes2.dex */
public final class C2969r {

    /* renamed from: a */
    public static final String f8133a;

    /* renamed from: b */
    public static final String f8134b;

    static {
        Object m6055constructorimpl;
        Object m6055constructorimpl2;
        try {
            Result.Companion companion = Result.INSTANCE;
            m6055constructorimpl = Result.m6055constructorimpl(Class.forName("kotlin.coroutines.jvm.internal.BaseContinuationImpl").getCanonicalName());
        } catch (Throwable th) {
            Result.Companion companion2 = Result.INSTANCE;
            m6055constructorimpl = Result.m6055constructorimpl(ResultKt.createFailure(th));
        }
        if (Result.m6058exceptionOrNullimpl(m6055constructorimpl) != null) {
            m6055constructorimpl = "kotlin.coroutines.jvm.internal.BaseContinuationImpl";
        }
        f8133a = (String) m6055constructorimpl;
        try {
            Result.Companion companion3 = Result.INSTANCE;
            m6055constructorimpl2 = Result.m6055constructorimpl(Class.forName("c.a.a.r").getCanonicalName());
        } catch (Throwable th2) {
            Result.Companion companion4 = Result.INSTANCE;
            m6055constructorimpl2 = Result.m6055constructorimpl(ResultKt.createFailure(th2));
        }
        if (Result.m6058exceptionOrNullimpl(m6055constructorimpl2) != null) {
            m6055constructorimpl2 = "kotlinx.coroutines.internal.StackTraceRecoveryKt";
        }
        f8134b = (String) m6055constructorimpl2;
    }
}
