package p379c.p380a.p386z1;

import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import androidx.annotation.VisibleForTesting;
import java.util.Objects;
import kotlin.Result;
import kotlin.ResultKt;
import org.jetbrains.annotations.NotNull;

/* renamed from: c.a.z1.c */
/* loaded from: classes2.dex */
public final class C3121c {
    static {
        Object m6055constructorimpl;
        try {
            Result.Companion companion = Result.INSTANCE;
            m6055constructorimpl = Result.m6055constructorimpl(new C3119a(m3643a(Looper.getMainLooper(), true), null, false));
        } catch (Throwable th) {
            Result.Companion companion2 = Result.INSTANCE;
            m6055constructorimpl = Result.m6055constructorimpl(ResultKt.createFailure(th));
        }
    }

    @VisibleForTesting
    @NotNull
    /* renamed from: a */
    public static final Handler m3643a(@NotNull Looper looper, boolean z) {
        if (!z) {
            return new Handler(looper);
        }
        if (Build.VERSION.SDK_INT < 28) {
            try {
                return (Handler) Handler.class.getDeclaredConstructor(Looper.class, Handler.Callback.class, Boolean.TYPE).newInstance(looper, null, Boolean.TRUE);
            } catch (NoSuchMethodException unused) {
                return new Handler(looper);
            }
        }
        Object invoke = Handler.class.getDeclaredMethod("createAsync", Looper.class).invoke(null, looper);
        Objects.requireNonNull(invoke, "null cannot be cast to non-null type android.os.Handler");
        return (Handler) invoke;
    }
}
