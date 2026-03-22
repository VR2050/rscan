package p379c.p380a;

import java.util.concurrent.CancellationException;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.e1 */
/* loaded from: classes2.dex */
public final class C3056e1 extends CancellationException {

    /* renamed from: c */
    @JvmField
    @NotNull
    public final InterfaceC3053d1 f8397c;

    public C3056e1(@NotNull String str, @Nullable Throwable th, @NotNull InterfaceC3053d1 interfaceC3053d1) {
        super(str);
        this.f8397c = interfaceC3053d1;
        if (th != null) {
            initCause(th);
        }
    }

    public boolean equals(@Nullable Object obj) {
        if (obj != this) {
            if (obj instanceof C3056e1) {
                C3056e1 c3056e1 = (C3056e1) obj;
                if (!Intrinsics.areEqual(c3056e1.getMessage(), getMessage()) || !Intrinsics.areEqual(c3056e1.f8397c, this.f8397c) || !Intrinsics.areEqual(c3056e1.getCause(), getCause())) {
                }
            }
            return false;
        }
        return true;
    }

    @Override // java.lang.Throwable
    @NotNull
    public Throwable fillInStackTrace() {
        setStackTrace(new StackTraceElement[0]);
        return this;
    }

    public int hashCode() {
        String message = getMessage();
        Intrinsics.checkNotNull(message);
        int hashCode = (this.f8397c.hashCode() + (message.hashCode() * 31)) * 31;
        Throwable cause = getCause();
        return hashCode + (cause != null ? cause.hashCode() : 0);
    }

    @Override // java.lang.Throwable
    @NotNull
    public String toString() {
        return super.toString() + "; job=" + this.f8397c;
    }
}
