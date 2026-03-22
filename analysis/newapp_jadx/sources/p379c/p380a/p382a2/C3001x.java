package p379c.p380a.p382a2;

import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: c.a.a2.x */
/* loaded from: classes2.dex */
public final class C3001x<T> {

    /* renamed from: a */
    public final Object f8188a;

    /* renamed from: c.a.a2.x$a */
    public static final class a {

        /* renamed from: a */
        @JvmField
        @Nullable
        public final Throwable f8189a;

        public a(@Nullable Throwable th) {
            this.f8189a = th;
        }

        public boolean equals(@Nullable Object obj) {
            return (obj instanceof a) && Intrinsics.areEqual(this.f8189a, ((a) obj).f8189a);
        }

        public int hashCode() {
            Throwable th = this.f8189a;
            if (th != null) {
                return th.hashCode();
            }
            return 0;
        }

        @NotNull
        public String toString() {
            StringBuilder m586H = C1499a.m586H("Closed(");
            m586H.append(this.f8189a);
            m586H.append(')');
            return m586H.toString();
        }
    }

    public boolean equals(Object obj) {
        return (obj instanceof C3001x) && Intrinsics.areEqual(this.f8188a, ((C3001x) obj).f8188a);
    }

    public int hashCode() {
        Object obj = this.f8188a;
        if (obj != null) {
            return obj.hashCode();
        }
        return 0;
    }

    @NotNull
    public String toString() {
        Object obj = this.f8188a;
        if (obj instanceof a) {
            return obj.toString();
        }
        return "Value(" + obj + ')';
    }
}
