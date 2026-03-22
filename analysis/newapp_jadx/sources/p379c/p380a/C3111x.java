package p379c.p380a;

import kotlin.Unit;
import kotlin.jvm.JvmField;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: c.a.x */
/* loaded from: classes2.dex */
public final class C3111x {

    /* renamed from: a */
    @JvmField
    @Nullable
    public final Object f8473a;

    /* renamed from: b */
    @JvmField
    @NotNull
    public final Function1<Throwable, Unit> f8474b;

    /* JADX WARN: Multi-variable type inference failed */
    public C3111x(@Nullable Object obj, @NotNull Function1<? super Throwable, Unit> function1) {
        this.f8473a = obj;
        this.f8474b = function1;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C3111x)) {
            return false;
        }
        C3111x c3111x = (C3111x) obj;
        return Intrinsics.areEqual(this.f8473a, c3111x.f8473a) && Intrinsics.areEqual(this.f8474b, c3111x.f8474b);
    }

    public int hashCode() {
        Object obj = this.f8473a;
        int hashCode = (obj != null ? obj.hashCode() : 0) * 31;
        Function1<Throwable, Unit> function1 = this.f8474b;
        return hashCode + (function1 != null ? function1.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("CompletedWithCancellation(result=");
        m586H.append(this.f8473a);
        m586H.append(", onCancellation=");
        m586H.append(this.f8474b);
        m586H.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        return m586H.toString();
    }
}
