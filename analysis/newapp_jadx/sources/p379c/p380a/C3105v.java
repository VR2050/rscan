package p379c.p380a;

import java.util.Objects;
import kotlin.Unit;
import kotlin.jvm.JvmField;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: c.a.v */
/* loaded from: classes2.dex */
public final class C3105v {

    /* renamed from: a */
    @JvmField
    @Nullable
    public final Object f8462a;

    /* renamed from: b */
    @JvmField
    @Nullable
    public final AbstractC3060g f8463b;

    /* renamed from: c */
    @JvmField
    @Nullable
    public final Function1<Throwable, Unit> f8464c;

    /* renamed from: d */
    @JvmField
    @Nullable
    public final Object f8465d;

    /* renamed from: e */
    @JvmField
    @Nullable
    public final Throwable f8466e;

    /* JADX WARN: Multi-variable type inference failed */
    public C3105v(@Nullable Object obj, @Nullable AbstractC3060g abstractC3060g, @Nullable Function1<? super Throwable, Unit> function1, @Nullable Object obj2, @Nullable Throwable th) {
        this.f8462a = obj;
        this.f8463b = abstractC3060g;
        this.f8464c = function1;
        this.f8465d = obj2;
        this.f8466e = th;
    }

    /* renamed from: a */
    public static C3105v m3641a(C3105v c3105v, Object obj, AbstractC3060g abstractC3060g, Function1 function1, Object obj2, Throwable th, int i2) {
        Object obj3 = (i2 & 1) != 0 ? c3105v.f8462a : null;
        if ((i2 & 2) != 0) {
            abstractC3060g = c3105v.f8463b;
        }
        AbstractC3060g abstractC3060g2 = abstractC3060g;
        Function1<Throwable, Unit> function12 = (i2 & 4) != 0 ? c3105v.f8464c : null;
        Object obj4 = (i2 & 8) != 0 ? c3105v.f8465d : null;
        if ((i2 & 16) != 0) {
            th = c3105v.f8466e;
        }
        Objects.requireNonNull(c3105v);
        return new C3105v(obj3, abstractC3060g2, function12, obj4, th);
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C3105v)) {
            return false;
        }
        C3105v c3105v = (C3105v) obj;
        return Intrinsics.areEqual(this.f8462a, c3105v.f8462a) && Intrinsics.areEqual(this.f8463b, c3105v.f8463b) && Intrinsics.areEqual(this.f8464c, c3105v.f8464c) && Intrinsics.areEqual(this.f8465d, c3105v.f8465d) && Intrinsics.areEqual(this.f8466e, c3105v.f8466e);
    }

    public int hashCode() {
        Object obj = this.f8462a;
        int hashCode = (obj != null ? obj.hashCode() : 0) * 31;
        AbstractC3060g abstractC3060g = this.f8463b;
        int hashCode2 = (hashCode + (abstractC3060g != null ? abstractC3060g.hashCode() : 0)) * 31;
        Function1<Throwable, Unit> function1 = this.f8464c;
        int hashCode3 = (hashCode2 + (function1 != null ? function1.hashCode() : 0)) * 31;
        Object obj2 = this.f8465d;
        int hashCode4 = (hashCode3 + (obj2 != null ? obj2.hashCode() : 0)) * 31;
        Throwable th = this.f8466e;
        return hashCode4 + (th != null ? th.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("CompletedContinuation(result=");
        m586H.append(this.f8462a);
        m586H.append(", cancelHandler=");
        m586H.append(this.f8463b);
        m586H.append(", onCancellation=");
        m586H.append(this.f8464c);
        m586H.append(", idempotentResume=");
        m586H.append(this.f8465d);
        m586H.append(", cancelCause=");
        m586H.append(this.f8466e);
        m586H.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        return m586H.toString();
    }

    public C3105v(Object obj, AbstractC3060g abstractC3060g, Function1 function1, Object obj2, Throwable th, int i2) {
        abstractC3060g = (i2 & 2) != 0 ? null : abstractC3060g;
        function1 = (i2 & 4) != 0 ? null : function1;
        obj2 = (i2 & 8) != 0 ? null : obj2;
        th = (i2 & 16) != 0 ? null : th;
        this.f8462a = obj;
        this.f8463b = abstractC3060g;
        this.f8464c = function1;
        this.f8465d = obj2;
        this.f8466e = th;
    }
}
