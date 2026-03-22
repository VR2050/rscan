package p458k.p459p0.p465i;

import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p474l.C4747i;

/* renamed from: k.p0.i.c */
/* loaded from: classes3.dex */
public final class C4437c {

    /* renamed from: a */
    @JvmField
    @NotNull
    public static final C4747i f11783a;

    /* renamed from: b */
    @JvmField
    @NotNull
    public static final C4747i f11784b;

    /* renamed from: c */
    @JvmField
    @NotNull
    public static final C4747i f11785c;

    /* renamed from: d */
    @JvmField
    @NotNull
    public static final C4747i f11786d;

    /* renamed from: e */
    @JvmField
    @NotNull
    public static final C4747i f11787e;

    /* renamed from: f */
    @JvmField
    @NotNull
    public static final C4747i f11788f;

    /* renamed from: g */
    @JvmField
    public final int f11789g;

    /* renamed from: h */
    @JvmField
    @NotNull
    public final C4747i f11790h;

    /* renamed from: i */
    @JvmField
    @NotNull
    public final C4747i f11791i;

    static {
        C4747i.a aVar = C4747i.f12136e;
        f11783a = aVar.m5412c(":");
        f11784b = aVar.m5412c(":status");
        f11785c = aVar.m5412c(":method");
        f11786d = aVar.m5412c(":path");
        f11787e = aVar.m5412c(":scheme");
        f11788f = aVar.m5412c(":authority");
    }

    public C4437c(@NotNull C4747i name, @NotNull C4747i value) {
        Intrinsics.checkParameterIsNotNull(name, "name");
        Intrinsics.checkParameterIsNotNull(value, "value");
        this.f11790h = name;
        this.f11791i = value;
        this.f11789g = name.mo5400c() + 32 + value.mo5400c();
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4437c)) {
            return false;
        }
        C4437c c4437c = (C4437c) obj;
        return Intrinsics.areEqual(this.f11790h, c4437c.f11790h) && Intrinsics.areEqual(this.f11791i, c4437c.f11791i);
    }

    public int hashCode() {
        C4747i c4747i = this.f11790h;
        int hashCode = (c4747i != null ? c4747i.hashCode() : 0) * 31;
        C4747i c4747i2 = this.f11791i;
        return hashCode + (c4747i2 != null ? c4747i2.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        return this.f11790h.m5407j() + ": " + this.f11791i.m5407j();
    }

    /* JADX WARN: Illegal instructions before constructor call */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C4437c(@org.jetbrains.annotations.NotNull java.lang.String r2, @org.jetbrains.annotations.NotNull java.lang.String r3) {
        /*
            r1 = this;
            java.lang.String r0 = "name"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r2, r0)
            java.lang.String r0 = "value"
            kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r3, r0)
            l.i$a r0 = p474l.C4747i.f12136e
            l.i r2 = r0.m5412c(r2)
            l.i r3 = r0.m5412c(r3)
            r1.<init>(r2, r3)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p465i.C4437c.<init>(java.lang.String, java.lang.String):void");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C4437c(@NotNull C4747i name, @NotNull String value) {
        this(name, C4747i.f12136e.m5412c(value));
        Intrinsics.checkParameterIsNotNull(name, "name");
        Intrinsics.checkParameterIsNotNull(value, "value");
    }
}
