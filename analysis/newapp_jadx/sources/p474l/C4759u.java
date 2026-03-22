package p474l;

import kotlin.collections.ArraysKt___ArraysJvmKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: l.u */
/* loaded from: classes3.dex */
public final class C4759u {

    /* renamed from: a */
    @JvmField
    @NotNull
    public final byte[] f12167a;

    /* renamed from: b */
    @JvmField
    public int f12168b;

    /* renamed from: c */
    @JvmField
    public int f12169c;

    /* renamed from: d */
    @JvmField
    public boolean f12170d;

    /* renamed from: e */
    @JvmField
    public boolean f12171e;

    /* renamed from: f */
    @JvmField
    @Nullable
    public C4759u f12172f;

    /* renamed from: g */
    @JvmField
    @Nullable
    public C4759u f12173g;

    public C4759u() {
        this.f12167a = new byte[8192];
        this.f12171e = true;
        this.f12170d = false;
    }

    @Nullable
    /* renamed from: a */
    public final C4759u m5420a() {
        C4759u c4759u = this.f12172f;
        if (c4759u == this) {
            c4759u = null;
        }
        C4759u c4759u2 = this.f12173g;
        Intrinsics.checkNotNull(c4759u2);
        c4759u2.f12172f = this.f12172f;
        C4759u c4759u3 = this.f12172f;
        Intrinsics.checkNotNull(c4759u3);
        c4759u3.f12173g = this.f12173g;
        this.f12172f = null;
        this.f12173g = null;
        return c4759u;
    }

    @NotNull
    /* renamed from: b */
    public final C4759u m5421b(@NotNull C4759u segment) {
        Intrinsics.checkNotNullParameter(segment, "segment");
        segment.f12173g = this;
        segment.f12172f = this.f12172f;
        C4759u c4759u = this.f12172f;
        Intrinsics.checkNotNull(c4759u);
        c4759u.f12173g = segment;
        this.f12172f = segment;
        return segment;
    }

    @NotNull
    /* renamed from: c */
    public final C4759u m5422c() {
        this.f12170d = true;
        return new C4759u(this.f12167a, this.f12168b, this.f12169c, true, false);
    }

    /* renamed from: d */
    public final void m5423d(@NotNull C4759u sink, int i2) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (!sink.f12171e) {
            throw new IllegalStateException("only owner can write".toString());
        }
        int i3 = sink.f12169c;
        if (i3 + i2 > 8192) {
            if (sink.f12170d) {
                throw new IllegalArgumentException();
            }
            int i4 = sink.f12168b;
            if ((i3 + i2) - i4 > 8192) {
                throw new IllegalArgumentException();
            }
            byte[] bArr = sink.f12167a;
            ArraysKt___ArraysJvmKt.copyInto$default(bArr, bArr, 0, i4, i3, 2, (Object) null);
            sink.f12169c -= sink.f12168b;
            sink.f12168b = 0;
        }
        byte[] bArr2 = this.f12167a;
        byte[] bArr3 = sink.f12167a;
        int i5 = sink.f12169c;
        int i6 = this.f12168b;
        ArraysKt___ArraysJvmKt.copyInto(bArr2, bArr3, i5, i6, i6 + i2);
        sink.f12169c += i2;
        this.f12168b += i2;
    }

    public C4759u(@NotNull byte[] data, int i2, int i3, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.f12167a = data;
        this.f12168b = i2;
        this.f12169c = i3;
        this.f12170d = z;
        this.f12171e = z2;
    }
}
