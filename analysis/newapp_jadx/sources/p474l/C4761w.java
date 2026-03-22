package p474l;

import java.security.MessageDigest;
import kotlin.collections.ArraysKt___ArraysJvmKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: l.w */
/* loaded from: classes3.dex */
public final class C4761w extends C4747i {

    /* renamed from: i */
    @NotNull
    public final transient byte[][] f12178i;

    /* renamed from: j */
    @NotNull
    public final transient int[] f12179j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4761w(@NotNull byte[][] segments, @NotNull int[] directory) {
        super(C4747i.f12135c.f12139h);
        Intrinsics.checkNotNullParameter(segments, "segments");
        Intrinsics.checkNotNullParameter(directory, "directory");
        this.f12178i = segments;
        this.f12179j = directory;
    }

    private final Object writeReplace() {
        return m5427m();
    }

    @Override // p474l.C4747i
    @NotNull
    /* renamed from: a */
    public String mo5398a() {
        return m5427m().mo5398a();
    }

    @Override // p474l.C4747i
    @NotNull
    /* renamed from: b */
    public C4747i mo5399b(@NotNull String algorithm) {
        Intrinsics.checkNotNullParameter(algorithm, "algorithm");
        Intrinsics.checkNotNullParameter(this, "$this$commonSegmentDigest");
        Intrinsics.checkNotNullParameter(algorithm, "algorithm");
        Intrinsics.checkNotNullParameter(algorithm, "algorithm");
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        int length = this.f12178i.length;
        int i2 = 0;
        int i3 = 0;
        while (i2 < length) {
            int[] iArr = this.f12179j;
            int i4 = iArr[length + i2];
            int i5 = iArr[i2];
            byte[] input = this.f12178i[i2];
            Intrinsics.checkNotNullParameter(input, "input");
            messageDigest.update(input, i4, i5 - i3);
            i2++;
            i3 = i5;
        }
        return new C4747i(messageDigest.digest());
    }

    @Override // p474l.C4747i
    /* renamed from: c */
    public int mo5400c() {
        return this.f12179j[this.f12178i.length - 1];
    }

    @Override // p474l.C4747i
    @NotNull
    /* renamed from: d */
    public String mo5401d() {
        return m5427m().mo5401d();
    }

    @Override // p474l.C4747i
    @NotNull
    /* renamed from: e */
    public byte[] mo5402e() {
        return m5426l();
    }

    @Override // p474l.C4747i
    public boolean equals(@Nullable Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C4747i) {
            C4747i c4747i = (C4747i) obj;
            if (c4747i.mo5400c() == mo5400c() && mo5404g(0, c4747i, 0, mo5400c())) {
                return true;
            }
        }
        return false;
    }

    @Override // p474l.C4747i
    /* renamed from: f */
    public byte mo5403f(int i2) {
        C2354n.m2530y(this.f12179j[this.f12178i.length - 1], i2, 1L);
        int m2526w1 = C2354n.m2526w1(this, i2);
        int i3 = m2526w1 == 0 ? 0 : this.f12179j[m2526w1 - 1];
        int[] iArr = this.f12179j;
        byte[][] bArr = this.f12178i;
        return bArr[m2526w1][(i2 - i3) + iArr[bArr.length + m2526w1]];
    }

    @Override // p474l.C4747i
    /* renamed from: g */
    public boolean mo5404g(int i2, @NotNull C4747i other, int i3, int i4) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (i2 < 0 || i2 > mo5400c() - i4) {
            return false;
        }
        int i5 = i4 + i2;
        int m2526w1 = C2354n.m2526w1(this, i2);
        while (i2 < i5) {
            int i6 = m2526w1 == 0 ? 0 : this.f12179j[m2526w1 - 1];
            int[] iArr = this.f12179j;
            int i7 = iArr[m2526w1] - i6;
            int i8 = iArr[this.f12178i.length + m2526w1];
            int min = Math.min(i5, i7 + i6) - i2;
            if (!other.mo5405h(i3, this.f12178i[m2526w1], (i2 - i6) + i8, min)) {
                return false;
            }
            i3 += min;
            i2 += min;
            m2526w1++;
        }
        return true;
    }

    @Override // p474l.C4747i
    /* renamed from: h */
    public boolean mo5405h(int i2, @NotNull byte[] other, int i3, int i4) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (i2 < 0 || i2 > mo5400c() - i4 || i3 < 0 || i3 > other.length - i4) {
            return false;
        }
        int i5 = i4 + i2;
        int m2526w1 = C2354n.m2526w1(this, i2);
        while (i2 < i5) {
            int i6 = m2526w1 == 0 ? 0 : this.f12179j[m2526w1 - 1];
            int[] iArr = this.f12179j;
            int i7 = iArr[m2526w1] - i6;
            int i8 = iArr[this.f12178i.length + m2526w1];
            int min = Math.min(i5, i7 + i6) - i2;
            if (!C2354n.m2482i(this.f12178i[m2526w1], (i2 - i6) + i8, other, i3, min)) {
                return false;
            }
            i3 += min;
            i2 += min;
            m2526w1++;
        }
        return true;
    }

    @Override // p474l.C4747i
    public int hashCode() {
        int i2 = this.f12137f;
        if (i2 != 0) {
            return i2;
        }
        int length = this.f12178i.length;
        int i3 = 0;
        int i4 = 1;
        int i5 = 0;
        while (i3 < length) {
            int[] iArr = this.f12179j;
            int i6 = iArr[length + i3];
            int i7 = iArr[i3];
            byte[] bArr = this.f12178i[i3];
            int i8 = (i7 - i5) + i6;
            while (i6 < i8) {
                i4 = (i4 * 31) + bArr[i6];
                i6++;
            }
            i3++;
            i5 = i7;
        }
        this.f12137f = i4;
        return i4;
    }

    @Override // p474l.C4747i
    @NotNull
    /* renamed from: i */
    public C4747i mo5406i() {
        return m5427m().mo5406i();
    }

    @Override // p474l.C4747i
    /* renamed from: k */
    public void mo5408k(@NotNull C4744f buffer, int i2, int i3) {
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        int i4 = i2 + i3;
        int m2526w1 = C2354n.m2526w1(this, i2);
        while (i2 < i4) {
            int i5 = m2526w1 == 0 ? 0 : this.f12179j[m2526w1 - 1];
            int[] iArr = this.f12179j;
            int i6 = iArr[m2526w1] - i5;
            int i7 = iArr[this.f12178i.length + m2526w1];
            int min = Math.min(i4, i6 + i5) - i2;
            int i8 = (i2 - i5) + i7;
            C4759u c4759u = new C4759u(this.f12178i[m2526w1], i8, i8 + min, true, false);
            C4759u c4759u2 = buffer.f12132c;
            if (c4759u2 == null) {
                c4759u.f12173g = c4759u;
                c4759u.f12172f = c4759u;
                buffer.f12132c = c4759u;
            } else {
                Intrinsics.checkNotNull(c4759u2);
                C4759u c4759u3 = c4759u2.f12173g;
                Intrinsics.checkNotNull(c4759u3);
                c4759u3.m5421b(c4759u);
            }
            i2 += min;
            m2526w1++;
        }
        buffer.f12133e += i3;
    }

    @NotNull
    /* renamed from: l */
    public byte[] m5426l() {
        byte[] bArr = new byte[mo5400c()];
        int length = this.f12178i.length;
        int i2 = 0;
        int i3 = 0;
        int i4 = 0;
        while (i2 < length) {
            int[] iArr = this.f12179j;
            int i5 = iArr[length + i2];
            int i6 = iArr[i2];
            int i7 = i6 - i3;
            ArraysKt___ArraysJvmKt.copyInto(this.f12178i[i2], bArr, i4, i5, i5 + i7);
            i4 += i7;
            i2++;
            i3 = i6;
        }
        return bArr;
    }

    /* renamed from: m */
    public final C4747i m5427m() {
        return new C4747i(m5426l());
    }

    @Override // p474l.C4747i
    @NotNull
    public String toString() {
        return m5427m().toString();
    }
}
