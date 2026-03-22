package p005b.p199l.p200a.p201a.p208f1.p211c0;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;

/* renamed from: b.l.a.a.f1.c0.i */
/* loaded from: classes.dex */
public final class C1989i {

    /* renamed from: a */
    public final int f3678a;

    /* renamed from: b */
    public final int f3679b;

    /* renamed from: c */
    public final long f3680c;

    /* renamed from: d */
    public final long f3681d;

    /* renamed from: e */
    public final long f3682e;

    /* renamed from: f */
    public final Format f3683f;

    /* renamed from: g */
    public final int f3684g;

    /* renamed from: h */
    @Nullable
    public final long[] f3685h;

    /* renamed from: i */
    @Nullable
    public final long[] f3686i;

    /* renamed from: j */
    public final int f3687j;

    /* renamed from: k */
    @Nullable
    public final C1990j[] f3688k;

    public C1989i(int i2, int i3, long j2, long j3, long j4, Format format, int i4, @Nullable C1990j[] c1990jArr, int i5, @Nullable long[] jArr, @Nullable long[] jArr2) {
        this.f3678a = i2;
        this.f3679b = i3;
        this.f3680c = j2;
        this.f3681d = j3;
        this.f3682e = j4;
        this.f3683f = format;
        this.f3684g = i4;
        this.f3688k = c1990jArr;
        this.f3687j = i5;
        this.f3685h = jArr;
        this.f3686i = jArr2;
    }

    @Nullable
    /* renamed from: a */
    public C1990j m1540a(int i2) {
        C1990j[] c1990jArr = this.f3688k;
        if (c1990jArr == null) {
            return null;
        }
        return c1990jArr[i2];
    }
}
