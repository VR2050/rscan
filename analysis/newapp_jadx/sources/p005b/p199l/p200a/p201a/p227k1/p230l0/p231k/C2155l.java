package p005b.p199l.p200a.p201a.p227k1.p230l0.p231k;

import java.util.Locale;

/* renamed from: b.l.a.a.k1.l0.k.l */
/* loaded from: classes.dex */
public final class C2155l {

    /* renamed from: a */
    public final String[] f4847a;

    /* renamed from: b */
    public final int[] f4848b;

    /* renamed from: c */
    public final String[] f4849c;

    /* renamed from: d */
    public final int f4850d;

    public C2155l(String[] strArr, int[] iArr, String[] strArr2, int i2) {
        this.f4847a = strArr;
        this.f4848b = iArr;
        this.f4849c = strArr2;
        this.f4850d = i2;
    }

    /* renamed from: a */
    public String m1925a(String str, long j2, int i2, long j3) {
        StringBuilder sb = new StringBuilder();
        int i3 = 0;
        while (true) {
            int i4 = this.f4850d;
            if (i3 >= i4) {
                sb.append(this.f4847a[i4]);
                return sb.toString();
            }
            sb.append(this.f4847a[i3]);
            int[] iArr = this.f4848b;
            if (iArr[i3] == 1) {
                sb.append(str);
            } else if (iArr[i3] == 2) {
                sb.append(String.format(Locale.US, this.f4849c[i3], Long.valueOf(j2)));
            } else if (iArr[i3] == 3) {
                sb.append(String.format(Locale.US, this.f4849c[i3], Integer.valueOf(i2)));
            } else if (iArr[i3] == 4) {
                sb.append(String.format(Locale.US, this.f4849c[i3], Long.valueOf(j3)));
            }
            i3++;
        }
    }
}
