package p005b.p199l.p200a.p201a.p208f1;

import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.t */
/* loaded from: classes.dex */
public final class C2053t {

    /* renamed from: a */
    public final byte[] f4199a;

    /* renamed from: b */
    public final int f4200b;

    /* renamed from: c */
    public int f4201c;

    /* renamed from: d */
    public int f4202d;

    public C2053t(byte[] bArr) {
        this.f4199a = bArr;
        this.f4200b = bArr.length;
    }

    /* renamed from: a */
    public boolean m1637a() {
        boolean z = (((this.f4199a[this.f4201c] & 255) >> this.f4202d) & 1) == 1;
        m1639c(1);
        return z;
    }

    /* renamed from: b */
    public int m1638b(int i2) {
        int i3 = this.f4201c;
        int min = Math.min(i2, 8 - this.f4202d);
        int i4 = i3 + 1;
        int i5 = ((this.f4199a[i3] & 255) >> this.f4202d) & (255 >> (8 - min));
        while (min < i2) {
            i5 |= (this.f4199a[i4] & 255) << min;
            min += 8;
            i4++;
        }
        int i6 = i5 & ((-1) >>> (32 - i2));
        m1639c(i2);
        return i6;
    }

    /* renamed from: c */
    public void m1639c(int i2) {
        int i3;
        int i4 = i2 / 8;
        int i5 = this.f4201c + i4;
        this.f4201c = i5;
        int i6 = (i2 - (i4 * 8)) + this.f4202d;
        this.f4202d = i6;
        boolean z = true;
        if (i6 > 7) {
            this.f4201c = i5 + 1;
            this.f4202d = i6 - 8;
        }
        int i7 = this.f4201c;
        if (i7 < 0 || (i7 >= (i3 = this.f4200b) && (i7 != i3 || this.f4202d != 0))) {
            z = false;
        }
        C4195m.m4771I(z);
    }
}
