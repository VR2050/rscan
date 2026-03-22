package p005b.p199l.p200a.p201a.p208f1.p214f0;

import java.util.Arrays;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.f0.q */
/* loaded from: classes.dex */
public final class C2026q {

    /* renamed from: a */
    public final int f4066a;

    /* renamed from: b */
    public boolean f4067b;

    /* renamed from: c */
    public boolean f4068c;

    /* renamed from: d */
    public byte[] f4069d;

    /* renamed from: e */
    public int f4070e;

    public C2026q(int i2, int i3) {
        this.f4066a = i2;
        byte[] bArr = new byte[i3 + 3];
        this.f4069d = bArr;
        bArr[2] = 1;
    }

    /* renamed from: a */
    public void m1601a(byte[] bArr, int i2, int i3) {
        if (this.f4067b) {
            int i4 = i3 - i2;
            byte[] bArr2 = this.f4069d;
            int length = bArr2.length;
            int i5 = this.f4070e;
            if (length < i5 + i4) {
                this.f4069d = Arrays.copyOf(bArr2, (i5 + i4) * 2);
            }
            System.arraycopy(bArr, i2, this.f4069d, this.f4070e, i4);
            this.f4070e += i4;
        }
    }

    /* renamed from: b */
    public boolean m1602b(int i2) {
        if (!this.f4067b) {
            return false;
        }
        this.f4070e -= i2;
        this.f4067b = false;
        this.f4068c = true;
        return true;
    }

    /* renamed from: c */
    public void m1603c() {
        this.f4067b = false;
        this.f4068c = false;
    }

    /* renamed from: d */
    public void m1604d(int i2) {
        C4195m.m4771I(!this.f4067b);
        boolean z = i2 == this.f4066a;
        this.f4067b = z;
        if (z) {
            this.f4070e = 3;
            this.f4068c = false;
        }
    }
}
