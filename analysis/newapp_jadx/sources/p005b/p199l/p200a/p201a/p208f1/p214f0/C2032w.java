package p005b.p199l.p200a.p201a.p208f1.p214f0;

import androidx.core.view.InputDeviceCompat;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.w */
/* loaded from: classes.dex */
public final class C2032w implements InterfaceC2011c0 {

    /* renamed from: a */
    public final InterfaceC2031v f4112a;

    /* renamed from: b */
    public final C2360t f4113b = new C2360t(32);

    /* renamed from: c */
    public int f4114c;

    /* renamed from: d */
    public int f4115d;

    /* renamed from: e */
    public boolean f4116e;

    /* renamed from: f */
    public boolean f4117f;

    public C2032w(InterfaceC2031v interfaceC2031v) {
        this.f4112a = interfaceC2031v;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0
    /* renamed from: a */
    public void mo1580a(C2342c0 c2342c0, InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        this.f4112a.mo1578a(c2342c0, interfaceC2042i, dVar);
        this.f4117f = true;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0
    /* renamed from: b */
    public void mo1581b(C2360t c2360t, int i2) {
        boolean z = (i2 & 1) != 0;
        int m2585q = z ? c2360t.f6134b + c2360t.m2585q() : -1;
        if (this.f4117f) {
            if (!z) {
                return;
            }
            this.f4117f = false;
            c2360t.m2567C(m2585q);
            this.f4115d = 0;
        }
        while (c2360t.m2569a() > 0) {
            int i3 = this.f4115d;
            if (i3 < 3) {
                if (i3 == 0) {
                    int m2585q2 = c2360t.m2585q();
                    c2360t.m2567C(c2360t.f6134b - 1);
                    if (m2585q2 == 255) {
                        this.f4117f = true;
                        return;
                    }
                }
                int min = Math.min(c2360t.m2569a(), 3 - this.f4115d);
                c2360t.m2572d(this.f4113b.f6133a, this.f4115d, min);
                int i4 = this.f4115d + min;
                this.f4115d = i4;
                if (i4 == 3) {
                    this.f4113b.m2593y(3);
                    this.f4113b.m2568D(1);
                    int m2585q3 = this.f4113b.m2585q();
                    int m2585q4 = this.f4113b.m2585q();
                    this.f4116e = (m2585q3 & 128) != 0;
                    int i5 = (((m2585q3 & 15) << 8) | m2585q4) + 3;
                    this.f4114c = i5;
                    C2360t c2360t2 = this.f4113b;
                    byte[] bArr = c2360t2.f6133a;
                    if (bArr.length < i5) {
                        c2360t2.m2593y(Math.min(InputDeviceCompat.SOURCE_TOUCHSCREEN, Math.max(i5, bArr.length * 2)));
                        System.arraycopy(bArr, 0, this.f4113b.f6133a, 0, 3);
                    }
                }
            } else {
                int min2 = Math.min(c2360t.m2569a(), this.f4114c - this.f4115d);
                c2360t.m2572d(this.f4113b.f6133a, this.f4115d, min2);
                int i6 = this.f4115d + min2;
                this.f4115d = i6;
                int i7 = this.f4114c;
                if (i6 != i7) {
                    continue;
                } else {
                    if (this.f4116e) {
                        byte[] bArr2 = this.f4113b.f6133a;
                        int i8 = C2344d0.f6035a;
                        int i9 = -1;
                        for (int i10 = 0; i10 < i7; i10++) {
                            i9 = C2344d0.f6047m[((i9 >>> 24) ^ (bArr2[i10] & 255)) & 255] ^ (i9 << 8);
                        }
                        if (i9 != 0) {
                            this.f4117f = true;
                            return;
                        }
                        this.f4113b.m2593y(this.f4114c - 4);
                    } else {
                        this.f4113b.m2593y(i7);
                    }
                    this.f4112a.mo1579b(this.f4113b);
                    this.f4115d = 0;
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0
    /* renamed from: c */
    public void mo1582c() {
        this.f4117f = true;
    }
}
