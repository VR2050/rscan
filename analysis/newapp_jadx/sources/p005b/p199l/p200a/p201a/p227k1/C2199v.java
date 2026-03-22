package p005b.p199l.p200a.p201a.p227k1;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.util.List;
import java.util.Map;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.v */
/* loaded from: classes.dex */
public final class C2199v implements InterfaceC2321m {

    /* renamed from: a */
    public final InterfaceC2321m f5234a;

    /* renamed from: b */
    public final int f5235b;

    /* renamed from: c */
    public final a f5236c;

    /* renamed from: d */
    public final byte[] f5237d;

    /* renamed from: e */
    public int f5238e;

    /* renamed from: b.l.a.a.k1.v$a */
    public interface a {
    }

    public C2199v(InterfaceC2321m interfaceC2321m, int i2, a aVar) {
        C4195m.m4765F(i2 > 0);
        this.f5234a = interfaceC2321m;
        this.f5235b = i2;
        this.f5236c = aVar;
        this.f5237d = new byte[1];
        this.f5238e = i2;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void addTransferListener(InterfaceC2291f0 interfaceC2291f0) {
        this.f5234a.addTransferListener(interfaceC2291f0);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        throw new UnsupportedOperationException();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public Map<String, List<String>> getResponseHeaders() {
        return this.f5234a.getResponseHeaders();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        return this.f5234a.getUri();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        throw new UnsupportedOperationException();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0078 A[RETURN] */
    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int read(byte[] r17, int r18, int r19) {
        /*
            r16 = this;
            r0 = r16
            int r1 = r0.f5238e
            r2 = -1
            if (r1 != 0) goto L79
            b.l.a.a.o1.m r1 = r0.f5234a
            byte[] r3 = r0.f5237d
            r4 = 1
            r5 = 0
            int r1 = r1.read(r3, r5, r4)
            if (r1 != r2) goto L15
        L13:
            r4 = 0
            goto L71
        L15:
            byte[] r1 = r0.f5237d
            r1 = r1[r5]
            r1 = r1 & 255(0xff, float:3.57E-43)
            int r1 = r1 << 4
            if (r1 != 0) goto L20
            goto L71
        L20:
            byte[] r3 = new byte[r1]
            r6 = r1
            r7 = 0
        L24:
            if (r6 <= 0) goto L32
            b.l.a.a.o1.m r8 = r0.f5234a
            int r8 = r8.read(r3, r7, r6)
            if (r8 != r2) goto L2f
            goto L13
        L2f:
            int r7 = r7 + r8
            int r6 = r6 - r8
            goto L24
        L32:
            if (r1 <= 0) goto L3c
            int r5 = r1 + (-1)
            r6 = r3[r5]
            if (r6 != 0) goto L3c
            r1 = r5
            goto L32
        L3c:
            if (r1 <= 0) goto L71
            b.l.a.a.k1.v$a r5 = r0.f5236c
            b.l.a.a.p1.t r6 = new b.l.a.a.p1.t
            r6.<init>(r3, r1)
            b.l.a.a.k1.a0$a r5 = (p005b.p199l.p200a.p201a.p227k1.C2099a0.a) r5
            boolean r1 = r5.f4489m
            if (r1 != 0) goto L4e
            long r7 = r5.f4485i
            goto L5c
        L4e:
            b.l.a.a.k1.a0 r1 = p005b.p199l.p200a.p201a.p227k1.C2099a0.this
            java.util.Map<java.lang.String, java.lang.String> r3 = p005b.p199l.p200a.p201a.p227k1.C2099a0.f4437c
            long r7 = r1.m1778w()
            long r9 = r5.f4485i
            long r7 = java.lang.Math.max(r7, r9)
        L5c:
            r10 = r7
            int r13 = r6.m2569a()
            b.l.a.a.f1.s r9 = r5.f4488l
            java.util.Objects.requireNonNull(r9)
            r9.mo1613b(r6, r13)
            r12 = 1
            r14 = 0
            r15 = 0
            r9.mo1614c(r10, r12, r13, r14, r15)
            r5.f4489m = r4
        L71:
            if (r4 == 0) goto L78
            int r1 = r0.f5235b
            r0.f5238e = r1
            goto L79
        L78:
            return r2
        L79:
            b.l.a.a.o1.m r1 = r0.f5234a
            int r3 = r0.f5238e
            r4 = r19
            int r3 = java.lang.Math.min(r3, r4)
            r4 = r17
            r5 = r18
            int r1 = r1.read(r4, r5, r3)
            if (r1 == r2) goto L92
            int r2 = r0.f5238e
            int r2 = r2 - r1
            r0.f5238e = r2
        L92:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.C2199v.read(byte[], int, int):int");
    }
}
