package p458k.p459p0.p465i;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kotlin.collections.ArraysKt___ArraysJvmKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p458k.p459p0.C4401c;
import p458k.p459p0.p465i.C4451q;
import p474l.C4744f;
import p474l.C4747i;
import p474l.InterfaceC4746h;
import p474l.InterfaceC4764z;

/* renamed from: k.p0.i.d */
/* loaded from: classes3.dex */
public final class C4438d {

    /* renamed from: a */
    @NotNull
    public static final C4437c[] f11792a;

    /* renamed from: b */
    @NotNull
    public static final Map<C4747i, Integer> f11793b;

    /* renamed from: c */
    public static final C4438d f11794c = new C4438d();

    /* renamed from: k.p0.i.d$a */
    public static final class a {

        /* renamed from: a */
        public final List<C4437c> f11795a;

        /* renamed from: b */
        public final InterfaceC4746h f11796b;

        /* renamed from: c */
        @JvmField
        @NotNull
        public C4437c[] f11797c;

        /* renamed from: d */
        public int f11798d;

        /* renamed from: e */
        @JvmField
        public int f11799e;

        /* renamed from: f */
        @JvmField
        public int f11800f;

        /* renamed from: g */
        public final int f11801g;

        /* renamed from: h */
        public int f11802h;

        public a(InterfaceC4764z source, int i2, int i3, int i4) {
            i3 = (i4 & 4) != 0 ? i2 : i3;
            Intrinsics.checkParameterIsNotNull(source, "source");
            this.f11801g = i2;
            this.f11802h = i3;
            this.f11795a = new ArrayList();
            this.f11796b = C2354n.m2500o(source);
            this.f11797c = new C4437c[8];
            this.f11798d = 7;
        }

        /* renamed from: a */
        public final void m5153a() {
            ArraysKt___ArraysJvmKt.fill$default(this.f11797c, (Object) null, 0, 0, 6, (Object) null);
            this.f11798d = this.f11797c.length - 1;
            this.f11799e = 0;
            this.f11800f = 0;
        }

        /* renamed from: b */
        public final int m5154b(int i2) {
            return this.f11798d + 1 + i2;
        }

        /* renamed from: c */
        public final int m5155c(int i2) {
            int i3;
            int i4 = 0;
            if (i2 > 0) {
                int length = this.f11797c.length;
                while (true) {
                    length--;
                    i3 = this.f11798d;
                    if (length < i3 || i2 <= 0) {
                        break;
                    }
                    C4437c c4437c = this.f11797c[length];
                    if (c4437c == null) {
                        Intrinsics.throwNpe();
                    }
                    int i5 = c4437c.f11789g;
                    i2 -= i5;
                    this.f11800f -= i5;
                    this.f11799e--;
                    i4++;
                }
                C4437c[] c4437cArr = this.f11797c;
                System.arraycopy(c4437cArr, i3 + 1, c4437cArr, i3 + 1 + i4, this.f11799e);
                this.f11798d += i4;
            }
            return i4;
        }

        /* JADX WARN: Removed duplicated region for block: B:6:0x0010  */
        /* JADX WARN: Removed duplicated region for block: B:9:0x0019  */
        /* renamed from: d */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final p474l.C4747i m5156d(int r4) {
            /*
                r3 = this;
                if (r4 < 0) goto Ld
                k.p0.i.d r0 = p458k.p459p0.p465i.C4438d.f11794c
                k.p0.i.c[] r0 = p458k.p459p0.p465i.C4438d.f11792a
                int r0 = r0.length
                int r0 = r0 + (-1)
                if (r4 > r0) goto Ld
                r0 = 1
                goto Le
            Ld:
                r0 = 0
            Le:
                if (r0 == 0) goto L19
                k.p0.i.d r0 = p458k.p459p0.p465i.C4438d.f11794c
                k.p0.i.c[] r0 = p458k.p459p0.p465i.C4438d.f11792a
                r4 = r0[r4]
                l.i r4 = r4.f11790h
                goto L34
            L19:
                k.p0.i.d r0 = p458k.p459p0.p465i.C4438d.f11794c
                k.p0.i.c[] r0 = p458k.p459p0.p465i.C4438d.f11792a
                int r0 = r0.length
                int r0 = r4 - r0
                int r0 = r3.m5154b(r0)
                if (r0 < 0) goto L35
                k.p0.i.c[] r1 = r3.f11797c
                int r2 = r1.length
                if (r0 >= r2) goto L35
                r4 = r1[r0]
                if (r4 != 0) goto L32
                kotlin.jvm.internal.Intrinsics.throwNpe()
            L32:
                l.i r4 = r4.f11790h
            L34:
                return r4
            L35:
                java.io.IOException r0 = new java.io.IOException
                java.lang.String r1 = "Header index too large "
                java.lang.StringBuilder r1 = p005b.p131d.p132a.p133a.C1499a.m586H(r1)
                int r4 = r4 + 1
                r1.append(r4)
                java.lang.String r4 = r1.toString()
                r0.<init>(r4)
                throw r0
            */
            throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p465i.C4438d.a.m5156d(int):l.i");
        }

        /* renamed from: e */
        public final void m5157e(int i2, C4437c c4437c) {
            this.f11795a.add(c4437c);
            int i3 = c4437c.f11789g;
            if (i2 != -1) {
                C4437c c4437c2 = this.f11797c[this.f11798d + 1 + i2];
                if (c4437c2 == null) {
                    Intrinsics.throwNpe();
                }
                i3 -= c4437c2.f11789g;
            }
            int i4 = this.f11802h;
            if (i3 > i4) {
                m5153a();
                return;
            }
            int m5155c = m5155c((this.f11800f + i3) - i4);
            if (i2 == -1) {
                int i5 = this.f11799e + 1;
                C4437c[] c4437cArr = this.f11797c;
                if (i5 > c4437cArr.length) {
                    C4437c[] c4437cArr2 = new C4437c[c4437cArr.length * 2];
                    System.arraycopy(c4437cArr, 0, c4437cArr2, c4437cArr.length, c4437cArr.length);
                    this.f11798d = this.f11797c.length - 1;
                    this.f11797c = c4437cArr2;
                }
                int i6 = this.f11798d;
                this.f11798d = i6 - 1;
                this.f11797c[i6] = c4437c;
                this.f11799e++;
            } else {
                this.f11797c[this.f11798d + 1 + i2 + m5155c + i2] = c4437c;
            }
            this.f11800f += i3;
        }

        @NotNull
        /* renamed from: f */
        public final C4747i m5158f() {
            byte readByte = this.f11796b.readByte();
            byte[] bArr = C4401c.f11556a;
            int i2 = readByte & 255;
            int i3 = 0;
            boolean z = (i2 & 128) == 128;
            long m5159g = m5159g(i2, 127);
            if (!z) {
                return this.f11796b.mo5380f(m5159g);
            }
            C4744f sink = new C4744f();
            C4451q c4451q = C4451q.f11950d;
            InterfaceC4746h source = this.f11796b;
            Intrinsics.checkParameterIsNotNull(source, "source");
            Intrinsics.checkParameterIsNotNull(sink, "sink");
            C4451q.a aVar = C4451q.f11949c;
            int i4 = 0;
            for (long j2 = 0; j2 < m5159g; j2++) {
                byte readByte2 = source.readByte();
                byte[] bArr2 = C4401c.f11556a;
                i3 = (i3 << 8) | (readByte2 & 255);
                i4 += 8;
                while (i4 >= 8) {
                    int i5 = i4 - 8;
                    int i6 = (i3 >>> i5) & 255;
                    C4451q.a[] aVarArr = aVar.f11951a;
                    if (aVarArr == null) {
                        Intrinsics.throwNpe();
                    }
                    aVar = aVarArr[i6];
                    if (aVar == null) {
                        Intrinsics.throwNpe();
                    }
                    if (aVar.f11951a == null) {
                        sink.m5374a0(aVar.f11952b);
                        i4 -= aVar.f11953c;
                        aVar = C4451q.f11949c;
                    } else {
                        i4 = i5;
                    }
                }
            }
            while (i4 > 0) {
                int i7 = (i3 << (8 - i4)) & 255;
                C4451q.a[] aVarArr2 = aVar.f11951a;
                if (aVarArr2 == null) {
                    Intrinsics.throwNpe();
                }
                C4451q.a aVar2 = aVarArr2[i7];
                if (aVar2 == null) {
                    Intrinsics.throwNpe();
                }
                if (aVar2.f11951a != null || aVar2.f11953c > i4) {
                    break;
                }
                sink.m5374a0(aVar2.f11952b);
                i4 -= aVar2.f11953c;
                aVar = C4451q.f11949c;
            }
            return sink.m5353D();
        }

        /* renamed from: g */
        public final int m5159g(int i2, int i3) {
            int i4 = i2 & i3;
            if (i4 < i3) {
                return i4;
            }
            int i5 = 0;
            while (true) {
                byte readByte = this.f11796b.readByte();
                byte[] bArr = C4401c.f11556a;
                int i6 = readByte & 255;
                if ((i6 & 128) == 0) {
                    return i3 + (i6 << i5);
                }
                i3 += (i6 & 127) << i5;
                i5 += 7;
            }
        }
    }

    /* renamed from: k.p0.i.d$b */
    public static final class b {

        /* renamed from: a */
        public int f11803a;

        /* renamed from: b */
        public boolean f11804b;

        /* renamed from: c */
        @JvmField
        public int f11805c;

        /* renamed from: d */
        @JvmField
        @NotNull
        public C4437c[] f11806d;

        /* renamed from: e */
        public int f11807e;

        /* renamed from: f */
        @JvmField
        public int f11808f;

        /* renamed from: g */
        @JvmField
        public int f11809g;

        /* renamed from: h */
        @JvmField
        public int f11810h;

        /* renamed from: i */
        public final boolean f11811i;

        /* renamed from: j */
        public final C4744f f11812j;

        public b(int i2, boolean z, C4744f out, int i3) {
            i2 = (i3 & 1) != 0 ? 4096 : i2;
            z = (i3 & 2) != 0 ? true : z;
            Intrinsics.checkParameterIsNotNull(out, "out");
            this.f11810h = i2;
            this.f11811i = z;
            this.f11812j = out;
            this.f11803a = Integer.MAX_VALUE;
            this.f11805c = i2;
            this.f11806d = new C4437c[8];
            this.f11807e = 7;
        }

        /* renamed from: a */
        public final void m5160a() {
            ArraysKt___ArraysJvmKt.fill$default(this.f11806d, (Object) null, 0, 0, 6, (Object) null);
            this.f11807e = this.f11806d.length - 1;
            this.f11808f = 0;
            this.f11809g = 0;
        }

        /* renamed from: b */
        public final int m5161b(int i2) {
            int i3;
            int i4 = 0;
            if (i2 > 0) {
                int length = this.f11806d.length;
                while (true) {
                    length--;
                    i3 = this.f11807e;
                    if (length < i3 || i2 <= 0) {
                        break;
                    }
                    C4437c c4437c = this.f11806d[length];
                    if (c4437c == null) {
                        Intrinsics.throwNpe();
                    }
                    i2 -= c4437c.f11789g;
                    int i5 = this.f11809g;
                    C4437c c4437c2 = this.f11806d[length];
                    if (c4437c2 == null) {
                        Intrinsics.throwNpe();
                    }
                    this.f11809g = i5 - c4437c2.f11789g;
                    this.f11808f--;
                    i4++;
                }
                C4437c[] c4437cArr = this.f11806d;
                System.arraycopy(c4437cArr, i3 + 1, c4437cArr, i3 + 1 + i4, this.f11808f);
                C4437c[] c4437cArr2 = this.f11806d;
                int i6 = this.f11807e;
                Arrays.fill(c4437cArr2, i6 + 1, i6 + 1 + i4, (Object) null);
                this.f11807e += i4;
            }
            return i4;
        }

        /* renamed from: c */
        public final void m5162c(C4437c c4437c) {
            int i2 = c4437c.f11789g;
            int i3 = this.f11805c;
            if (i2 > i3) {
                m5160a();
                return;
            }
            m5161b((this.f11809g + i2) - i3);
            int i4 = this.f11808f + 1;
            C4437c[] c4437cArr = this.f11806d;
            if (i4 > c4437cArr.length) {
                C4437c[] c4437cArr2 = new C4437c[c4437cArr.length * 2];
                System.arraycopy(c4437cArr, 0, c4437cArr2, c4437cArr.length, c4437cArr.length);
                this.f11807e = this.f11806d.length - 1;
                this.f11806d = c4437cArr2;
            }
            int i5 = this.f11807e;
            this.f11807e = i5 - 1;
            this.f11806d[i5] = c4437c;
            this.f11808f++;
            this.f11809g += i2;
        }

        /* renamed from: d */
        public final void m5163d(@NotNull C4747i source) {
            Intrinsics.checkParameterIsNotNull(source, "data");
            if (this.f11811i) {
                C4451q c4451q = C4451q.f11950d;
                Intrinsics.checkParameterIsNotNull(source, "bytes");
                int mo5400c = source.mo5400c();
                long j2 = 0;
                for (int i2 = 0; i2 < mo5400c; i2++) {
                    byte mo5403f = source.mo5403f(i2);
                    byte[] bArr = C4401c.f11556a;
                    j2 += C4451q.f11948b[mo5403f & 255];
                }
                if (((int) ((j2 + 7) >> 3)) < source.mo5400c()) {
                    C4744f sink = new C4744f();
                    C4451q c4451q2 = C4451q.f11950d;
                    Intrinsics.checkParameterIsNotNull(source, "source");
                    Intrinsics.checkParameterIsNotNull(sink, "sink");
                    int mo5400c2 = source.mo5400c();
                    long j3 = 0;
                    int i3 = 0;
                    for (int i4 = 0; i4 < mo5400c2; i4++) {
                        byte mo5403f2 = source.mo5403f(i4);
                        byte[] bArr2 = C4401c.f11556a;
                        int i5 = mo5403f2 & 255;
                        int i6 = C4451q.f11947a[i5];
                        byte b2 = C4451q.f11948b[i5];
                        j3 = (j3 << b2) | i6;
                        i3 += b2;
                        while (i3 >= 8) {
                            i3 -= 8;
                            sink.mo5388n((int) (j3 >> i3));
                        }
                    }
                    if (i3 > 0) {
                        sink.mo5388n((int) ((255 >>> i3) | (j3 << (8 - i3))));
                    }
                    C4747i m5353D = sink.m5353D();
                    m5165f(m5353D.mo5400c(), 127, 128);
                    this.f11812j.m5370X(m5353D);
                    return;
                }
            }
            m5165f(source.mo5400c(), 127, 0);
            this.f11812j.m5370X(source);
        }

        /* renamed from: e */
        public final void m5164e(@NotNull List<C4437c> headerBlock) {
            int i2;
            int i3;
            Intrinsics.checkParameterIsNotNull(headerBlock, "headerBlock");
            if (this.f11804b) {
                int i4 = this.f11803a;
                if (i4 < this.f11805c) {
                    m5165f(i4, 31, 32);
                }
                this.f11804b = false;
                this.f11803a = Integer.MAX_VALUE;
                m5165f(this.f11805c, 31, 32);
            }
            int size = headerBlock.size();
            for (int i5 = 0; i5 < size; i5++) {
                C4437c c4437c = headerBlock.get(i5);
                C4747i mo5406i = c4437c.f11790h.mo5406i();
                C4747i c4747i = c4437c.f11791i;
                C4438d c4438d = C4438d.f11794c;
                Integer num = C4438d.f11793b.get(mo5406i);
                if (num != null) {
                    i2 = num.intValue() + 1;
                    if (2 <= i2 && 7 >= i2) {
                        C4437c[] c4437cArr = C4438d.f11792a;
                        if (Intrinsics.areEqual(c4437cArr[i2 - 1].f11791i, c4747i)) {
                            i3 = i2;
                        } else if (Intrinsics.areEqual(c4437cArr[i2].f11791i, c4747i)) {
                            i3 = i2;
                            i2++;
                        }
                    }
                    i3 = i2;
                    i2 = -1;
                } else {
                    i2 = -1;
                    i3 = -1;
                }
                if (i2 == -1) {
                    int i6 = this.f11807e + 1;
                    int length = this.f11806d.length;
                    while (true) {
                        if (i6 >= length) {
                            break;
                        }
                        C4437c c4437c2 = this.f11806d[i6];
                        if (c4437c2 == null) {
                            Intrinsics.throwNpe();
                        }
                        if (Intrinsics.areEqual(c4437c2.f11790h, mo5406i)) {
                            C4437c c4437c3 = this.f11806d[i6];
                            if (c4437c3 == null) {
                                Intrinsics.throwNpe();
                            }
                            if (Intrinsics.areEqual(c4437c3.f11791i, c4747i)) {
                                int i7 = i6 - this.f11807e;
                                C4438d c4438d2 = C4438d.f11794c;
                                i2 = C4438d.f11792a.length + i7;
                                break;
                            } else if (i3 == -1) {
                                int i8 = i6 - this.f11807e;
                                C4438d c4438d3 = C4438d.f11794c;
                                i3 = i8 + C4438d.f11792a.length;
                            }
                        }
                        i6++;
                    }
                }
                if (i2 != -1) {
                    m5165f(i2, 127, 128);
                } else if (i3 == -1) {
                    this.f11812j.m5374a0(64);
                    m5163d(mo5406i);
                    m5163d(c4747i);
                    m5162c(c4437c);
                } else {
                    C4747i prefix = C4437c.f11783a;
                    Objects.requireNonNull(mo5406i);
                    Intrinsics.checkNotNullParameter(prefix, "prefix");
                    if (mo5406i.mo5404g(0, prefix, 0, prefix.mo5400c()) && (!Intrinsics.areEqual(C4437c.f11788f, mo5406i))) {
                        m5165f(i3, 15, 0);
                        m5163d(c4747i);
                    } else {
                        m5165f(i3, 63, 64);
                        m5163d(c4747i);
                        m5162c(c4437c);
                    }
                }
            }
        }

        /* renamed from: f */
        public final void m5165f(int i2, int i3, int i4) {
            if (i2 < i3) {
                this.f11812j.m5374a0(i2 | i4);
                return;
            }
            this.f11812j.m5374a0(i4 | i3);
            int i5 = i2 - i3;
            while (i5 >= 128) {
                this.f11812j.m5374a0(128 | (i5 & 127));
                i5 >>>= 7;
            }
            this.f11812j.m5374a0(i5);
        }
    }

    static {
        C4437c c4437c = new C4437c(C4437c.f11788f, "");
        C4747i c4747i = C4437c.f11785c;
        C4747i c4747i2 = C4437c.f11786d;
        C4747i c4747i3 = C4437c.f11787e;
        C4747i c4747i4 = C4437c.f11784b;
        C4437c[] c4437cArr = {c4437c, new C4437c(c4747i, "GET"), new C4437c(c4747i, "POST"), new C4437c(c4747i2, "/"), new C4437c(c4747i2, "/index.html"), new C4437c(c4747i3, "http"), new C4437c(c4747i3, "https"), new C4437c(c4747i4, "200"), new C4437c(c4747i4, "204"), new C4437c(c4747i4, "206"), new C4437c(c4747i4, "304"), new C4437c(c4747i4, "400"), new C4437c(c4747i4, "404"), new C4437c(c4747i4, "500"), new C4437c("accept-charset", ""), new C4437c("accept-encoding", "gzip, deflate"), new C4437c("accept-language", ""), new C4437c("accept-ranges", ""), new C4437c("accept", ""), new C4437c("access-control-allow-origin", ""), new C4437c("age", ""), new C4437c("allow", ""), new C4437c("authorization", ""), new C4437c("cache-control", ""), new C4437c("content-disposition", ""), new C4437c("content-encoding", ""), new C4437c("content-language", ""), new C4437c("content-length", ""), new C4437c("content-location", ""), new C4437c("content-range", ""), new C4437c("content-type", ""), new C4437c("cookie", ""), new C4437c("date", ""), new C4437c("etag", ""), new C4437c("expect", ""), new C4437c("expires", ""), new C4437c("from", ""), new C4437c("host", ""), new C4437c("if-match", ""), new C4437c("if-modified-since", ""), new C4437c("if-none-match", ""), new C4437c("if-range", ""), new C4437c("if-unmodified-since", ""), new C4437c("last-modified", ""), new C4437c("link", ""), new C4437c("location", ""), new C4437c("max-forwards", ""), new C4437c("proxy-authenticate", ""), new C4437c("proxy-authorization", ""), new C4437c("range", ""), new C4437c("referer", ""), new C4437c("refresh", ""), new C4437c("retry-after", ""), new C4437c("server", ""), new C4437c("set-cookie", ""), new C4437c("strict-transport-security", ""), new C4437c("transfer-encoding", ""), new C4437c("user-agent", ""), new C4437c("vary", ""), new C4437c("via", ""), new C4437c("www-authenticate", "")};
        f11792a = c4437cArr;
        LinkedHashMap linkedHashMap = new LinkedHashMap(c4437cArr.length);
        int length = c4437cArr.length;
        for (int i2 = 0; i2 < length; i2++) {
            C4437c[] c4437cArr2 = f11792a;
            if (!linkedHashMap.containsKey(c4437cArr2[i2].f11790h)) {
                linkedHashMap.put(c4437cArr2[i2].f11790h, Integer.valueOf(i2));
            }
        }
        Map<C4747i, Integer> unmodifiableMap = Collections.unmodifiableMap(linkedHashMap);
        Intrinsics.checkExpressionValueIsNotNull(unmodifiableMap, "Collections.unmodifiableMap(result)");
        f11793b = unmodifiableMap;
    }

    @NotNull
    /* renamed from: a */
    public final C4747i m5152a(@NotNull C4747i name) {
        Intrinsics.checkParameterIsNotNull(name, "name");
        int mo5400c = name.mo5400c();
        for (int i2 = 0; i2 < mo5400c; i2++) {
            byte b2 = (byte) 65;
            byte b3 = (byte) 90;
            byte mo5403f = name.mo5403f(i2);
            if (b2 <= mo5403f && b3 >= mo5403f) {
                StringBuilder m586H = C1499a.m586H("PROTOCOL_ERROR response malformed: mixed case name: ");
                m586H.append(name.m5407j());
                throw new IOException(m586H.toString());
            }
        }
        return name;
    }
}
