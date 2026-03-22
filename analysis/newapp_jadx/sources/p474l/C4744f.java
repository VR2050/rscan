package p474l;

import androidx.work.WorkRequest;
import com.alibaba.fastjson.asm.Opcodes;
import java.io.EOFException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.charset.Charset;
import java.util.Objects;
import kotlin.UShort;
import kotlin.collections.ArraysKt___ArraysJvmKt;
import kotlin.jvm.JvmField;
import kotlin.jvm.JvmName;
import kotlin.jvm.internal.ByteCompanionObject;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p474l.p475b0.C4739a;
import p474l.p475b0.C4740b;

/* renamed from: l.f */
/* loaded from: classes3.dex */
public final class C4744f implements InterfaceC4746h, InterfaceC4745g, Cloneable, ByteChannel {

    /* renamed from: c */
    @JvmField
    @Nullable
    public C4759u f12132c;

    /* renamed from: e */
    public long f12133e;

    @Override // p474l.InterfaceC4746h
    /* renamed from: A */
    public boolean mo5350A(long j2) {
        return this.f12133e >= j2;
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: B */
    public String mo5351B() {
        return mo5390r(Long.MAX_VALUE);
    }

    /* renamed from: C */
    public long m5352C(byte b2, long j2, long j3) {
        C4759u c4759u;
        long j4 = 0;
        if (!(0 <= j2 && j3 >= j2)) {
            StringBuilder m586H = C1499a.m586H("size=");
            m586H.append(this.f12133e);
            m586H.append(" fromIndex=");
            m586H.append(j2);
            m586H.append(" toIndex=");
            m586H.append(j3);
            throw new IllegalArgumentException(m586H.toString().toString());
        }
        long j5 = this.f12133e;
        if (j3 > j5) {
            j3 = j5;
        }
        if (j2 != j3 && (c4759u = this.f12132c) != null) {
            if (j5 - j2 < j2) {
                while (j5 > j2) {
                    c4759u = c4759u.f12173g;
                    Intrinsics.checkNotNull(c4759u);
                    j5 -= c4759u.f12169c - c4759u.f12168b;
                }
                while (j5 < j3) {
                    byte[] bArr = c4759u.f12167a;
                    int min = (int) Math.min(c4759u.f12169c, (c4759u.f12168b + j3) - j5);
                    for (int i2 = (int) ((c4759u.f12168b + j2) - j5); i2 < min; i2++) {
                        if (bArr[i2] == b2) {
                            return (i2 - c4759u.f12168b) + j5;
                        }
                    }
                    j5 += c4759u.f12169c - c4759u.f12168b;
                    c4759u = c4759u.f12172f;
                    Intrinsics.checkNotNull(c4759u);
                    j2 = j5;
                }
            } else {
                while (true) {
                    long j6 = (c4759u.f12169c - c4759u.f12168b) + j4;
                    if (j6 > j2) {
                        break;
                    }
                    c4759u = c4759u.f12172f;
                    Intrinsics.checkNotNull(c4759u);
                    j4 = j6;
                }
                while (j4 < j3) {
                    byte[] bArr2 = c4759u.f12167a;
                    int min2 = (int) Math.min(c4759u.f12169c, (c4759u.f12168b + j3) - j4);
                    for (int i3 = (int) ((c4759u.f12168b + j2) - j4); i3 < min2; i3++) {
                        if (bArr2[i3] == b2) {
                            return (i3 - c4759u.f12168b) + j4;
                        }
                    }
                    j4 += c4759u.f12169c - c4759u.f12168b;
                    c4759u = c4759u.f12172f;
                    Intrinsics.checkNotNull(c4759u);
                    j2 = j4;
                }
            }
        }
        return -1L;
    }

    @NotNull
    /* renamed from: D */
    public C4747i m5353D() {
        return mo5380f(this.f12133e);
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x0095  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00a7 A[EDGE_INSN: B:46:0x00a7->B:40:0x00a7 BREAK  A[LOOP:0: B:4:0x000f->B:45:?], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:47:0x009f  */
    /* renamed from: E */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long m5354E() {
        /*
            r17 = this;
            r0 = r17
            long r1 = r0.f12133e
            r3 = 0
            int r5 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r5 == 0) goto Lb2
            r1 = -7
            r5 = 0
            r6 = 0
            r7 = 0
        Lf:
            l.u r8 = r0.f12132c
            kotlin.jvm.internal.Intrinsics.checkNotNull(r8)
            byte[] r9 = r8.f12167a
            int r10 = r8.f12168b
            int r11 = r8.f12169c
        L1a:
            if (r10 >= r11) goto L93
            r12 = r9[r10]
            r13 = 48
            byte r13 = (byte) r13
            if (r12 < r13) goto L68
            r14 = 57
            byte r14 = (byte) r14
            if (r12 > r14) goto L68
            int r13 = r13 - r12
            r14 = -922337203685477580(0xf333333333333334, double:-8.390303882365713E246)
            int r16 = (r3 > r14 ? 1 : (r3 == r14 ? 0 : -1))
            if (r16 < 0) goto L41
            if (r16 != 0) goto L3a
            long r14 = (long) r13
            int r16 = (r14 > r1 ? 1 : (r14 == r1 ? 0 : -1))
            if (r16 >= 0) goto L3a
            goto L41
        L3a:
            r14 = 10
            long r3 = r3 * r14
            long r12 = (long) r13
            long r3 = r3 + r12
            goto L73
        L41:
            l.f r1 = new l.f
            r1.<init>()
            r1.mo5361N(r3)
            r1.m5374a0(r12)
            if (r6 != 0) goto L51
            r1.readByte()
        L51:
            java.lang.NumberFormatException r2 = new java.lang.NumberFormatException
            java.lang.String r3 = "Number too large: "
            java.lang.StringBuilder r3 = p005b.p131d.p132a.p133a.C1499a.m586H(r3)
            java.lang.String r1 = r1.m5365S()
            r3.append(r1)
            java.lang.String r1 = r3.toString()
            r2.<init>(r1)
            throw r2
        L68:
            r13 = 45
            byte r13 = (byte) r13
            if (r12 != r13) goto L78
            if (r5 != 0) goto L78
            r12 = 1
            long r1 = r1 - r12
            r6 = 1
        L73:
            int r10 = r10 + 1
            int r5 = r5 + 1
            goto L1a
        L78:
            if (r5 == 0) goto L7c
            r7 = 1
            goto L93
        L7c:
            java.lang.NumberFormatException r1 = new java.lang.NumberFormatException
            java.lang.String r2 = "Expected leading [0-9] or '-' character but was 0x"
            java.lang.StringBuilder r2 = p005b.p131d.p132a.p133a.C1499a.m586H(r2)
            java.lang.String r3 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2439V1(r12)
            r2.append(r3)
            java.lang.String r2 = r2.toString()
            r1.<init>(r2)
            throw r1
        L93:
            if (r10 != r11) goto L9f
            l.u r9 = r8.m5420a()
            r0.f12132c = r9
            p474l.C4760v.m5424a(r8)
            goto La1
        L9f:
            r8.f12168b = r10
        La1:
            if (r7 != 0) goto La7
            l.u r8 = r0.f12132c
            if (r8 != 0) goto Lf
        La7:
            long r1 = r0.f12133e
            long r7 = (long) r5
            long r1 = r1 - r7
            r0.f12133e = r1
            if (r6 == 0) goto Lb0
            goto Lb1
        Lb0:
            long r3 = -r3
        Lb1:
            return r3
        Lb2:
            java.io.EOFException r1 = new java.io.EOFException
            r1.<init>()
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: p474l.C4744f.m5354E():long");
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: F */
    public byte[] mo5355F(long j2) {
        int i2 = 0;
        if (!(j2 >= 0 && j2 <= ((long) Integer.MAX_VALUE))) {
            throw new IllegalArgumentException(C1499a.m630p("byteCount: ", j2).toString());
        }
        if (this.f12133e < j2) {
            throw new EOFException();
        }
        int i3 = (int) j2;
        byte[] sink = new byte[i3];
        Intrinsics.checkNotNullParameter(sink, "sink");
        while (i2 < i3) {
            int read = read(sink, i2, i3 - i2);
            if (read == -1) {
                throw new EOFException();
            }
            i2 += read;
        }
        return sink;
    }

    @Override // p474l.InterfaceC4745g
    /* renamed from: G */
    public /* bridge */ /* synthetic */ InterfaceC4745g mo5356G(byte[] bArr) {
        m5371Y(bArr);
        return this;
    }

    @Override // p474l.InterfaceC4745g
    /* renamed from: H */
    public /* bridge */ /* synthetic */ InterfaceC4745g mo5357H(C4747i c4747i) {
        m5370X(c4747i);
        return this;
    }

    /* renamed from: I */
    public short m5358I() {
        int readShort = readShort() & UShort.MAX_VALUE;
        return (short) (((readShort & 255) << 8) | ((65280 & readShort) >>> 8));
    }

    @Override // p474l.InterfaceC4764z
    /* renamed from: J */
    public long mo4924J(@NotNull C4744f sink, long j2) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (!(j2 >= 0)) {
            throw new IllegalArgumentException(C1499a.m630p("byteCount < 0: ", j2).toString());
        }
        long j3 = this.f12133e;
        if (j3 == 0) {
            return -1L;
        }
        if (j2 > j3) {
            j2 = j3;
        }
        sink.mo4923x(this, j2);
        return j2;
    }

    @Override // p474l.InterfaceC4746h
    /* renamed from: K */
    public long mo5359K(@NotNull InterfaceC4762x sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        long j2 = this.f12133e;
        if (j2 > 0) {
            ((C4744f) sink).mo4923x(this, j2);
        }
        return j2;
    }

    @Override // p474l.InterfaceC4746h
    /* renamed from: M */
    public void mo5360M(long j2) {
        if (this.f12133e < j2) {
            throw new EOFException();
        }
    }

    @NotNull
    /* renamed from: P */
    public String m5362P(long j2, @NotNull Charset charset) {
        Intrinsics.checkNotNullParameter(charset, "charset");
        if (!(j2 >= 0 && j2 <= ((long) Integer.MAX_VALUE))) {
            throw new IllegalArgumentException(C1499a.m630p("byteCount: ", j2).toString());
        }
        if (this.f12133e < j2) {
            throw new EOFException();
        }
        if (j2 == 0) {
            return "";
        }
        C4759u c4759u = this.f12132c;
        Intrinsics.checkNotNull(c4759u);
        int i2 = c4759u.f12168b;
        if (i2 + j2 > c4759u.f12169c) {
            return new String(mo5355F(j2), charset);
        }
        int i3 = (int) j2;
        String str = new String(c4759u.f12167a, i2, i3, charset);
        int i4 = c4759u.f12168b + i3;
        c4759u.f12168b = i4;
        this.f12133e -= j2;
        if (i4 == c4759u.f12169c) {
            this.f12132c = c4759u.m5420a();
            C4760v.m5424a(c4759u);
        }
        return str;
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x008f  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x009d  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00a1 A[EDGE_INSN: B:39:0x00a1->B:36:0x00a1 BREAK  A[LOOP:0: B:4:0x000b->B:38:?], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0099  */
    @Override // p474l.InterfaceC4746h
    /* renamed from: Q */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long mo5363Q() {
        /*
            r15 = this;
            long r0 = r15.f12133e
            r2 = 0
            int r4 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r4 == 0) goto La8
            r0 = 0
            r1 = 0
            r4 = r2
        Lb:
            l.u r6 = r15.f12132c
            kotlin.jvm.internal.Intrinsics.checkNotNull(r6)
            byte[] r7 = r6.f12167a
            int r8 = r6.f12168b
            int r9 = r6.f12169c
        L16:
            if (r8 >= r9) goto L8d
            r10 = r7[r8]
            r11 = 48
            byte r11 = (byte) r11
            if (r10 < r11) goto L27
            r12 = 57
            byte r12 = (byte) r12
            if (r10 > r12) goto L27
            int r11 = r10 - r11
            goto L40
        L27:
            r11 = 97
            byte r11 = (byte) r11
            if (r10 < r11) goto L32
            r12 = 102(0x66, float:1.43E-43)
            byte r12 = (byte) r12
            if (r10 > r12) goto L32
            goto L3c
        L32:
            r11 = 65
            byte r11 = (byte) r11
            if (r10 < r11) goto L72
            r12 = 70
            byte r12 = (byte) r12
            if (r10 > r12) goto L72
        L3c:
            int r11 = r10 - r11
            int r11 = r11 + 10
        L40:
            r12 = -1152921504606846976(0xf000000000000000, double:-3.105036184601418E231)
            long r12 = r12 & r4
            int r14 = (r12 > r2 ? 1 : (r12 == r2 ? 0 : -1))
            if (r14 != 0) goto L50
            r10 = 4
            long r4 = r4 << r10
            long r10 = (long) r11
            long r4 = r4 | r10
            int r8 = r8 + 1
            int r0 = r0 + 1
            goto L16
        L50:
            l.f r0 = new l.f
            r0.<init>()
            r0.mo5397z(r4)
            r0.m5374a0(r10)
            java.lang.NumberFormatException r1 = new java.lang.NumberFormatException
            java.lang.String r2 = "Number too large: "
            java.lang.StringBuilder r2 = p005b.p131d.p132a.p133a.C1499a.m586H(r2)
            java.lang.String r0 = r0.m5365S()
            r2.append(r0)
            java.lang.String r0 = r2.toString()
            r1.<init>(r0)
            throw r1
        L72:
            if (r0 == 0) goto L76
            r1 = 1
            goto L8d
        L76:
            java.lang.NumberFormatException r0 = new java.lang.NumberFormatException
            java.lang.String r1 = "Expected leading [0-9a-fA-F] character but was 0x"
            java.lang.StringBuilder r1 = p005b.p131d.p132a.p133a.C1499a.m586H(r1)
            java.lang.String r2 = p005b.p199l.p200a.p201a.p250p1.C2354n.m2439V1(r10)
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            r0.<init>(r1)
            throw r0
        L8d:
            if (r8 != r9) goto L99
            l.u r7 = r6.m5420a()
            r15.f12132c = r7
            p474l.C4760v.m5424a(r6)
            goto L9b
        L99:
            r6.f12168b = r8
        L9b:
            if (r1 != 0) goto La1
            l.u r6 = r15.f12132c
            if (r6 != 0) goto Lb
        La1:
            long r1 = r15.f12133e
            long r6 = (long) r0
            long r1 = r1 - r6
            r15.f12133e = r1
            return r4
        La8:
            java.io.EOFException r0 = new java.io.EOFException
            r0.<init>()
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p474l.C4744f.mo5363Q():long");
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: R */
    public InputStream mo5364R() {
        return new a();
    }

    @NotNull
    /* renamed from: S */
    public String m5365S() {
        return m5362P(this.f12133e, Charsets.UTF_8);
    }

    @Override // p474l.InterfaceC4746h
    /* renamed from: T */
    public int mo5366T(@NotNull C4755q options) {
        Intrinsics.checkNotNullParameter(options, "options");
        int m5348b = C4739a.m5348b(this, options, false);
        if (m5348b == -1) {
            return -1;
        }
        skip(options.f12156e[m5348b].mo5400c());
        return m5348b;
    }

    /* renamed from: U */
    public int m5367U() {
        int i2;
        int i3;
        int i4;
        if (this.f12133e == 0) {
            throw new EOFException();
        }
        byte m5394v = m5394v(0L);
        if ((m5394v & ByteCompanionObject.MIN_VALUE) == 0) {
            i2 = m5394v & ByteCompanionObject.MAX_VALUE;
            i3 = 1;
            i4 = 0;
        } else if ((m5394v & 224) == 192) {
            i2 = m5394v & 31;
            i3 = 2;
            i4 = 128;
        } else if ((m5394v & 240) == 224) {
            i2 = m5394v & 15;
            i3 = 3;
            i4 = 2048;
        } else {
            if ((m5394v & 248) != 240) {
                skip(1L);
                return 65533;
            }
            i2 = m5394v & 7;
            i3 = 4;
            i4 = 65536;
        }
        long j2 = i3;
        if (this.f12133e < j2) {
            StringBuilder m588J = C1499a.m588J("size < ", i3, ": ");
            m588J.append(this.f12133e);
            m588J.append(" (to read code point prefixed 0x");
            m588J.append(C2354n.m2439V1(m5394v));
            m588J.append(')');
            throw new EOFException(m588J.toString());
        }
        for (int i5 = 1; i5 < i3; i5++) {
            long j3 = i5;
            byte m5394v2 = m5394v(j3);
            if ((m5394v2 & 192) != 128) {
                skip(j3);
                return 65533;
            }
            i2 = (i2 << 6) | (m5394v2 & 63);
        }
        skip(j2);
        if (i2 > 1114111) {
            return 65533;
        }
        if ((55296 <= i2 && 57343 >= i2) || i2 < i4) {
            return 65533;
        }
        return i2;
    }

    @NotNull
    /* renamed from: V */
    public final C4747i m5368V(int i2) {
        if (i2 == 0) {
            return C4747i.f12135c;
        }
        C2354n.m2530y(this.f12133e, 0L, i2);
        C4759u c4759u = this.f12132c;
        int i3 = 0;
        int i4 = 0;
        int i5 = 0;
        while (i4 < i2) {
            Intrinsics.checkNotNull(c4759u);
            int i6 = c4759u.f12169c;
            int i7 = c4759u.f12168b;
            if (i6 == i7) {
                throw new AssertionError("s.limit == s.pos");
            }
            i4 += i6 - i7;
            i5++;
            c4759u = c4759u.f12172f;
        }
        byte[][] bArr = new byte[i5][];
        int[] iArr = new int[i5 * 2];
        C4759u c4759u2 = this.f12132c;
        int i8 = 0;
        while (i3 < i2) {
            Intrinsics.checkNotNull(c4759u2);
            bArr[i8] = c4759u2.f12167a;
            i3 += c4759u2.f12169c - c4759u2.f12168b;
            iArr[i8] = Math.min(i3, i2);
            iArr[i8 + i5] = c4759u2.f12168b;
            c4759u2.f12170d = true;
            i8++;
            c4759u2 = c4759u2.f12172f;
        }
        return new C4761w(bArr, iArr);
    }

    @NotNull
    /* renamed from: W */
    public final C4759u m5369W(int i2) {
        if (!(i2 >= 1 && i2 <= 8192)) {
            throw new IllegalArgumentException("unexpected capacity".toString());
        }
        C4759u c4759u = this.f12132c;
        if (c4759u == null) {
            C4759u m5425b = C4760v.m5425b();
            this.f12132c = m5425b;
            m5425b.f12173g = m5425b;
            m5425b.f12172f = m5425b;
            return m5425b;
        }
        Intrinsics.checkNotNull(c4759u);
        C4759u c4759u2 = c4759u.f12173g;
        Intrinsics.checkNotNull(c4759u2);
        if (c4759u2.f12169c + i2 <= 8192 && c4759u2.f12171e) {
            return c4759u2;
        }
        C4759u m5425b2 = C4760v.m5425b();
        c4759u2.m5421b(m5425b2);
        return m5425b2;
    }

    @NotNull
    /* renamed from: X */
    public C4744f m5370X(@NotNull C4747i byteString) {
        Intrinsics.checkNotNullParameter(byteString, "byteString");
        byteString.mo5408k(this, 0, byteString.mo5400c());
        return this;
    }

    @NotNull
    /* renamed from: Y */
    public C4744f m5371Y(@NotNull byte[] source) {
        Intrinsics.checkNotNullParameter(source, "source");
        m5372Z(source, 0, source.length);
        return this;
    }

    @NotNull
    /* renamed from: Z */
    public C4744f m5372Z(@NotNull byte[] source, int i2, int i3) {
        Intrinsics.checkNotNullParameter(source, "source");
        long j2 = i3;
        C2354n.m2530y(source.length, i2, j2);
        int i4 = i3 + i2;
        while (i2 < i4) {
            C4759u m5369W = m5369W(1);
            int min = Math.min(i4 - i2, 8192 - m5369W.f12169c);
            int i5 = i2 + min;
            ArraysKt___ArraysJvmKt.copyInto(source, m5369W.f12167a, m5369W.f12169c, i2, i5);
            m5369W.f12169c += min;
            i2 = i5;
        }
        this.f12133e += j2;
        return this;
    }

    @Override // p474l.InterfaceC4745g
    /* renamed from: a */
    public /* bridge */ /* synthetic */ InterfaceC4745g mo5373a(byte[] bArr, int i2, int i3) {
        m5372Z(bArr, i2, i3);
        return this;
    }

    @NotNull
    /* renamed from: a0 */
    public C4744f m5374a0(int i2) {
        C4759u m5369W = m5369W(1);
        byte[] bArr = m5369W.f12167a;
        int i3 = m5369W.f12169c;
        m5369W.f12169c = i3 + 1;
        bArr[i3] = (byte) i2;
        this.f12133e++;
        return this;
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: b0, reason: merged with bridge method [inline-methods] */
    public C4744f mo5361N(long j2) {
        if (j2 == 0) {
            m5374a0(48);
        } else {
            boolean z = false;
            int i2 = 1;
            if (j2 < 0) {
                j2 = -j2;
                if (j2 < 0) {
                    m5381f0("-9223372036854775808");
                } else {
                    z = true;
                }
            }
            if (j2 >= 100000000) {
                i2 = j2 < 1000000000000L ? j2 < 10000000000L ? j2 < 1000000000 ? 9 : 10 : j2 < 100000000000L ? 11 : 12 : j2 < 1000000000000000L ? j2 < 10000000000000L ? 13 : j2 < 100000000000000L ? 14 : 15 : j2 < 100000000000000000L ? j2 < 10000000000000000L ? 16 : 17 : j2 < 1000000000000000000L ? 18 : 19;
            } else if (j2 >= WorkRequest.MIN_BACKOFF_MILLIS) {
                i2 = j2 < 1000000 ? j2 < 100000 ? 5 : 6 : j2 < 10000000 ? 7 : 8;
            } else if (j2 >= 100) {
                i2 = j2 < 1000 ? 3 : 4;
            } else if (j2 >= 10) {
                i2 = 2;
            }
            if (z) {
                i2++;
            }
            C4759u m5369W = m5369W(i2);
            byte[] bArr = m5369W.f12167a;
            int i3 = m5369W.f12169c + i2;
            while (j2 != 0) {
                long j3 = 10;
                i3--;
                bArr[i3] = C4739a.f12126a[(int) (j2 % j3)];
                j2 /= j3;
            }
            if (z) {
                bArr[i3 - 1] = (byte) 45;
            }
            m5369W.f12169c += i2;
            this.f12133e += i2;
        }
        return this;
    }

    @Override // p474l.InterfaceC4764z
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5044c() {
        return C4737a0.f12115a;
    }

    @Override // p474l.InterfaceC4745g
    @NotNull
    /* renamed from: c0, reason: merged with bridge method [inline-methods] */
    public C4744f mo5397z(long j2) {
        if (j2 == 0) {
            m5374a0(48);
        } else {
            long j3 = (j2 >>> 1) | j2;
            long j4 = j3 | (j3 >>> 2);
            long j5 = j4 | (j4 >>> 4);
            long j6 = j5 | (j5 >>> 8);
            long j7 = j6 | (j6 >>> 16);
            long j8 = j7 | (j7 >>> 32);
            long j9 = j8 - ((j8 >>> 1) & 6148914691236517205L);
            long j10 = ((j9 >>> 2) & 3689348814741910323L) + (j9 & 3689348814741910323L);
            long j11 = ((j10 >>> 4) + j10) & 1085102592571150095L;
            long j12 = j11 + (j11 >>> 8);
            long j13 = j12 + (j12 >>> 16);
            int i2 = (int) ((((j13 & 63) + ((j13 >>> 32) & 63)) + 3) / 4);
            C4759u m5369W = m5369W(i2);
            byte[] bArr = m5369W.f12167a;
            int i3 = m5369W.f12169c;
            for (int i4 = (i3 + i2) - 1; i4 >= i3; i4--) {
                bArr[i4] = C4739a.f12126a[(int) (15 & j2)];
                j2 >>>= 4;
            }
            m5369W.f12169c += i2;
            this.f12133e += i2;
        }
        return this;
    }

    @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
    }

    @NotNull
    /* renamed from: d, reason: merged with bridge method [inline-methods] */
    public C4744f clone() {
        C4744f c4744f = new C4744f();
        if (this.f12133e != 0) {
            C4759u c4759u = this.f12132c;
            Intrinsics.checkNotNull(c4759u);
            C4759u m5422c = c4759u.m5422c();
            c4744f.f12132c = m5422c;
            m5422c.f12173g = m5422c;
            m5422c.f12172f = m5422c;
            for (C4759u c4759u2 = c4759u.f12172f; c4759u2 != c4759u; c4759u2 = c4759u2.f12172f) {
                C4759u c4759u3 = m5422c.f12173g;
                Intrinsics.checkNotNull(c4759u3);
                Intrinsics.checkNotNull(c4759u2);
                c4759u3.m5421b(c4759u2.m5422c());
            }
            c4744f.f12133e = this.f12133e;
        }
        return c4744f;
    }

    @NotNull
    /* renamed from: d0 */
    public C4744f m5378d0(int i2) {
        C4759u m5369W = m5369W(4);
        byte[] bArr = m5369W.f12167a;
        int i3 = m5369W.f12169c;
        int i4 = i3 + 1;
        bArr[i3] = (byte) ((i2 >>> 24) & 255);
        int i5 = i4 + 1;
        bArr[i4] = (byte) ((i2 >>> 16) & 255);
        int i6 = i5 + 1;
        bArr[i5] = (byte) ((i2 >>> 8) & 255);
        bArr[i6] = (byte) (i2 & 255);
        m5369W.f12169c = i6 + 1;
        this.f12133e += 4;
        return this;
    }

    @NotNull
    /* renamed from: e0 */
    public C4744f m5379e0(int i2) {
        C4759u m5369W = m5369W(2);
        byte[] bArr = m5369W.f12167a;
        int i3 = m5369W.f12169c;
        int i4 = i3 + 1;
        bArr[i3] = (byte) ((i2 >>> 8) & 255);
        bArr[i4] = (byte) (i2 & 255);
        m5369W.f12169c = i4 + 1;
        this.f12133e += 2;
        return this;
    }

    public boolean equals(@Nullable Object obj) {
        if (this != obj) {
            if (!(obj instanceof C4744f)) {
                return false;
            }
            long j2 = this.f12133e;
            C4744f c4744f = (C4744f) obj;
            if (j2 != c4744f.f12133e) {
                return false;
            }
            if (j2 != 0) {
                C4759u c4759u = this.f12132c;
                Intrinsics.checkNotNull(c4759u);
                C4759u c4759u2 = c4744f.f12132c;
                Intrinsics.checkNotNull(c4759u2);
                int i2 = c4759u.f12168b;
                int i3 = c4759u2.f12168b;
                long j3 = 0;
                while (j3 < this.f12133e) {
                    long min = Math.min(c4759u.f12169c - i2, c4759u2.f12169c - i3);
                    long j4 = 0;
                    while (j4 < min) {
                        int i4 = i2 + 1;
                        int i5 = i3 + 1;
                        if (c4759u.f12167a[i2] != c4759u2.f12167a[i3]) {
                            return false;
                        }
                        j4++;
                        i2 = i4;
                        i3 = i5;
                    }
                    if (i2 == c4759u.f12169c) {
                        c4759u = c4759u.f12172f;
                        Intrinsics.checkNotNull(c4759u);
                        i2 = c4759u.f12168b;
                    }
                    if (i3 == c4759u2.f12169c) {
                        c4759u2 = c4759u2.f12172f;
                        Intrinsics.checkNotNull(c4759u2);
                        i3 = c4759u2.f12168b;
                    }
                    j3 += min;
                }
            }
        }
        return true;
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: f */
    public C4747i mo5380f(long j2) {
        if (!(j2 >= 0 && j2 <= ((long) Integer.MAX_VALUE))) {
            throw new IllegalArgumentException(C1499a.m630p("byteCount: ", j2).toString());
        }
        if (this.f12133e < j2) {
            throw new EOFException();
        }
        if (j2 < 4096) {
            return new C4747i(mo5355F(j2));
        }
        C4747i m5368V = m5368V((int) j2);
        skip(j2);
        return m5368V;
    }

    @NotNull
    /* renamed from: f0 */
    public C4744f m5381f0(@NotNull String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        m5382g0(string, 0, string.length());
        return this;
    }

    @Override // p474l.InterfaceC4745g, p474l.InterfaceC4762x, java.io.Flushable
    public void flush() {
    }

    @NotNull
    /* renamed from: g0 */
    public C4744f m5382g0(@NotNull String string, int i2, int i3) {
        char charAt;
        Intrinsics.checkNotNullParameter(string, "string");
        if (!(i2 >= 0)) {
            throw new IllegalArgumentException(C1499a.m626l("beginIndex < 0: ", i2).toString());
        }
        if (!(i3 >= i2)) {
            throw new IllegalArgumentException(C1499a.m629o("endIndex < beginIndex: ", i3, " < ", i2).toString());
        }
        if (!(i3 <= string.length())) {
            StringBuilder m588J = C1499a.m588J("endIndex > string.length: ", i3, " > ");
            m588J.append(string.length());
            throw new IllegalArgumentException(m588J.toString().toString());
        }
        while (i2 < i3) {
            char charAt2 = string.charAt(i2);
            if (charAt2 < 128) {
                C4759u m5369W = m5369W(1);
                byte[] bArr = m5369W.f12167a;
                int i4 = m5369W.f12169c - i2;
                int min = Math.min(i3, 8192 - i4);
                int i5 = i2 + 1;
                bArr[i2 + i4] = (byte) charAt2;
                while (true) {
                    i2 = i5;
                    if (i2 >= min || (charAt = string.charAt(i2)) >= 128) {
                        break;
                    }
                    i5 = i2 + 1;
                    bArr[i2 + i4] = (byte) charAt;
                }
                int i6 = m5369W.f12169c;
                int i7 = (i4 + i2) - i6;
                m5369W.f12169c = i6 + i7;
                this.f12133e += i7;
            } else {
                if (charAt2 < 2048) {
                    C4759u m5369W2 = m5369W(2);
                    byte[] bArr2 = m5369W2.f12167a;
                    int i8 = m5369W2.f12169c;
                    bArr2[i8] = (byte) ((charAt2 >> 6) | Opcodes.CHECKCAST);
                    bArr2[i8 + 1] = (byte) ((charAt2 & '?') | 128);
                    m5369W2.f12169c = i8 + 2;
                    this.f12133e += 2;
                } else if (charAt2 < 55296 || charAt2 > 57343) {
                    C4759u m5369W3 = m5369W(3);
                    byte[] bArr3 = m5369W3.f12167a;
                    int i9 = m5369W3.f12169c;
                    bArr3[i9] = (byte) ((charAt2 >> '\f') | 224);
                    bArr3[i9 + 1] = (byte) ((63 & (charAt2 >> 6)) | 128);
                    bArr3[i9 + 2] = (byte) ((charAt2 & '?') | 128);
                    m5369W3.f12169c = i9 + 3;
                    this.f12133e += 3;
                } else {
                    int i10 = i2 + 1;
                    char charAt3 = i10 < i3 ? string.charAt(i10) : (char) 0;
                    if (charAt2 > 56319 || 56320 > charAt3 || 57343 < charAt3) {
                        m5374a0(63);
                        i2 = i10;
                    } else {
                        int i11 = (((charAt2 & 1023) << 10) | (charAt3 & 1023)) + 65536;
                        C4759u m5369W4 = m5369W(4);
                        byte[] bArr4 = m5369W4.f12167a;
                        int i12 = m5369W4.f12169c;
                        bArr4[i12] = (byte) ((i11 >> 18) | 240);
                        bArr4[i12 + 1] = (byte) (((i11 >> 12) & 63) | 128);
                        bArr4[i12 + 2] = (byte) (((i11 >> 6) & 63) | 128);
                        bArr4[i12 + 3] = (byte) ((i11 & 63) | 128);
                        m5369W4.f12169c = i12 + 4;
                        this.f12133e += 4;
                        i2 += 2;
                    }
                }
                i2++;
            }
        }
        return this;
    }

    @Override // p474l.InterfaceC4746h, p474l.InterfaceC4745g
    @NotNull
    public C4744f getBuffer() {
        return this;
    }

    @Override // p474l.InterfaceC4745g
    /* renamed from: h */
    public /* bridge */ /* synthetic */ InterfaceC4745g mo5383h(int i2) {
        m5379e0(i2);
        return this;
    }

    @NotNull
    /* renamed from: h0 */
    public C4744f m5384h0(int i2) {
        String str;
        if (i2 < 128) {
            m5374a0(i2);
        } else if (i2 < 2048) {
            C4759u m5369W = m5369W(2);
            byte[] bArr = m5369W.f12167a;
            int i3 = m5369W.f12169c;
            bArr[i3] = (byte) ((i2 >> 6) | Opcodes.CHECKCAST);
            bArr[i3 + 1] = (byte) ((i2 & 63) | 128);
            m5369W.f12169c = i3 + 2;
            this.f12133e += 2;
        } else if (55296 <= i2 && 57343 >= i2) {
            m5374a0(63);
        } else if (i2 < 65536) {
            C4759u m5369W2 = m5369W(3);
            byte[] bArr2 = m5369W2.f12167a;
            int i4 = m5369W2.f12169c;
            bArr2[i4] = (byte) ((i2 >> 12) | 224);
            bArr2[i4 + 1] = (byte) (((i2 >> 6) & 63) | 128);
            bArr2[i4 + 2] = (byte) ((i2 & 63) | 128);
            m5369W2.f12169c = i4 + 3;
            this.f12133e += 3;
        } else {
            if (i2 > 1114111) {
                StringBuilder m586H = C1499a.m586H("Unexpected code point: 0x");
                if (i2 != 0) {
                    char[] cArr = C4740b.f12127a;
                    int i5 = 0;
                    char[] cArr2 = {cArr[(i2 >> 28) & 15], cArr[(i2 >> 24) & 15], cArr[(i2 >> 20) & 15], cArr[(i2 >> 16) & 15], cArr[(i2 >> 12) & 15], cArr[(i2 >> 8) & 15], cArr[(i2 >> 4) & 15], cArr[i2 & 15]};
                    while (i5 < 8 && cArr2[i5] == '0') {
                        i5++;
                    }
                    str = new String(cArr2, i5, 8 - i5);
                } else {
                    str = "0";
                }
                m586H.append(str);
                throw new IllegalArgumentException(m586H.toString());
            }
            C4759u m5369W3 = m5369W(4);
            byte[] bArr3 = m5369W3.f12167a;
            int i6 = m5369W3.f12169c;
            bArr3[i6] = (byte) ((i2 >> 18) | 240);
            bArr3[i6 + 1] = (byte) (((i2 >> 12) & 63) | 128);
            bArr3[i6 + 2] = (byte) (((i2 >> 6) & 63) | 128);
            bArr3[i6 + 3] = (byte) ((i2 & 63) | 128);
            m5369W3.f12169c = i6 + 4;
            this.f12133e += 4;
        }
        return this;
    }

    public int hashCode() {
        C4759u c4759u = this.f12132c;
        if (c4759u == null) {
            return 0;
        }
        int i2 = 1;
        do {
            int i3 = c4759u.f12169c;
            for (int i4 = c4759u.f12168b; i4 < i3; i4++) {
                i2 = (i2 * 31) + c4759u.f12167a[i4];
            }
            c4759u = c4759u.f12172f;
            Intrinsics.checkNotNull(c4759u);
        } while (c4759u != this.f12132c);
        return i2;
    }

    @Override // java.nio.channels.Channel
    public boolean isOpen() {
        return true;
    }

    @Override // p474l.InterfaceC4745g
    /* renamed from: j */
    public /* bridge */ /* synthetic */ InterfaceC4745g mo5385j(int i2) {
        m5378d0(i2);
        return this;
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: l */
    public byte[] mo5386l() {
        return mo5355F(this.f12133e);
    }

    @Override // p474l.InterfaceC4746h
    /* renamed from: m */
    public boolean mo5387m() {
        return this.f12133e == 0;
    }

    @Override // p474l.InterfaceC4745g
    /* renamed from: n */
    public /* bridge */ /* synthetic */ InterfaceC4745g mo5388n(int i2) {
        m5374a0(i2);
        return this;
    }

    @Override // p474l.InterfaceC4745g
    /* renamed from: p */
    public InterfaceC4745g mo5389p() {
        return this;
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: r */
    public String mo5390r(long j2) {
        if (!(j2 >= 0)) {
            throw new IllegalArgumentException(C1499a.m630p("limit < 0: ", j2).toString());
        }
        long j3 = j2 != Long.MAX_VALUE ? j2 + 1 : Long.MAX_VALUE;
        byte b2 = (byte) 10;
        long m5352C = m5352C(b2, 0L, j3);
        if (m5352C != -1) {
            return C4739a.m5347a(this, m5352C);
        }
        if (j3 < this.f12133e && m5394v(j3 - 1) == ((byte) 13) && m5394v(j3) == b2) {
            return C4739a.m5347a(this, j3);
        }
        C4744f c4744f = new C4744f();
        m5392t(c4744f, 0L, Math.min(32, this.f12133e));
        StringBuilder m586H = C1499a.m586H("\\n not found: limit=");
        m586H.append(Math.min(this.f12133e, j2));
        m586H.append(" content=");
        m586H.append(c4744f.m5353D().mo5401d());
        m586H.append(Typography.ellipsis);
        throw new EOFException(m586H.toString());
    }

    @Override // java.nio.channels.ReadableByteChannel
    public int read(@NotNull ByteBuffer sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        C4759u c4759u = this.f12132c;
        if (c4759u == null) {
            return -1;
        }
        int min = Math.min(sink.remaining(), c4759u.f12169c - c4759u.f12168b);
        sink.put(c4759u.f12167a, c4759u.f12168b, min);
        int i2 = c4759u.f12168b + min;
        c4759u.f12168b = i2;
        this.f12133e -= min;
        if (i2 == c4759u.f12169c) {
            this.f12132c = c4759u.m5420a();
            C4760v.m5424a(c4759u);
        }
        return min;
    }

    @Override // p474l.InterfaceC4746h
    public byte readByte() {
        if (this.f12133e == 0) {
            throw new EOFException();
        }
        C4759u c4759u = this.f12132c;
        Intrinsics.checkNotNull(c4759u);
        int i2 = c4759u.f12168b;
        int i3 = c4759u.f12169c;
        int i4 = i2 + 1;
        byte b2 = c4759u.f12167a[i2];
        this.f12133e--;
        if (i4 == i3) {
            this.f12132c = c4759u.m5420a();
            C4760v.m5424a(c4759u);
        } else {
            c4759u.f12168b = i4;
        }
        return b2;
    }

    @Override // p474l.InterfaceC4746h
    public int readInt() {
        if (this.f12133e < 4) {
            throw new EOFException();
        }
        C4759u c4759u = this.f12132c;
        Intrinsics.checkNotNull(c4759u);
        int i2 = c4759u.f12168b;
        int i3 = c4759u.f12169c;
        if (i3 - i2 < 4) {
            return ((readByte() & 255) << 24) | ((readByte() & 255) << 16) | ((readByte() & 255) << 8) | (readByte() & 255);
        }
        byte[] bArr = c4759u.f12167a;
        int i4 = i2 + 1;
        int i5 = i4 + 1;
        int i6 = ((bArr[i2] & 255) << 24) | ((bArr[i4] & 255) << 16);
        int i7 = i5 + 1;
        int i8 = i6 | ((bArr[i5] & 255) << 8);
        int i9 = i7 + 1;
        int i10 = i8 | (bArr[i7] & 255);
        this.f12133e -= 4;
        if (i9 == i3) {
            this.f12132c = c4759u.m5420a();
            C4760v.m5424a(c4759u);
        } else {
            c4759u.f12168b = i9;
        }
        return i10;
    }

    @Override // p474l.InterfaceC4746h
    public short readShort() {
        if (this.f12133e < 2) {
            throw new EOFException();
        }
        C4759u c4759u = this.f12132c;
        Intrinsics.checkNotNull(c4759u);
        int i2 = c4759u.f12168b;
        int i3 = c4759u.f12169c;
        if (i3 - i2 < 2) {
            return (short) (((readByte() & 255) << 8) | (readByte() & 255));
        }
        byte[] bArr = c4759u.f12167a;
        int i4 = i2 + 1;
        int i5 = i4 + 1;
        int i6 = ((bArr[i2] & 255) << 8) | (bArr[i4] & 255);
        this.f12133e -= 2;
        if (i5 == i3) {
            this.f12132c = c4759u.m5420a();
            C4760v.m5424a(c4759u);
        } else {
            c4759u.f12168b = i5;
        }
        return (short) i6;
    }

    /* renamed from: s */
    public final long m5391s() {
        long j2 = this.f12133e;
        if (j2 == 0) {
            return 0L;
        }
        C4759u c4759u = this.f12132c;
        Intrinsics.checkNotNull(c4759u);
        C4759u c4759u2 = c4759u.f12173g;
        Intrinsics.checkNotNull(c4759u2);
        if (c4759u2.f12169c < 8192 && c4759u2.f12171e) {
            j2 -= r3 - c4759u2.f12168b;
        }
        return j2;
    }

    @Override // p474l.InterfaceC4746h
    public void skip(long j2) {
        while (j2 > 0) {
            C4759u c4759u = this.f12132c;
            if (c4759u == null) {
                throw new EOFException();
            }
            int min = (int) Math.min(j2, c4759u.f12169c - c4759u.f12168b);
            long j3 = min;
            this.f12133e -= j3;
            j2 -= j3;
            int i2 = c4759u.f12168b + min;
            c4759u.f12168b = i2;
            if (i2 == c4759u.f12169c) {
                this.f12132c = c4759u.m5420a();
                C4760v.m5424a(c4759u);
            }
        }
    }

    @NotNull
    /* renamed from: t */
    public final C4744f m5392t(@NotNull C4744f out, long j2, long j3) {
        Intrinsics.checkNotNullParameter(out, "out");
        C2354n.m2530y(this.f12133e, j2, j3);
        if (j3 != 0) {
            out.f12133e += j3;
            C4759u c4759u = this.f12132c;
            while (true) {
                Intrinsics.checkNotNull(c4759u);
                int i2 = c4759u.f12169c;
                int i3 = c4759u.f12168b;
                if (j2 < i2 - i3) {
                    break;
                }
                j2 -= i2 - i3;
                c4759u = c4759u.f12172f;
            }
            while (j3 > 0) {
                Intrinsics.checkNotNull(c4759u);
                C4759u m5422c = c4759u.m5422c();
                int i4 = m5422c.f12168b + ((int) j2);
                m5422c.f12168b = i4;
                m5422c.f12169c = Math.min(i4 + ((int) j3), m5422c.f12169c);
                C4759u c4759u2 = out.f12132c;
                if (c4759u2 == null) {
                    m5422c.f12173g = m5422c;
                    m5422c.f12172f = m5422c;
                    out.f12132c = m5422c;
                } else {
                    Intrinsics.checkNotNull(c4759u2);
                    C4759u c4759u3 = c4759u2.f12173g;
                    Intrinsics.checkNotNull(c4759u3);
                    c4759u3.m5421b(m5422c);
                }
                j3 -= m5422c.f12169c - m5422c.f12168b;
                c4759u = c4759u.f12172f;
                j2 = 0;
            }
        }
        return this;
    }

    @NotNull
    public String toString() {
        long j2 = this.f12133e;
        if (j2 <= ((long) Integer.MAX_VALUE)) {
            return m5368V((int) j2).toString();
        }
        StringBuilder m586H = C1499a.m586H("size > Int.MAX_VALUE: ");
        m586H.append(this.f12133e);
        throw new IllegalStateException(m586H.toString().toString());
    }

    @Override // p474l.InterfaceC4745g
    /* renamed from: u */
    public /* bridge */ /* synthetic */ InterfaceC4745g mo5393u(String str) {
        m5381f0(str);
        return this;
    }

    @JvmName(name = "getByte")
    /* renamed from: v */
    public final byte m5394v(long j2) {
        C2354n.m2530y(this.f12133e, j2, 1L);
        C4759u c4759u = this.f12132c;
        if (c4759u == null) {
            Intrinsics.checkNotNull(null);
            throw null;
        }
        long j3 = this.f12133e;
        if (j3 - j2 < j2) {
            while (j3 > j2) {
                c4759u = c4759u.f12173g;
                Intrinsics.checkNotNull(c4759u);
                j3 -= c4759u.f12169c - c4759u.f12168b;
            }
            Intrinsics.checkNotNull(c4759u);
            return c4759u.f12167a[(int) ((c4759u.f12168b + j2) - j3)];
        }
        long j4 = 0;
        while (true) {
            long j5 = (c4759u.f12169c - c4759u.f12168b) + j4;
            if (j5 > j2) {
                Intrinsics.checkNotNull(c4759u);
                return c4759u.f12167a[(int) ((c4759u.f12168b + j2) - j4)];
            }
            c4759u = c4759u.f12172f;
            Intrinsics.checkNotNull(c4759u);
            j4 = j5;
        }
    }

    @Override // p474l.InterfaceC4746h
    @NotNull
    /* renamed from: w */
    public String mo5395w(@NotNull Charset charset) {
        Intrinsics.checkNotNullParameter(charset, "charset");
        return m5362P(this.f12133e, charset);
    }

    @Override // java.nio.channels.WritableByteChannel
    public int write(@NotNull ByteBuffer source) {
        Intrinsics.checkNotNullParameter(source, "source");
        int remaining = source.remaining();
        int i2 = remaining;
        while (i2 > 0) {
            C4759u m5369W = m5369W(1);
            int min = Math.min(i2, 8192 - m5369W.f12169c);
            source.get(m5369W.f12167a, m5369W.f12169c, min);
            i2 -= min;
            m5369W.f12169c += min;
        }
        this.f12133e += remaining;
        return remaining;
    }

    @Override // p474l.InterfaceC4762x
    /* renamed from: x */
    public void mo4923x(@NotNull C4744f source, long j2) {
        int i2;
        C4759u c4759u;
        C4759u m5425b;
        Intrinsics.checkNotNullParameter(source, "source");
        if (!(source != this)) {
            throw new IllegalArgumentException("source == this".toString());
        }
        C2354n.m2530y(source.f12133e, 0L, j2);
        long j3 = j2;
        while (j3 > 0) {
            C4759u c4759u2 = source.f12132c;
            Intrinsics.checkNotNull(c4759u2);
            int i3 = c4759u2.f12169c;
            Intrinsics.checkNotNull(source.f12132c);
            if (j3 < i3 - r7.f12168b) {
                C4759u c4759u3 = this.f12132c;
                if (c4759u3 != null) {
                    Intrinsics.checkNotNull(c4759u3);
                    c4759u = c4759u3.f12173g;
                } else {
                    c4759u = null;
                }
                if (c4759u != null && c4759u.f12171e) {
                    if ((c4759u.f12169c + j3) - (c4759u.f12170d ? 0 : c4759u.f12168b) <= 8192) {
                        C4759u c4759u4 = source.f12132c;
                        Intrinsics.checkNotNull(c4759u4);
                        c4759u4.m5423d(c4759u, (int) j3);
                        source.f12133e -= j3;
                        this.f12133e += j3;
                        return;
                    }
                }
                C4759u c4759u5 = source.f12132c;
                Intrinsics.checkNotNull(c4759u5);
                int i4 = (int) j3;
                Objects.requireNonNull(c4759u5);
                if (!(i4 > 0 && i4 <= c4759u5.f12169c - c4759u5.f12168b)) {
                    throw new IllegalArgumentException("byteCount out of range".toString());
                }
                if (i4 >= 1024) {
                    m5425b = c4759u5.m5422c();
                } else {
                    m5425b = C4760v.m5425b();
                    byte[] bArr = c4759u5.f12167a;
                    byte[] bArr2 = m5425b.f12167a;
                    int i5 = c4759u5.f12168b;
                    ArraysKt___ArraysJvmKt.copyInto$default(bArr, bArr2, 0, i5, i5 + i4, 2, (Object) null);
                }
                m5425b.f12169c = m5425b.f12168b + i4;
                c4759u5.f12168b += i4;
                C4759u c4759u6 = c4759u5.f12173g;
                Intrinsics.checkNotNull(c4759u6);
                c4759u6.m5421b(m5425b);
                source.f12132c = m5425b;
            }
            C4759u c4759u7 = source.f12132c;
            Intrinsics.checkNotNull(c4759u7);
            long j4 = c4759u7.f12169c - c4759u7.f12168b;
            source.f12132c = c4759u7.m5420a();
            C4759u c4759u8 = this.f12132c;
            if (c4759u8 == null) {
                this.f12132c = c4759u7;
                c4759u7.f12173g = c4759u7;
                c4759u7.f12172f = c4759u7;
            } else {
                Intrinsics.checkNotNull(c4759u8);
                C4759u c4759u9 = c4759u8.f12173g;
                Intrinsics.checkNotNull(c4759u9);
                c4759u9.m5421b(c4759u7);
                C4759u c4759u10 = c4759u7.f12173g;
                if (!(c4759u10 != c4759u7)) {
                    throw new IllegalStateException("cannot compact".toString());
                }
                Intrinsics.checkNotNull(c4759u10);
                if (c4759u10.f12171e) {
                    int i6 = c4759u7.f12169c - c4759u7.f12168b;
                    C4759u c4759u11 = c4759u7.f12173g;
                    Intrinsics.checkNotNull(c4759u11);
                    int i7 = 8192 - c4759u11.f12169c;
                    C4759u c4759u12 = c4759u7.f12173g;
                    Intrinsics.checkNotNull(c4759u12);
                    if (c4759u12.f12170d) {
                        i2 = 0;
                    } else {
                        C4759u c4759u13 = c4759u7.f12173g;
                        Intrinsics.checkNotNull(c4759u13);
                        i2 = c4759u13.f12168b;
                    }
                    if (i6 <= i7 + i2) {
                        C4759u c4759u14 = c4759u7.f12173g;
                        Intrinsics.checkNotNull(c4759u14);
                        c4759u7.m5423d(c4759u14, i6);
                        c4759u7.m5420a();
                        C4760v.m5424a(c4759u7);
                    }
                }
            }
            source.f12133e -= j4;
            this.f12133e += j4;
            j3 -= j4;
        }
    }

    @Override // p474l.InterfaceC4745g
    /* renamed from: y */
    public long mo5396y(@NotNull InterfaceC4764z source) {
        Intrinsics.checkNotNullParameter(source, "source");
        long j2 = 0;
        while (true) {
            long mo4924J = source.mo4924J(this, 8192);
            if (mo4924J == -1) {
                return j2;
            }
            j2 += mo4924J;
        }
    }

    /* renamed from: l.f$a */
    public static final class a extends InputStream {
        public a() {
        }

        @Override // java.io.InputStream
        public int available() {
            return (int) Math.min(C4744f.this.f12133e, Integer.MAX_VALUE);
        }

        @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
        }

        @Override // java.io.InputStream
        public int read() {
            C4744f c4744f = C4744f.this;
            if (c4744f.f12133e > 0) {
                return c4744f.readByte() & 255;
            }
            return -1;
        }

        @NotNull
        public String toString() {
            return C4744f.this + ".inputStream()";
        }

        @Override // java.io.InputStream
        public int read(@NotNull byte[] sink, int i2, int i3) {
            Intrinsics.checkNotNullParameter(sink, "sink");
            return C4744f.this.read(sink, i2, i3);
        }
    }

    public int read(@NotNull byte[] sink, int i2, int i3) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        C2354n.m2530y(sink.length, i2, i3);
        C4759u c4759u = this.f12132c;
        if (c4759u == null) {
            return -1;
        }
        int min = Math.min(i3, c4759u.f12169c - c4759u.f12168b);
        byte[] bArr = c4759u.f12167a;
        int i4 = c4759u.f12168b;
        ArraysKt___ArraysJvmKt.copyInto(bArr, sink, i2, i4, i4 + min);
        int i5 = c4759u.f12168b + min;
        c4759u.f12168b = i5;
        this.f12133e -= min;
        if (i5 != c4759u.f12169c) {
            return min;
        }
        this.f12132c = c4759u.m5420a();
        C4760v.m5424a(c4759u);
        return min;
    }
}
