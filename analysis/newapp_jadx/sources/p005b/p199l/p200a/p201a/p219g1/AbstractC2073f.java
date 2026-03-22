package p005b.p199l.p200a.p201a.p219g1;

import android.annotation.TargetApi;
import android.media.MediaCodec;
import android.media.MediaCrypto;
import android.media.MediaCryptoException;
import android.media.MediaFormat;
import android.os.Bundle;
import android.os.SystemClock;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.AbstractC2397u;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.p204c1.C1944d;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p005b.p199l.p200a.p201a.p205d1.C1957h;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1952c;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p219g1.C2075h;
import p005b.p199l.p200a.p201a.p250p1.C2340b0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.g1.f */
/* loaded from: classes.dex */
public abstract class AbstractC2073f extends AbstractC2397u {

    /* renamed from: o */
    public static final byte[] f4288o = {0, 0, 1, 103, 66, -64, 11, -38, 37, -112, 0, 0, 1, 104, -50, 15, 19, 32, 0, 0, 1, 101, -120, -124, 13, -50, 113, 24, -96, 0, 47, -65, 28, 49, -61, 39, 93, 120};

    /* renamed from: A */
    @Nullable
    public Format f4289A;

    /* renamed from: B */
    public Format f4290B;

    /* renamed from: C */
    @Nullable
    public InterfaceC1952c<C1957h> f4291C;

    /* renamed from: D */
    @Nullable
    public InterfaceC1952c<C1957h> f4292D;

    /* renamed from: E */
    @Nullable
    public MediaCrypto f4293E;

    /* renamed from: F */
    public boolean f4294F;

    /* renamed from: G */
    public long f4295G;

    /* renamed from: H */
    public float f4296H;

    /* renamed from: I */
    @Nullable
    public MediaCodec f4297I;

    /* renamed from: J */
    @Nullable
    public Format f4298J;

    /* renamed from: K */
    public float f4299K;

    /* renamed from: L */
    @Nullable
    public ArrayDeque<C2072e> f4300L;

    /* renamed from: M */
    @Nullable
    public a f4301M;

    /* renamed from: N */
    @Nullable
    public C2072e f4302N;

    /* renamed from: O */
    public int f4303O;

    /* renamed from: P */
    public boolean f4304P;

    /* renamed from: Q */
    public boolean f4305Q;

    /* renamed from: R */
    public boolean f4306R;

    /* renamed from: S */
    public boolean f4307S;

    /* renamed from: T */
    public boolean f4308T;

    /* renamed from: U */
    public boolean f4309U;

    /* renamed from: V */
    public boolean f4310V;

    /* renamed from: W */
    public boolean f4311W;

    /* renamed from: X */
    public boolean f4312X;

    /* renamed from: Y */
    public ByteBuffer[] f4313Y;

    /* renamed from: Z */
    public ByteBuffer[] f4314Z;

    /* renamed from: a0 */
    public long f4315a0;

    /* renamed from: b0 */
    public int f4316b0;

    /* renamed from: c0 */
    public int f4317c0;

    /* renamed from: d0 */
    public ByteBuffer f4318d0;

    /* renamed from: e0 */
    public boolean f4319e0;

    /* renamed from: f0 */
    public boolean f4320f0;

    /* renamed from: g0 */
    public boolean f4321g0;

    /* renamed from: h0 */
    public int f4322h0;

    /* renamed from: i0 */
    public int f4323i0;

    /* renamed from: j0 */
    public int f4324j0;

    /* renamed from: k0 */
    public boolean f4325k0;

    /* renamed from: l0 */
    public boolean f4326l0;

    /* renamed from: m0 */
    public long f4327m0;

    /* renamed from: n0 */
    public long f4328n0;

    /* renamed from: o0 */
    public boolean f4329o0;

    /* renamed from: p */
    public final InterfaceC2074g f4330p;

    /* renamed from: p0 */
    public boolean f4331p0;

    /* renamed from: q */
    @Nullable
    public final InterfaceC1954e<C1957h> f4332q;

    /* renamed from: q0 */
    public boolean f4333q0;

    /* renamed from: r */
    public final boolean f4334r;

    /* renamed from: r0 */
    public boolean f4335r0;

    /* renamed from: s */
    public final boolean f4336s;

    /* renamed from: s0 */
    public boolean f4337s0;

    /* renamed from: t */
    public final float f4338t;

    /* renamed from: t0 */
    public boolean f4339t0;

    /* renamed from: u */
    public final C1945e f4340u;

    /* renamed from: u0 */
    public C1944d f4341u0;

    /* renamed from: v */
    public final C1945e f4342v;

    /* renamed from: w */
    public final C2340b0<Format> f4343w;

    /* renamed from: x */
    public final ArrayList<Long> f4344x;

    /* renamed from: y */
    public final MediaCodec.BufferInfo f4345y;

    /* renamed from: z */
    public boolean f4346z;

    public AbstractC2073f(int i2, InterfaceC2074g interfaceC2074g, @Nullable InterfaceC1954e<C1957h> interfaceC1954e, boolean z, boolean z2, float f2) {
        super(i2);
        Objects.requireNonNull(interfaceC2074g);
        this.f4330p = interfaceC2074g;
        this.f4332q = interfaceC1954e;
        this.f4334r = z;
        this.f4336s = z2;
        this.f4338t = f2;
        this.f4340u = new C1945e(0);
        this.f4342v = new C1945e(0);
        this.f4343w = new C2340b0<>();
        this.f4344x = new ArrayList<>();
        this.f4345y = new MediaCodec.BufferInfo();
        this.f4322h0 = 0;
        this.f4323i0 = 0;
        this.f4324j0 = 0;
        this.f4299K = -1.0f;
        this.f4296H = 1.0f;
        this.f4295G = -9223372036854775807L;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: E */
    public final int mo1661E(Format format) {
        try {
            return mo1319m0(this.f4330p, this.f4332q, format);
        } catch (C2075h.c e2) {
            throw m2666u(e2, format);
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: G */
    public final int mo1662G() {
        return 8;
    }

    /* renamed from: H */
    public abstract int mo1304H(MediaCodec mediaCodec, C2072e c2072e, Format format, Format format2);

    /* renamed from: I */
    public abstract void mo1305I(C2072e c2072e, MediaCodec mediaCodec, Format format, @Nullable MediaCrypto mediaCrypto, float f2);

    /* renamed from: J */
    public final void m1663J() {
        if (this.f4325k0) {
            this.f4323i0 = 1;
            this.f4324j0 = 3;
        } else {
            mo1677f0();
            m1673V();
        }
    }

    /* renamed from: K */
    public final void m1664K() {
        if (C2344d0.f6035a < 23) {
            m1663J();
        } else if (!this.f4325k0) {
            m1686o0();
        } else {
            this.f4323i0 = 1;
            this.f4324j0 = 2;
        }
    }

    /* renamed from: L */
    public final boolean m1665L(long j2, long j3) {
        boolean z;
        boolean mo1315d0;
        int dequeueOutputBuffer;
        boolean z2;
        if (!(this.f4317c0 >= 0)) {
            if (this.f4308T && this.f4326l0) {
                try {
                    dequeueOutputBuffer = this.f4297I.dequeueOutputBuffer(this.f4345y, 0L);
                } catch (IllegalStateException unused) {
                    m1675c0();
                    if (this.f4331p0) {
                        mo1677f0();
                    }
                    return false;
                }
            } else {
                dequeueOutputBuffer = this.f4297I.dequeueOutputBuffer(this.f4345y, 0L);
            }
            if (dequeueOutputBuffer < 0) {
                if (dequeueOutputBuffer == -2) {
                    MediaFormat outputFormat = this.f4297I.getOutputFormat();
                    if (this.f4303O != 0 && outputFormat.getInteger("width") == 32 && outputFormat.getInteger("height") == 32) {
                        this.f4311W = true;
                    } else {
                        if (this.f4309U) {
                            outputFormat.setInteger("channel-count", 1);
                        }
                        mo1310Z(this.f4297I, outputFormat);
                    }
                    return true;
                }
                if (dequeueOutputBuffer == -3) {
                    if (C2344d0.f6035a < 21) {
                        this.f4314Z = this.f4297I.getOutputBuffers();
                    }
                    return true;
                }
                if (this.f4312X && (this.f4329o0 || this.f4323i0 == 2)) {
                    m1675c0();
                }
                return false;
            }
            if (this.f4311W) {
                this.f4311W = false;
                this.f4297I.releaseOutputBuffer(dequeueOutputBuffer, false);
                return true;
            }
            MediaCodec.BufferInfo bufferInfo = this.f4345y;
            if (bufferInfo.size == 0 && (bufferInfo.flags & 4) != 0) {
                m1675c0();
                return false;
            }
            this.f4317c0 = dequeueOutputBuffer;
            ByteBuffer outputBuffer = C2344d0.f6035a >= 21 ? this.f4297I.getOutputBuffer(dequeueOutputBuffer) : this.f4314Z[dequeueOutputBuffer];
            this.f4318d0 = outputBuffer;
            if (outputBuffer != null) {
                outputBuffer.position(this.f4345y.offset);
                ByteBuffer byteBuffer = this.f4318d0;
                MediaCodec.BufferInfo bufferInfo2 = this.f4345y;
                byteBuffer.limit(bufferInfo2.offset + bufferInfo2.size);
            }
            long j4 = this.f4345y.presentationTimeUs;
            int size = this.f4344x.size();
            int i2 = 0;
            while (true) {
                if (i2 >= size) {
                    z2 = false;
                    break;
                }
                if (this.f4344x.get(i2).longValue() == j4) {
                    this.f4344x.remove(i2);
                    z2 = true;
                    break;
                }
                i2++;
            }
            this.f4319e0 = z2;
            long j5 = this.f4328n0;
            long j6 = this.f4345y.presentationTimeUs;
            this.f4320f0 = j5 == j6;
            Format m2304e = this.f4343w.m2304e(j6);
            if (m2304e != null) {
                this.f4290B = m2304e;
            }
        }
        if (this.f4308T && this.f4326l0) {
            try {
                MediaCodec mediaCodec = this.f4297I;
                ByteBuffer byteBuffer2 = this.f4318d0;
                int i3 = this.f4317c0;
                MediaCodec.BufferInfo bufferInfo3 = this.f4345y;
                z = false;
                try {
                    mo1315d0 = mo1315d0(j2, j3, mediaCodec, byteBuffer2, i3, bufferInfo3.flags, bufferInfo3.presentationTimeUs, this.f4319e0, this.f4320f0, this.f4290B);
                } catch (IllegalStateException unused2) {
                    m1675c0();
                    if (this.f4331p0) {
                        mo1677f0();
                    }
                    return z;
                }
            } catch (IllegalStateException unused3) {
                z = false;
            }
        } else {
            z = false;
            MediaCodec mediaCodec2 = this.f4297I;
            ByteBuffer byteBuffer3 = this.f4318d0;
            int i4 = this.f4317c0;
            MediaCodec.BufferInfo bufferInfo4 = this.f4345y;
            mo1315d0 = mo1315d0(j2, j3, mediaCodec2, byteBuffer3, i4, bufferInfo4.flags, bufferInfo4.presentationTimeUs, this.f4319e0, this.f4320f0, this.f4290B);
        }
        if (mo1315d0) {
            mo1311a0(this.f4345y.presentationTimeUs);
            boolean z3 = (this.f4345y.flags & 4) != 0;
            m1679i0();
            if (!z3) {
                return true;
            }
            m1675c0();
        }
        return z;
    }

    /* JADX WARN: Removed duplicated region for block: B:86:0x0167 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0168  */
    /* renamed from: M */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m1666M() {
        /*
            Method dump skipped, instructions count: 585
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p219g1.AbstractC2073f.m1666M():boolean");
    }

    /* renamed from: N */
    public final boolean m1667N() {
        boolean mo1668O = mo1668O();
        if (mo1668O) {
            m1673V();
        }
        return mo1668O;
    }

    /* renamed from: O */
    public boolean mo1668O() {
        MediaCodec mediaCodec = this.f4297I;
        if (mediaCodec == null) {
            return false;
        }
        if (this.f4324j0 == 3 || this.f4306R || (this.f4307S && this.f4326l0)) {
            mo1677f0();
            return true;
        }
        mediaCodec.flush();
        m1678h0();
        m1679i0();
        this.f4315a0 = -9223372036854775807L;
        this.f4326l0 = false;
        this.f4325k0 = false;
        this.f4335r0 = true;
        this.f4310V = false;
        this.f4311W = false;
        this.f4319e0 = false;
        this.f4320f0 = false;
        this.f4333q0 = false;
        this.f4344x.clear();
        this.f4327m0 = -9223372036854775807L;
        this.f4328n0 = -9223372036854775807L;
        this.f4323i0 = 0;
        this.f4324j0 = 0;
        this.f4322h0 = this.f4321g0 ? 1 : 0;
        return false;
    }

    /* renamed from: P */
    public final List<C2072e> m1669P(boolean z) {
        List<C2072e> mo1307S = mo1307S(this.f4330p, this.f4289A, z);
        if (mo1307S.isEmpty() && z) {
            mo1307S = mo1307S(this.f4330p, this.f4289A, false);
            if (!mo1307S.isEmpty()) {
                StringBuilder m586H = C1499a.m586H("Drm session requires secure decoder for ");
                m586H.append(this.f4289A.f9245l);
                m586H.append(", but no secure decoder available. Trying to proceed with ");
                m586H.append(mo1307S);
                m586H.append(".");
                m586H.toString();
            }
        }
        return mo1307S;
    }

    /* renamed from: Q */
    public boolean mo1670Q() {
        return false;
    }

    /* renamed from: R */
    public abstract float mo1306R(float f2, Format format, Format[] formatArr);

    /* renamed from: S */
    public abstract List<C2072e> mo1307S(InterfaceC2074g interfaceC2074g, Format format, boolean z);

    /* renamed from: T */
    public void mo1671T(C1945e c1945e) {
    }

    /* JADX WARN: Code restructure failed: missing block: B:108:0x017b, code lost:
    
        if ("stvm8".equals(r1) == false) goto L94;
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x018b, code lost:
    
        if ("OMX.amlogic.avc.decoder.awesome.secure".equals(r8) == false) goto L94;
     */
    /* JADX WARN: Removed duplicated region for block: B:105:0x016b  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x0249  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0103  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x012f A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0194  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01a5  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x01bc  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x01eb  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0207  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x020f  */
    /* renamed from: U */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m1672U(p005b.p199l.p200a.p201a.p219g1.C2072e r17, android.media.MediaCrypto r18) {
        /*
            Method dump skipped, instructions count: 597
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p219g1.AbstractC2073f.m1672U(b.l.a.a.g1.e, android.media.MediaCrypto):void");
    }

    /* renamed from: V */
    public final void m1673V() {
        if (this.f4297I != null || this.f4289A == null) {
            return;
        }
        m1681j0(this.f4292D);
        String str = this.f4289A.f9245l;
        InterfaceC1952c<C1957h> interfaceC1952c = this.f4291C;
        if (interfaceC1952c != null) {
            if (this.f4293E == null) {
                if (interfaceC1952c.mo1449b() != null) {
                    try {
                        MediaCrypto mediaCrypto = new MediaCrypto(null, null);
                        this.f4293E = mediaCrypto;
                        this.f4294F = mediaCrypto.requiresSecureDecoderComponent(str);
                    } catch (MediaCryptoException e2) {
                        throw m2666u(e2, this.f4289A);
                    }
                } else if (this.f4291C.mo1450c() == null) {
                    return;
                }
            }
            if (C1957h.f3385a) {
                int state = this.f4291C.getState();
                if (state == 1) {
                    throw m2666u(this.f4291C.mo1450c(), this.f4289A);
                }
                if (state != 4) {
                    return;
                }
            }
        }
        try {
            m1674W(this.f4293E, this.f4294F);
        } catch (a e3) {
            throw m2666u(e3, this.f4289A);
        }
    }

    /* renamed from: W */
    public final void m1674W(MediaCrypto mediaCrypto, boolean z) {
        if (this.f4300L == null) {
            try {
                List<C2072e> m1669P = m1669P(z);
                ArrayDeque<C2072e> arrayDeque = new ArrayDeque<>();
                this.f4300L = arrayDeque;
                if (this.f4336s) {
                    arrayDeque.addAll(m1669P);
                } else if (!m1669P.isEmpty()) {
                    this.f4300L.add(m1669P.get(0));
                }
                this.f4301M = null;
            } catch (C2075h.c e2) {
                throw new a(this.f4289A, e2, z, -49998);
            }
        }
        if (this.f4300L.isEmpty()) {
            throw new a(this.f4289A, null, z, -49999);
        }
        while (this.f4297I == null) {
            C2072e peekFirst = this.f4300L.peekFirst();
            if (!mo1683l0(peekFirst)) {
                return;
            }
            try {
                m1672U(peekFirst, mediaCrypto);
            } catch (Exception e3) {
                String str = "Failed to initialize decoder: " + peekFirst;
                this.f4300L.removeFirst();
                Format format = this.f4289A;
                StringBuilder m586H = C1499a.m586H("Decoder init failed: ");
                m586H.append(peekFirst.f4280a);
                m586H.append(", ");
                m586H.append(format);
                a aVar = new a(m586H.toString(), e3, format.f9245l, z, peekFirst, (C2344d0.f6035a < 21 || !(e3 instanceof MediaCodec.CodecException)) ? null : ((MediaCodec.CodecException) e3).getDiagnosticInfo(), null);
                a aVar2 = this.f4301M;
                if (aVar2 == null) {
                    this.f4301M = aVar;
                } else {
                    this.f4301M = new a(aVar2.getMessage(), aVar2.getCause(), aVar2.f4347c, aVar2.f4348e, aVar2.f4349f, aVar2.f4350g, aVar);
                }
                if (this.f4300L.isEmpty()) {
                    throw this.f4301M;
                }
            }
        }
        this.f4300L = null;
    }

    /* renamed from: X */
    public abstract void mo1308X(String str, long j2, long j3);

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0092, code lost:
    
        if (r2 != false) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x00eb, code lost:
    
        if (r1.f9251r == r2.f9251r) goto L78;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: Y */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1309Y(p005b.p199l.p200a.p201a.C1964f0 r7) {
        /*
            Method dump skipped, instructions count: 284
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p219g1.AbstractC2073f.mo1309Y(b.l.a.a.f0):void");
    }

    /* renamed from: Z */
    public abstract void mo1310Z(MediaCodec mediaCodec, MediaFormat mediaFormat);

    /* renamed from: a0 */
    public abstract void mo1311a0(long j2);

    /* renamed from: b0 */
    public abstract void mo1313b0(C1945e c1945e);

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: c */
    public boolean mo1314c() {
        return this.f4331p0;
    }

    /* renamed from: c0 */
    public final void m1675c0() {
        int i2 = this.f4324j0;
        if (i2 == 1) {
            m1667N();
            return;
        }
        if (i2 == 2) {
            m1686o0();
        } else if (i2 != 3) {
            this.f4331p0 = true;
            mo1316g0();
        } else {
            mo1677f0();
            m1673V();
        }
    }

    /* renamed from: d0 */
    public abstract boolean mo1315d0(long j2, long j3, MediaCodec mediaCodec, ByteBuffer byteBuffer, int i2, int i3, long j4, boolean z, boolean z2, Format format);

    /* renamed from: e0 */
    public final boolean m1676e0(boolean z) {
        C1964f0 m2667v = m2667v();
        this.f4342v.clear();
        int m2665D = m2665D(m2667v, this.f4342v, z);
        if (m2665D == -5) {
            mo1309Y(m2667v);
            return true;
        }
        if (m2665D != -4 || !this.f4342v.isEndOfStream()) {
            return false;
        }
        this.f4329o0 = true;
        m1675c0();
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: f0 */
    public void mo1677f0() {
        this.f4300L = null;
        this.f4302N = null;
        this.f4298J = null;
        m1678h0();
        m1679i0();
        if (C2344d0.f6035a < 21) {
            this.f4313Y = null;
            this.f4314Z = null;
        }
        this.f4333q0 = false;
        this.f4315a0 = -9223372036854775807L;
        this.f4344x.clear();
        this.f4327m0 = -9223372036854775807L;
        this.f4328n0 = -9223372036854775807L;
        try {
            MediaCodec mediaCodec = this.f4297I;
            if (mediaCodec != null) {
                this.f4341u0.f3297b++;
                try {
                    mediaCodec.stop();
                    this.f4297I.release();
                } catch (Throwable th) {
                    this.f4297I.release();
                    throw th;
                }
            }
            this.f4297I = null;
            try {
                MediaCrypto mediaCrypto = this.f4293E;
                if (mediaCrypto != null) {
                    mediaCrypto.release();
                }
            } finally {
            }
        } catch (Throwable th2) {
            this.f4297I = null;
            try {
                MediaCrypto mediaCrypto2 = this.f4293E;
                if (mediaCrypto2 != null) {
                    mediaCrypto2.release();
                }
                throw th2;
            } finally {
            }
        }
    }

    /* renamed from: g0 */
    public void mo1316g0() {
    }

    /* renamed from: h0 */
    public final void m1678h0() {
        this.f4316b0 = -1;
        this.f4340u.f3306e = null;
    }

    /* renamed from: i0 */
    public final void m1679i0() {
        this.f4317c0 = -1;
        this.f4318d0 = null;
    }

    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    public boolean isReady() {
        if (this.f4289A == null || this.f4333q0) {
            return false;
        }
        if (!(mo2654e() ? this.f6323m : this.f6319i.isReady())) {
            if (!(this.f4317c0 >= 0) && (this.f4315a0 == -9223372036854775807L || SystemClock.elapsedRealtime() >= this.f4315a0)) {
                return false;
            }
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x0057 A[LOOP:1: B:23:0x0035->B:32:0x0057, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0058 A[EDGE_INSN: B:33:0x0058->B:34:0x0058 BREAK  A[LOOP:1: B:23:0x0035->B:32:0x0057], SYNTHETIC] */
    @Override // p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: j */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1680j(long r6, long r8) {
        /*
            r5 = this;
            boolean r0 = r5.f4339t0
            r1 = 0
            if (r0 == 0) goto La
            r5.f4339t0 = r1
            r5.m1675c0()
        La:
            r0 = 1
            boolean r2 = r5.f4331p0     // Catch: java.lang.IllegalStateException -> L74
            if (r2 == 0) goto L13
            r5.mo1316g0()     // Catch: java.lang.IllegalStateException -> L74
            return
        L13:
            com.google.android.exoplayer2.Format r2 = r5.f4289A     // Catch: java.lang.IllegalStateException -> L74
            if (r2 != 0) goto L1e
            boolean r2 = r5.m1676e0(r0)     // Catch: java.lang.IllegalStateException -> L74
            if (r2 != 0) goto L1e
            return
        L1e:
            r5.m1673V()     // Catch: java.lang.IllegalStateException -> L74
            android.media.MediaCodec r2 = r5.f4297I     // Catch: java.lang.IllegalStateException -> L74
            if (r2 == 0) goto L5c
            long r2 = android.os.SystemClock.elapsedRealtime()     // Catch: java.lang.IllegalStateException -> L74
            java.lang.String r4 = "drainAndFeed"
            p005b.p199l.p200a.p201a.p250p1.C2354n.m2488k(r4)     // Catch: java.lang.IllegalStateException -> L74
        L2e:
            boolean r4 = r5.m1665L(r6, r8)     // Catch: java.lang.IllegalStateException -> L74
            if (r4 == 0) goto L35
            goto L2e
        L35:
            boolean r6 = r5.m1666M()     // Catch: java.lang.IllegalStateException -> L74
            if (r6 == 0) goto L58
            long r6 = r5.f4295G     // Catch: java.lang.IllegalStateException -> L74
            r8 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            int r4 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1))
            if (r4 == 0) goto L54
            long r6 = android.os.SystemClock.elapsedRealtime()     // Catch: java.lang.IllegalStateException -> L74
            long r6 = r6 - r2
            long r8 = r5.f4295G     // Catch: java.lang.IllegalStateException -> L74
            int r4 = (r6 > r8 ? 1 : (r6 == r8 ? 0 : -1))
            if (r4 >= 0) goto L52
            goto L54
        L52:
            r6 = 0
            goto L55
        L54:
            r6 = 1
        L55:
            if (r6 == 0) goto L58
            goto L35
        L58:
            p005b.p199l.p200a.p201a.p250p1.C2354n.m2443X()     // Catch: java.lang.IllegalStateException -> L74
            goto L6f
        L5c:
            b.l.a.a.c1.d r8 = r5.f4341u0     // Catch: java.lang.IllegalStateException -> L74
            int r9 = r8.f3299d     // Catch: java.lang.IllegalStateException -> L74
            b.l.a.a.k1.e0 r2 = r5.f6319i     // Catch: java.lang.IllegalStateException -> L74
            long r3 = r5.f6321k     // Catch: java.lang.IllegalStateException -> L74
            long r6 = r6 - r3
            int r6 = r2.mo1788o(r6)     // Catch: java.lang.IllegalStateException -> L74
            int r9 = r9 + r6
            r8.f3299d = r9     // Catch: java.lang.IllegalStateException -> L74
            r5.m1676e0(r1)     // Catch: java.lang.IllegalStateException -> L74
        L6f:
            b.l.a.a.c1.d r6 = r5.f4341u0     // Catch: java.lang.IllegalStateException -> L74
            monitor-enter(r6)     // Catch: java.lang.IllegalStateException -> L74
            monitor-exit(r6)     // Catch: java.lang.IllegalStateException -> L74
            return
        L74:
            r6 = move-exception
            int r7 = p005b.p199l.p200a.p201a.p250p1.C2344d0.f6035a
            r8 = 21
            if (r7 < r8) goto L80
            boolean r7 = r6 instanceof android.media.MediaCodec.CodecException
            if (r7 == 0) goto L80
            goto L97
        L80:
            java.lang.StackTraceElement[] r7 = r6.getStackTrace()
            int r8 = r7.length
            if (r8 <= 0) goto L96
            r7 = r7[r1]
            java.lang.String r7 = r7.getClassName()
            java.lang.String r8 = "android.media.MediaCodec"
            boolean r7 = r7.equals(r8)
            if (r7 == 0) goto L96
            r1 = 1
        L96:
            r0 = r1
        L97:
            if (r0 == 0) goto La0
            com.google.android.exoplayer2.Format r7 = r5.f4289A
            b.l.a.a.b0 r6 = r5.m2666u(r6, r7)
            throw r6
        La0:
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p219g1.AbstractC2073f.mo1680j(long, long):void");
    }

    /* renamed from: j0 */
    public final void m1681j0(@Nullable InterfaceC1952c<C1957h> interfaceC1952c) {
        InterfaceC1952c<C1957h> interfaceC1952c2 = this.f4291C;
        if (interfaceC1952c2 != interfaceC1952c) {
            if (interfaceC1952c != null) {
                interfaceC1952c.acquire();
            }
            if (interfaceC1952c2 != null) {
                interfaceC1952c2.release();
            }
        }
        this.f4291C = interfaceC1952c;
    }

    /* renamed from: k0 */
    public final void m1682k0(@Nullable InterfaceC1952c<C1957h> interfaceC1952c) {
        InterfaceC1952c<C1957h> interfaceC1952c2 = this.f4292D;
        if (interfaceC1952c2 != interfaceC1952c) {
            if (interfaceC1952c != null) {
                interfaceC1952c.acquire();
            }
            if (interfaceC1952c2 != null) {
                interfaceC1952c2.release();
            }
        }
        this.f4292D = interfaceC1952c;
    }

    /* renamed from: l0 */
    public boolean mo1683l0(C2072e c2072e) {
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u, p005b.p199l.p200a.p201a.InterfaceC2396t0
    /* renamed from: m */
    public final void mo1684m(float f2) {
        this.f4296H = f2;
        if (this.f4297I == null || this.f4324j0 == 3 || this.f6318h == 0) {
            return;
        }
        m1685n0();
    }

    /* renamed from: m0 */
    public abstract int mo1319m0(InterfaceC2074g interfaceC2074g, @Nullable InterfaceC1954e<C1957h> interfaceC1954e, Format format);

    /* renamed from: n0 */
    public final void m1685n0() {
        if (C2344d0.f6035a < 23) {
            return;
        }
        float mo1306R = mo1306R(this.f4296H, this.f4298J, this.f6320j);
        float f2 = this.f4299K;
        if (f2 == mo1306R) {
            return;
        }
        if (mo1306R == -1.0f) {
            m1663J();
            return;
        }
        if (f2 != -1.0f || mo1306R > this.f4338t) {
            Bundle bundle = new Bundle();
            bundle.putFloat("operating-rate", mo1306R);
            this.f4297I.setParameters(bundle);
            this.f4299K = mo1306R;
        }
    }

    @TargetApi(23)
    /* renamed from: o0 */
    public final void m1686o0() {
        if (this.f4292D.mo1449b() == null) {
            mo1677f0();
            m1673V();
            return;
        }
        if (C2399v.f6331e.equals(null)) {
            mo1677f0();
            m1673V();
        } else {
            if (m1667N()) {
                return;
            }
            try {
                this.f4293E.setMediaDrmSession(null);
                m1681j0(this.f4292D);
                this.f4323i0 = 0;
                this.f4324j0 = 0;
            } catch (MediaCryptoException e2) {
                throw m2666u(e2, this.f4289A);
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: w */
    public void mo1325w() {
        this.f4289A = null;
        if (this.f4292D == null && this.f4291C == null) {
            mo1668O();
        } else {
            mo1328z();
        }
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: x */
    public void mo1326x(boolean z) {
        InterfaceC1954e<C1957h> interfaceC1954e = this.f4332q;
        if (interfaceC1954e != null && !this.f4346z) {
            this.f4346z = true;
            interfaceC1954e.mo1443b();
        }
        this.f4341u0 = new C1944d();
    }

    @Override // p005b.p199l.p200a.p201a.AbstractC2397u
    /* renamed from: z */
    public void mo1328z() {
        try {
            mo1677f0();
            m1682k0(null);
            InterfaceC1954e<C1957h> interfaceC1954e = this.f4332q;
            if (interfaceC1954e == null || !this.f4346z) {
                return;
            }
            this.f4346z = false;
            interfaceC1954e.release();
        } catch (Throwable th) {
            m1682k0(null);
            throw th;
        }
    }

    /* renamed from: b.l.a.a.g1.f$a */
    public static class a extends Exception {

        /* renamed from: c */
        public final String f4347c;

        /* renamed from: e */
        public final boolean f4348e;

        /* renamed from: f */
        @Nullable
        public final C2072e f4349f;

        /* renamed from: g */
        @Nullable
        public final String f4350g;

        /* JADX WARN: Illegal instructions before constructor call */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public a(com.google.android.exoplayer2.Format r11, java.lang.Throwable r12, boolean r13, int r14) {
            /*
                r10 = this;
                java.lang.StringBuilder r0 = new java.lang.StringBuilder
                r0.<init>()
                java.lang.String r1 = "Decoder init failed: ["
                r0.append(r1)
                r0.append(r14)
                java.lang.String r1 = "], "
                r0.append(r1)
                r0.append(r11)
                java.lang.String r3 = r0.toString()
                java.lang.String r5 = r11.f9245l
                if (r14 >= 0) goto L20
                java.lang.String r11 = "neg_"
                goto L22
            L20:
                java.lang.String r11 = ""
            L22:
                java.lang.String r0 = "com.google.android.exoplayer2.mediacodec.MediaCodecRenderer_"
                java.lang.StringBuilder r11 = p005b.p131d.p132a.p133a.C1499a.m590L(r0, r11)
                int r14 = java.lang.Math.abs(r14)
                r11.append(r14)
                java.lang.String r8 = r11.toString()
                r9 = 0
                r7 = 0
                r2 = r10
                r4 = r12
                r6 = r13
                r2.<init>(r3, r4, r5, r6, r7, r8, r9)
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p219g1.AbstractC2073f.a.<init>(com.google.android.exoplayer2.Format, java.lang.Throwable, boolean, int):void");
        }

        public a(String str, Throwable th, String str2, boolean z, @Nullable C2072e c2072e, @Nullable String str3, @Nullable a aVar) {
            super(str, th);
            this.f4347c = str2;
            this.f4348e = z;
            this.f4349f = c2072e;
            this.f4350g = str3;
        }
    }
}
