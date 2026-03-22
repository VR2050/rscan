package p379c.p380a.p381a;

import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: c.a.a.l */
/* loaded from: classes2.dex */
public final class C2963l<E> {
    public volatile Object _next = null;
    public volatile long _state = 0;

    /* renamed from: e */
    public final int f8121e;

    /* renamed from: f */
    public AtomicReferenceArray f8122f;

    /* renamed from: g */
    public final int f8123g;

    /* renamed from: h */
    public final boolean f8124h;

    /* renamed from: d */
    public static final a f8120d = new a(null);

    /* renamed from: c */
    @JvmField
    @NotNull
    public static final C2970s f8119c = new C2970s("REMOVE_FROZEN");

    /* renamed from: a */
    public static final AtomicReferenceFieldUpdater f8117a = AtomicReferenceFieldUpdater.newUpdater(C2963l.class, Object.class, "_next");

    /* renamed from: b */
    public static final AtomicLongFieldUpdater f8118b = AtomicLongFieldUpdater.newUpdater(C2963l.class, "_state");

    /* renamed from: c.a.a.l$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    /* renamed from: c.a.a.l$b */
    public static final class b {

        /* renamed from: a */
        @JvmField
        public final int f8125a;

        public b(int i2) {
            this.f8125a = i2;
        }
    }

    public C2963l(int i2, boolean z) {
        this.f8123g = i2;
        this.f8124h = z;
        int i3 = i2 - 1;
        this.f8121e = i3;
        this.f8122f = new AtomicReferenceArray(i2);
        if (!(i3 <= 1073741823)) {
            throw new IllegalStateException("Check failed.".toString());
        }
        if (!((i2 & i3) == 0)) {
            throw new IllegalStateException("Check failed.".toString());
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:39:0x0051, code lost:
    
        return 1;
     */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int m3438a(@org.jetbrains.annotations.NotNull E r16) {
        /*
            r15 = this;
            r6 = r15
            r7 = r16
        L3:
            long r2 = r6._state
            r0 = 3458764513820540928(0x3000000000000000, double:1.727233711018889E-77)
            long r0 = r0 & r2
            r8 = 0
            r4 = 1
            int r5 = (r0 > r8 ? 1 : (r0 == r8 ? 0 : -1))
            if (r5 == 0) goto L18
            r0 = 2305843009213693952(0x2000000000000000, double:1.4916681462400413E-154)
            long r0 = r0 & r2
            int r2 = (r0 > r8 ? 1 : (r0 == r8 ? 0 : -1))
            if (r2 == 0) goto L17
            r4 = 2
        L17:
            return r4
        L18:
            r0 = 1073741823(0x3fffffff, double:5.304989472E-315)
            long r0 = r0 & r2
            r10 = 0
            long r0 = r0 >> r10
            int r1 = (int) r0
            r11 = 1152921503533105152(0xfffffffc0000000, double:1.2882296003504729E-231)
            long r11 = r11 & r2
            r0 = 30
            long r11 = r11 >> r0
            int r12 = (int) r11
            int r11 = r6.f8121e
            int r5 = r12 + 2
            r5 = r5 & r11
            r13 = r1 & r11
            if (r5 != r13) goto L33
            return r4
        L33:
            boolean r5 = r6.f8124h
            r13 = 1073741823(0x3fffffff, float:1.9999999)
            if (r5 != 0) goto L52
            java.util.concurrent.atomic.AtomicReferenceArray r5 = r6.f8122f
            r14 = r12 & r11
            java.lang.Object r5 = r5.get(r14)
            if (r5 == 0) goto L52
            int r0 = r6.f8123g
            r2 = 1024(0x400, float:1.435E-42)
            if (r0 < r2) goto L51
            int r12 = r12 - r1
            r1 = r12 & r13
            int r0 = r0 >> 1
            if (r1 <= r0) goto L3
        L51:
            return r4
        L52:
            int r1 = r12 + 1
            r1 = r1 & r13
            java.util.concurrent.atomic.AtomicLongFieldUpdater r4 = p379c.p380a.p381a.C2963l.f8118b
            r13 = -1152921503533105153(0xf00000003fffffff, double:-3.1050369248997324E231)
            long r13 = r13 & r2
            long r8 = (long) r1
            long r0 = r8 << r0
            long r8 = r13 | r0
            r0 = r4
            r1 = r15
            r4 = r8
            boolean r0 = r0.compareAndSet(r1, r2, r4)
            if (r0 == 0) goto L3
            java.util.concurrent.atomic.AtomicReferenceArray r0 = r6.f8122f
            r1 = r12 & r11
            r0.set(r1, r7)
            r0 = r6
        L73:
            long r1 = r0._state
            r3 = 1152921504606846976(0x1000000000000000, double:1.2882297539194267E-231)
            long r1 = r1 & r3
            r3 = 0
            int r5 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r5 != 0) goto L7f
            goto La3
        L7f:
            c.a.a.l r0 = r0.m3441d()
            java.util.concurrent.atomic.AtomicReferenceArray r1 = r0.f8122f
            int r2 = r0.f8121e
            r2 = r2 & r12
            java.lang.Object r1 = r1.get(r2)
            boolean r2 = r1 instanceof p379c.p380a.p381a.C2963l.b
            if (r2 == 0) goto L9f
            c.a.a.l$b r1 = (p379c.p380a.p381a.C2963l.b) r1
            int r1 = r1.f8125a
            if (r1 != r12) goto L9f
            java.util.concurrent.atomic.AtomicReferenceArray r1 = r0.f8122f
            int r2 = r0.f8121e
            r2 = r2 & r12
            r1.set(r2, r7)
            goto La0
        L9f:
            r0 = 0
        La0:
            if (r0 == 0) goto La3
            goto L73
        La3:
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p381a.C2963l.m3438a(java.lang.Object):int");
    }

    /* renamed from: b */
    public final boolean m3439b() {
        long j2;
        do {
            j2 = this._state;
            if ((j2 & 2305843009213693952L) != 0) {
                return true;
            }
            if ((1152921504606846976L & j2) != 0) {
                return false;
            }
        } while (!f8118b.compareAndSet(this, j2, j2 | 2305843009213693952L));
        return true;
    }

    /* renamed from: c */
    public final boolean m3440c() {
        long j2 = this._state;
        return ((int) ((1073741823 & j2) >> 0)) == ((int) ((j2 & 1152921503533105152L) >> 30));
    }

    /* JADX WARN: Multi-variable type inference failed */
    @NotNull
    /* renamed from: d */
    public final C2963l<E> m3441d() {
        long j2;
        while (true) {
            j2 = this._state;
            if ((j2 & 1152921504606846976L) != 0) {
                break;
            }
            long j3 = j2 | 1152921504606846976L;
            if (f8118b.compareAndSet(this, j2, j3)) {
                j2 = j3;
                break;
            }
        }
        while (true) {
            C2963l<E> c2963l = (C2963l) this._next;
            if (c2963l != null) {
                return c2963l;
            }
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f8117a;
            C2963l c2963l2 = new C2963l(this.f8123g * 2, this.f8124h);
            int i2 = (int) ((1073741823 & j2) >> 0);
            int i3 = (int) ((1152921503533105152L & j2) >> 30);
            while (true) {
                int i4 = this.f8121e;
                int i5 = i2 & i4;
                if (i5 != (i4 & i3)) {
                    Object obj = this.f8122f.get(i5);
                    if (obj == null) {
                        obj = new b(i2);
                    }
                    c2963l2.f8122f.set(c2963l2.f8121e & i2, obj);
                    i2++;
                }
            }
            c2963l2._state = (-1152921504606846977L) & j2;
            atomicReferenceFieldUpdater.compareAndSet(this, null, c2963l2);
        }
    }

    @Nullable
    /* renamed from: e */
    public final Object m3442e() {
        while (true) {
            long j2 = this._state;
            if ((j2 & 1152921504606846976L) != 0) {
                return f8119c;
            }
            int i2 = (int) ((j2 & 1073741823) >> 0);
            int i3 = this.f8121e;
            int i4 = ((int) ((1152921503533105152L & j2) >> 30)) & i3;
            int i5 = i3 & i2;
            if (i4 == i5) {
                return null;
            }
            Object obj = this.f8122f.get(i5);
            if (obj == null) {
                if (this.f8124h) {
                    return null;
                }
            } else {
                if (obj instanceof b) {
                    return null;
                }
                long j3 = ((i2 + 1) & 1073741823) << 0;
                if (f8118b.compareAndSet(this, j2, (j2 & (-1073741824)) | j3)) {
                    this.f8122f.set(this.f8121e & i2, null);
                    return obj;
                }
                if (this.f8124h) {
                    C2963l<E> c2963l = this;
                    while (true) {
                        long j4 = c2963l._state;
                        int i6 = (int) ((j4 & 1073741823) >> 0);
                        if ((j4 & 1152921504606846976L) != 0) {
                            c2963l = c2963l.m3441d();
                        } else {
                            if (f8118b.compareAndSet(c2963l, j4, (j4 & (-1073741824)) | j3)) {
                                c2963l.f8122f.set(c2963l.f8121e & i6, null);
                                c2963l = null;
                            } else {
                                continue;
                            }
                        }
                        if (c2963l == null) {
                            return obj;
                        }
                    }
                }
            }
        }
    }
}
