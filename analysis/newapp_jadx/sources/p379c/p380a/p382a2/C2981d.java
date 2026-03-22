package p379c.p380a.p382a2;

import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.collections.ArraysKt___ArraysJvmKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p381a.C2970s;
import p379c.p380a.p381a.C2975x;

/* renamed from: c.a.a2.d */
/* loaded from: classes2.dex */
public class C2981d<E> extends AbstractC2978a<E> {

    /* renamed from: g */
    public final ReentrantLock f8169g;

    /* renamed from: h */
    public Object[] f8170h;

    /* renamed from: i */
    public int f8171i;

    /* renamed from: j */
    public final int f8172j;

    /* renamed from: k */
    public final EnumC2982e f8173k;
    public volatile int size;

    public C2981d(int i2, @NotNull EnumC2982e enumC2982e, @Nullable Function1<? super E, Unit> function1) {
        super(function1);
        this.f8172j = i2;
        this.f8173k = enumC2982e;
        if (!(i2 >= 1)) {
            throw new IllegalArgumentException(C1499a.m628n("ArrayChannel capacity must be at least 1, but ", i2, " was specified").toString());
        }
        this.f8169g = new ReentrantLock();
        Object[] objArr = new Object[Math.min(i2, 8)];
        ArraysKt___ArraysJvmKt.fill$default(objArr, C2979b.f8158a, 0, 0, 6, (Object) null);
        Unit unit = Unit.INSTANCE;
        this.f8170h = objArr;
        this.size = 0;
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    @Nullable
    /* renamed from: b */
    public Object mo3475b(@NotNull AbstractC2997t abstractC2997t) {
        ReentrantLock reentrantLock = this.f8169g;
        reentrantLock.lock();
        try {
            return super.mo3475b(abstractC2997t);
        } finally {
            reentrantLock.unlock();
        }
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a, p379c.p380a.p382a2.InterfaceC2994q
    /* renamed from: c */
    public boolean mo3457c() {
        ReentrantLock reentrantLock = this.f8169g;
        reentrantLock.lock();
        try {
            return super.mo3457c();
        } finally {
            reentrantLock.unlock();
        }
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    @NotNull
    /* renamed from: f */
    public String mo3476f() {
        StringBuilder m586H = C1499a.m586H("(buffer:capacity=");
        m586H.append(this.f8172j);
        m586H.append(",size=");
        return C1499a.m579A(m586H, this.size, ')');
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    /* renamed from: l */
    public final boolean mo3481l() {
        return false;
    }

    @Override // p379c.p380a.p382a2.AbstractC2980c
    /* renamed from: o */
    public final boolean mo3483o() {
        return this.size == this.f8172j && this.f8173k == EnumC2982e.SUSPEND;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0038 A[DONT_GENERATE] */
    /* JADX WARN: Removed duplicated region for block: B:15:0x003c  */
    @Override // p379c.p380a.p382a2.AbstractC2980c
    @org.jetbrains.annotations.NotNull
    /* renamed from: q */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object mo3485q(E r6) {
        /*
            r5 = this;
            java.util.concurrent.locks.ReentrantLock r0 = r5.f8169g
            r0.lock()
            int r1 = r5.size     // Catch: java.lang.Throwable -> L78
            c.a.a2.h r2 = r5.m3477g()     // Catch: java.lang.Throwable -> L78
            if (r2 == 0) goto L11
            r0.unlock()
            return r2
        L11:
            int r2 = r5.f8172j     // Catch: java.lang.Throwable -> L78
            r3 = 1
            r4 = 0
            if (r1 >= r2) goto L1c
            int r2 = r1 + 1
            r5.size = r2     // Catch: java.lang.Throwable -> L78
            goto L32
        L1c:
            c.a.a2.e r2 = r5.f8173k     // Catch: java.lang.Throwable -> L78
            int r2 = r2.ordinal()     // Catch: java.lang.Throwable -> L78
            if (r2 == 0) goto L34
            if (r2 == r3) goto L32
            r3 = 2
            if (r2 != r3) goto L2c
            c.a.a.s r2 = p379c.p380a.p382a2.C2979b.f8159b     // Catch: java.lang.Throwable -> L78
            goto L36
        L2c:
            kotlin.NoWhenBranchMatchedException r6 = new kotlin.NoWhenBranchMatchedException     // Catch: java.lang.Throwable -> L78
            r6.<init>()     // Catch: java.lang.Throwable -> L78
            throw r6     // Catch: java.lang.Throwable -> L78
        L32:
            r2 = r4
            goto L36
        L34:
            c.a.a.s r2 = p379c.p380a.p382a2.C2979b.f8160c     // Catch: java.lang.Throwable -> L78
        L36:
            if (r2 == 0) goto L3c
            r0.unlock()
            return r2
        L3c:
            if (r1 != 0) goto L6f
        L3e:
            c.a.a2.r r2 = r5.mo3461r()     // Catch: java.lang.Throwable -> L78
            if (r2 == 0) goto L6f
            boolean r3 = r2 instanceof p379c.p380a.p382a2.C2985h     // Catch: java.lang.Throwable -> L78
            if (r3 == 0) goto L51
            r5.size = r1     // Catch: java.lang.Throwable -> L78
            kotlin.jvm.internal.Intrinsics.checkNotNull(r2)     // Catch: java.lang.Throwable -> L78
            r0.unlock()
            return r2
        L51:
            kotlin.jvm.internal.Intrinsics.checkNotNull(r2)     // Catch: java.lang.Throwable -> L78
            c.a.a.s r3 = r2.mo3471f(r6, r4)     // Catch: java.lang.Throwable -> L78
            if (r3 == 0) goto L3e
            r5.size = r1     // Catch: java.lang.Throwable -> L78
            kotlin.Unit r1 = kotlin.Unit.INSTANCE     // Catch: java.lang.Throwable -> L78
            r0.unlock()
            kotlin.jvm.internal.Intrinsics.checkNotNull(r2)
            r2.mo3470e(r6)
            kotlin.jvm.internal.Intrinsics.checkNotNull(r2)
            java.lang.Object r6 = r2.mo3492a()
            return r6
        L6f:
            r5.m3491z(r1, r6)     // Catch: java.lang.Throwable -> L78
            c.a.a.s r6 = p379c.p380a.p382a2.C2979b.f8159b     // Catch: java.lang.Throwable -> L78
            r0.unlock()
            return r6
        L78:
            r6 = move-exception
            r0.unlock()
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: p379c.p380a.p382a2.C2981d.mo3485q(java.lang.Object):java.lang.Object");
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    /* renamed from: t */
    public boolean mo3462t(@NotNull AbstractC2993p<? super E> abstractC2993p) {
        ReentrantLock reentrantLock = this.f8169g;
        reentrantLock.lock();
        try {
            return super.mo3462t(abstractC2993p);
        } finally {
            reentrantLock.unlock();
        }
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    /* renamed from: u */
    public final boolean mo3463u() {
        return false;
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    /* renamed from: v */
    public final boolean mo3464v() {
        return this.size == 0;
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    /* renamed from: w */
    public void mo3465w(boolean z) {
        Function1<E, Unit> function1 = this.f8166f;
        ReentrantLock reentrantLock = this.f8169g;
        reentrantLock.lock();
        try {
            int i2 = this.size;
            C2975x c2975x = null;
            for (int i3 = 0; i3 < i2; i3++) {
                Object obj = this.f8170h[this.f8171i];
                if (function1 != null && obj != C2979b.f8158a) {
                    c2975x = C2354n.m2503p(function1, obj, c2975x);
                }
                Object[] objArr = this.f8170h;
                int i4 = this.f8171i;
                objArr[i4] = C2979b.f8158a;
                this.f8171i = (i4 + 1) % objArr.length;
            }
            this.size = 0;
            Unit unit = Unit.INSTANCE;
            reentrantLock.unlock();
            super.mo3465w(z);
            if (c2975x != null) {
                throw c2975x;
            }
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    @Override // p379c.p380a.p382a2.AbstractC2978a
    @Nullable
    /* renamed from: x */
    public Object mo3466x() {
        ReentrantLock reentrantLock = this.f8169g;
        reentrantLock.lock();
        try {
            int i2 = this.size;
            if (i2 == 0) {
                Object m3477g = m3477g();
                if (m3477g == null) {
                    m3477g = C2979b.f8161d;
                }
                return m3477g;
            }
            Object[] objArr = this.f8170h;
            int i3 = this.f8171i;
            Object obj = objArr[i3];
            AbstractC2997t abstractC2997t = null;
            objArr[i3] = null;
            this.size = i2 - 1;
            Object obj2 = C2979b.f8161d;
            boolean z = false;
            if (i2 == this.f8172j) {
                AbstractC2997t abstractC2997t2 = null;
                while (true) {
                    AbstractC2997t m3486s = m3486s();
                    if (m3486s == null) {
                        abstractC2997t = abstractC2997t2;
                        break;
                    }
                    Intrinsics.checkNotNull(m3486s);
                    if (m3486s.mo3490u(null) != null) {
                        Intrinsics.checkNotNull(m3486s);
                        obj2 = m3486s.mo3488s();
                        abstractC2997t = m3486s;
                        z = true;
                        break;
                    }
                    Intrinsics.checkNotNull(m3486s);
                    m3486s.mo3502v();
                    abstractC2997t2 = m3486s;
                }
            }
            if (obj2 != C2979b.f8161d && !(obj2 instanceof C2985h)) {
                this.size = i2;
                Object[] objArr2 = this.f8170h;
                objArr2[(this.f8171i + i2) % objArr2.length] = obj2;
            }
            this.f8171i = (this.f8171i + 1) % this.f8170h.length;
            Unit unit = Unit.INSTANCE;
            if (z) {
                Intrinsics.checkNotNull(abstractC2997t);
                abstractC2997t.mo3487r();
            }
            return obj;
        } finally {
            reentrantLock.unlock();
        }
    }

    /* renamed from: z */
    public final void m3491z(int i2, E e2) {
        int i3 = this.f8172j;
        if (i2 >= i3) {
            Object[] objArr = this.f8170h;
            int i4 = this.f8171i;
            objArr[i4 % objArr.length] = null;
            objArr[(i2 + i4) % objArr.length] = e2;
            this.f8171i = (i4 + 1) % objArr.length;
            return;
        }
        Object[] objArr2 = this.f8170h;
        if (i2 >= objArr2.length) {
            int min = Math.min(objArr2.length * 2, i3);
            Object[] objArr3 = new Object[min];
            for (int i5 = 0; i5 < i2; i5++) {
                Object[] objArr4 = this.f8170h;
                objArr3[i5] = objArr4[(this.f8171i + i5) % objArr4.length];
            }
            ArraysKt___ArraysJvmKt.fill((C2970s[]) objArr3, C2979b.f8158a, i2, min);
            this.f8170h = objArr3;
            this.f8171i = 0;
        }
        Object[] objArr5 = this.f8170h;
        objArr5[(this.f8171i + i2) % objArr5.length] = e2;
    }
}
