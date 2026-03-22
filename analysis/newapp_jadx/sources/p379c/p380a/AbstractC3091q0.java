package p379c.p380a;

import java.util.Objects;
import kotlin.collections.ArraysKt___ArraysJvmKt;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.p381a.C2953b;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: c.a.q0 */
/* loaded from: classes2.dex */
public abstract class AbstractC3091q0 extends AbstractC3036c0 {

    /* renamed from: c */
    public static final /* synthetic */ int f8440c = 0;

    /* renamed from: e */
    public long f8441e;

    /* renamed from: f */
    public boolean f8442f;

    /* renamed from: g */
    public C2953b<AbstractC3076l0<?>> f8443g;

    /* renamed from: U */
    public final void m3626U(boolean z) {
        long m3627V = this.f8441e - m3627V(z);
        this.f8441e = m3627V;
        if (m3627V <= 0 && this.f8442f) {
            shutdown();
        }
    }

    /* renamed from: V */
    public final long m3627V(boolean z) {
        if (z) {
            return IjkMediaMeta.AV_CH_WIDE_RIGHT;
        }
        return 1L;
    }

    /* renamed from: W */
    public final void m3628W(@NotNull AbstractC3076l0<?> abstractC3076l0) {
        C2953b<AbstractC3076l0<?>> c2953b = this.f8443g;
        if (c2953b == null) {
            c2953b = new C2953b<>();
            this.f8443g = c2953b;
        }
        Object[] objArr = c2953b.f8096a;
        int i2 = c2953b.f8098c;
        objArr[i2] = abstractC3076l0;
        int length = (objArr.length - 1) & (i2 + 1);
        c2953b.f8098c = length;
        int i3 = c2953b.f8097b;
        if (length == i3) {
            int length2 = objArr.length;
            Object[] objArr2 = new Object[length2 << 1];
            ArraysKt___ArraysJvmKt.copyInto$default(objArr, objArr2, 0, i3, 0, 10, (Object) null);
            Object[] objArr3 = c2953b.f8096a;
            int length3 = objArr3.length;
            int i4 = c2953b.f8097b;
            ArraysKt___ArraysJvmKt.copyInto$default(objArr3, objArr2, length3 - i4, 0, i4, 4, (Object) null);
            c2953b.f8096a = objArr2;
            c2953b.f8097b = 0;
            c2953b.f8098c = length2;
        }
    }

    /* renamed from: X */
    public final void m3629X(boolean z) {
        this.f8441e = m3627V(z) + this.f8441e;
        if (z) {
            return;
        }
        this.f8442f = true;
    }

    /* renamed from: Y */
    public final boolean m3630Y() {
        return this.f8441e >= m3627V(true);
    }

    /* renamed from: Z */
    public long mo3631Z() {
        return !m3632a0() ? Long.MAX_VALUE : 0L;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v1, types: [java.lang.Object[]] */
    /* JADX WARN: Type inference failed for: r6v0, types: [java.lang.Object] */
    /* renamed from: a0 */
    public final boolean m3632a0() {
        C2953b<AbstractC3076l0<?>> c2953b = this.f8443g;
        if (c2953b != null) {
            int i2 = c2953b.f8097b;
            AbstractC3076l0 abstractC3076l0 = null;
            if (i2 != c2953b.f8098c) {
                ?? r3 = c2953b.f8096a;
                ?? r6 = r3[i2];
                r3[i2] = 0;
                c2953b.f8097b = (i2 + 1) & (r3.length - 1);
                Objects.requireNonNull(r6, "null cannot be cast to non-null type T");
                abstractC3076l0 = r6;
            }
            AbstractC3076l0 abstractC3076l02 = abstractC3076l0;
            if (abstractC3076l02 != null) {
                abstractC3076l02.run();
                return true;
            }
        }
        return false;
    }

    public void shutdown() {
    }
}
