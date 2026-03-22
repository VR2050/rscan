package p005b.p325v.p326a;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.v.a.f */
/* loaded from: classes2.dex */
public class C2819f {

    /* renamed from: a */
    public final ThreadLocal<String> f7656a = new ThreadLocal<>();

    /* renamed from: b */
    public final List<InterfaceC2816c> f7657b = new ArrayList();

    /* renamed from: a */
    public void m3275a(@Nullable Object obj) {
        m3277c(3, null, obj == null ? "null" : !obj.getClass().isArray() ? obj.toString() : obj instanceof boolean[] ? Arrays.toString((boolean[]) obj) : obj instanceof byte[] ? Arrays.toString((byte[]) obj) : obj instanceof char[] ? Arrays.toString((char[]) obj) : obj instanceof short[] ? Arrays.toString((short[]) obj) : obj instanceof int[] ? Arrays.toString((int[]) obj) : obj instanceof long[] ? Arrays.toString((long[]) obj) : obj instanceof float[] ? Arrays.toString((float[]) obj) : obj instanceof double[] ? Arrays.toString((double[]) obj) : obj instanceof Object[] ? Arrays.deepToString((Object[]) obj) : "Couldn't find a correct type for the object", new Object[0]);
    }

    /* renamed from: b */
    public synchronized void m3276b(int i2, @Nullable String str, @Nullable String str2, @Nullable Throwable th) {
        if (th != null && str2 != null) {
            str2 = str2 + " : " + C2354n.m2504p0(th);
        }
        if (th != null && str2 == null) {
            str2 = C2354n.m2504p0(th);
        }
        if (C2354n.m2405K0(str2)) {
            str2 = "Empty/NULL log message";
        }
        for (InterfaceC2816c interfaceC2816c : this.f7657b) {
            if (interfaceC2816c.mo212b(i2, str)) {
                interfaceC2816c.mo3270a(i2, str, str2);
            }
        }
    }

    /* renamed from: c */
    public final synchronized void m3277c(int i2, @Nullable Throwable th, @NonNull String str, @Nullable Object... objArr) {
        Objects.requireNonNull(str);
        String str2 = this.f7656a.get();
        if (str2 != null) {
            this.f7656a.remove();
        } else {
            str2 = null;
        }
        if (objArr != null && objArr.length != 0) {
            str = String.format(str, objArr);
        }
        m3276b(i2, str2, str, th);
    }
}
