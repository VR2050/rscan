package p005b.p199l.p200a.p201a.p236l1.p244t;

import androidx.annotation.Nullable;
import java.util.Collections;
import java.util.List;

/* renamed from: b.l.a.a.l1.t.d */
/* loaded from: classes.dex */
public final class C2244d {

    /* renamed from: f */
    public int f5566f;

    /* renamed from: h */
    public int f5568h;

    /* renamed from: a */
    public String f5561a = "";

    /* renamed from: b */
    public String f5562b = "";

    /* renamed from: c */
    public List<String> f5563c = Collections.emptyList();

    /* renamed from: d */
    public String f5564d = "";

    /* renamed from: e */
    @Nullable
    public String f5565e = null;

    /* renamed from: g */
    public boolean f5567g = false;

    /* renamed from: i */
    public boolean f5569i = false;

    /* renamed from: j */
    public int f5570j = -1;

    /* renamed from: k */
    public int f5571k = -1;

    /* renamed from: l */
    public int f5572l = -1;

    /* renamed from: m */
    public int f5573m = -1;

    /* renamed from: n */
    public int f5574n = -1;

    /* renamed from: b */
    public static int m2126b(int i2, String str, @Nullable String str2, int i3) {
        if (str.isEmpty() || i2 == -1) {
            return i2;
        }
        if (str.equals(str2)) {
            return i2 + i3;
        }
        return -1;
    }

    /* renamed from: a */
    public int m2127a() {
        int i2 = this.f5572l;
        if (i2 == -1 && this.f5573m == -1) {
            return -1;
        }
        return (i2 == 1 ? 1 : 0) | (this.f5573m == 1 ? 2 : 0);
    }
}
