package p005b.p199l.p200a.p201a.p236l1.p237m;

import android.text.Layout;
import androidx.annotation.NonNull;
import p005b.p199l.p200a.p201a.p236l1.C2207b;

/* renamed from: b.l.a.a.l1.m.b */
/* loaded from: classes.dex */
public final class C2219b extends C2207b implements Comparable<C2219b> {

    /* renamed from: s */
    public final int f5342s;

    public C2219b(CharSequence charSequence, Layout.Alignment alignment, float f2, int i2, int i3, float f3, int i4, float f4, boolean z, int i5, int i6) {
        super(charSequence, alignment, f2, i2, i3, f3, i4, f4, z, i5);
        this.f5342s = i6;
    }

    @Override // java.lang.Comparable
    public int compareTo(@NonNull C2219b c2219b) {
        int i2 = c2219b.f5342s;
        int i3 = this.f5342s;
        if (i2 < i3) {
            return -1;
        }
        return i2 > i3 ? 1 : 0;
    }
}
