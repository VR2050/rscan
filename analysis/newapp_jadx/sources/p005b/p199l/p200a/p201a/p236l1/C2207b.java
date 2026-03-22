package p005b.p199l.p200a.p201a.p236l1;

import android.graphics.Bitmap;
import android.text.Layout;
import androidx.annotation.Nullable;
import androidx.core.view.ViewCompat;

/* renamed from: b.l.a.a.l1.b */
/* loaded from: classes.dex */
public class C2207b {

    /* renamed from: c */
    public static final C2207b f5274c = new C2207b("");

    /* renamed from: e */
    @Nullable
    public final CharSequence f5275e;

    /* renamed from: f */
    @Nullable
    public final Layout.Alignment f5276f;

    /* renamed from: g */
    @Nullable
    public final Bitmap f5277g;

    /* renamed from: h */
    public final float f5278h;

    /* renamed from: i */
    public final int f5279i;

    /* renamed from: j */
    public final int f5280j;

    /* renamed from: k */
    public final float f5281k;

    /* renamed from: l */
    public final int f5282l;

    /* renamed from: m */
    public final float f5283m;

    /* renamed from: n */
    public final float f5284n;

    /* renamed from: o */
    public final boolean f5285o;

    /* renamed from: p */
    public final int f5286p;

    /* renamed from: q */
    public final int f5287q;

    /* renamed from: r */
    public final float f5288r;

    public C2207b(Bitmap bitmap, float f2, int i2, float f3, int i3, float f4, float f5) {
        this(null, null, bitmap, f3, 0, i3, f2, i2, Integer.MIN_VALUE, -3.4028235E38f, f4, f5, false, ViewCompat.MEASURED_STATE_MASK);
    }

    public C2207b(CharSequence charSequence) {
        this(charSequence, null, -3.4028235E38f, Integer.MIN_VALUE, Integer.MIN_VALUE, -3.4028235E38f, Integer.MIN_VALUE, -3.4028235E38f);
    }

    public C2207b(CharSequence charSequence, @Nullable Layout.Alignment alignment, float f2, int i2, int i3, float f3, int i4, float f4) {
        this(charSequence, alignment, f2, i2, i3, f3, i4, f4, false, ViewCompat.MEASURED_STATE_MASK);
    }

    public C2207b(CharSequence charSequence, @Nullable Layout.Alignment alignment, float f2, int i2, int i3, float f3, int i4, float f4, boolean z, int i5) {
        this(charSequence, alignment, null, f2, i2, i3, f3, i4, Integer.MIN_VALUE, -3.4028235E38f, f4, -3.4028235E38f, z, i5);
    }

    public C2207b(@Nullable CharSequence charSequence, @Nullable Layout.Alignment alignment, @Nullable Bitmap bitmap, float f2, int i2, int i3, float f3, int i4, int i5, float f4, float f5, float f6, boolean z, int i6) {
        this.f5275e = charSequence;
        this.f5276f = alignment;
        this.f5277g = bitmap;
        this.f5278h = f2;
        this.f5279i = i2;
        this.f5280j = i3;
        this.f5281k = f3;
        this.f5282l = i4;
        this.f5283m = f5;
        this.f5284n = f6;
        this.f5285o = z;
        this.f5286p = i6;
        this.f5287q = i5;
        this.f5288r = f4;
    }
}
