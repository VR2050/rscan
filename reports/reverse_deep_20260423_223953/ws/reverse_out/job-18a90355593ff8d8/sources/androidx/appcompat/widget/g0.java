package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.util.TypedValue;
import androidx.core.content.res.f;
import e.AbstractC0510a;

/* JADX INFO: loaded from: classes.dex */
public class g0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f4072a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final TypedArray f4073b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private TypedValue f4074c;

    private g0(Context context, TypedArray typedArray) {
        this.f4072a = context;
        this.f4073b = typedArray;
    }

    public static g0 s(Context context, int i3, int[] iArr) {
        return new g0(context, context.obtainStyledAttributes(i3, iArr));
    }

    public static g0 t(Context context, AttributeSet attributeSet, int[] iArr) {
        return new g0(context, context.obtainStyledAttributes(attributeSet, iArr));
    }

    public static g0 u(Context context, AttributeSet attributeSet, int[] iArr, int i3, int i4) {
        return new g0(context, context.obtainStyledAttributes(attributeSet, iArr, i3, i4));
    }

    public boolean a(int i3, boolean z3) {
        return this.f4073b.getBoolean(i3, z3);
    }

    public int b(int i3, int i4) {
        return this.f4073b.getColor(i3, i4);
    }

    public ColorStateList c(int i3) {
        int resourceId;
        ColorStateList colorStateListA;
        return (!this.f4073b.hasValue(i3) || (resourceId = this.f4073b.getResourceId(i3, 0)) == 0 || (colorStateListA = AbstractC0510a.a(this.f4072a, resourceId)) == null) ? this.f4073b.getColorStateList(i3) : colorStateListA;
    }

    public int d(int i3, int i4) {
        return this.f4073b.getDimensionPixelOffset(i3, i4);
    }

    public int e(int i3, int i4) {
        return this.f4073b.getDimensionPixelSize(i3, i4);
    }

    public Drawable f(int i3) {
        int resourceId;
        return (!this.f4073b.hasValue(i3) || (resourceId = this.f4073b.getResourceId(i3, 0)) == 0) ? this.f4073b.getDrawable(i3) : AbstractC0510a.b(this.f4072a, resourceId);
    }

    public Drawable g(int i3) {
        int resourceId;
        if (!this.f4073b.hasValue(i3) || (resourceId = this.f4073b.getResourceId(i3, 0)) == 0) {
            return null;
        }
        return C0237k.b().d(this.f4072a, resourceId, true);
    }

    public float h(int i3, float f3) {
        return this.f4073b.getFloat(i3, f3);
    }

    public Typeface i(int i3, int i4, f.e eVar) {
        int resourceId = this.f4073b.getResourceId(i3, 0);
        if (resourceId == 0) {
            return null;
        }
        if (this.f4074c == null) {
            this.f4074c = new TypedValue();
        }
        return androidx.core.content.res.f.g(this.f4072a, resourceId, this.f4074c, i4, eVar);
    }

    public int j(int i3, int i4) {
        return this.f4073b.getInt(i3, i4);
    }

    public int k(int i3, int i4) {
        return this.f4073b.getInteger(i3, i4);
    }

    public int l(int i3, int i4) {
        return this.f4073b.getLayoutDimension(i3, i4);
    }

    public int m(int i3, int i4) {
        return this.f4073b.getResourceId(i3, i4);
    }

    public String n(int i3) {
        return this.f4073b.getString(i3);
    }

    public CharSequence o(int i3) {
        return this.f4073b.getText(i3);
    }

    public CharSequence[] p(int i3) {
        return this.f4073b.getTextArray(i3);
    }

    public TypedArray q() {
        return this.f4073b;
    }

    public boolean r(int i3) {
        return this.f4073b.hasValue(i3);
    }

    public TypedValue v(int i3) {
        return this.f4073b.peekValue(i3);
    }

    public void w() {
        this.f4073b.recycle();
    }
}
