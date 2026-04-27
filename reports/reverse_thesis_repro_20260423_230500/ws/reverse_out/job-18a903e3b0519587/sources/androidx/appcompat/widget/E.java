package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.RectF;
import android.os.Build;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextDirectionHeuristic;
import android.text.TextDirectionHeuristics;
import android.text.TextPaint;
import android.text.method.TransformationMethod;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.Log;
import android.util.TypedValue;
import android.widget.TextView;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;

/* JADX INFO: loaded from: classes.dex */
class E {

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static final RectF f3746l = new RectF();

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static ConcurrentHashMap f3747m = new ConcurrentHashMap();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f3748a = 0;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f3749b = false;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float f3750c = -1.0f;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private float f3751d = -1.0f;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private float f3752e = -1.0f;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int[] f3753f = new int[0];

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f3754g = false;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private TextPaint f3755h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final TextView f3756i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final Context f3757j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final d f3758k;

    private static final class a {
        static StaticLayout a(CharSequence charSequence, Layout.Alignment alignment, int i3, int i4, TextView textView, TextPaint textPaint, d dVar) {
            StaticLayout.Builder builderObtain = StaticLayout.Builder.obtain(charSequence, 0, charSequence.length(), textPaint, i3);
            StaticLayout.Builder hyphenationFrequency = builderObtain.setAlignment(alignment).setLineSpacing(textView.getLineSpacingExtra(), textView.getLineSpacingMultiplier()).setIncludePad(textView.getIncludeFontPadding()).setBreakStrategy(textView.getBreakStrategy()).setHyphenationFrequency(textView.getHyphenationFrequency());
            if (i4 == -1) {
                i4 = Integer.MAX_VALUE;
            }
            hyphenationFrequency.setMaxLines(i4);
            try {
                dVar.a(builderObtain, textView);
            } catch (ClassCastException unused) {
                Log.w("ACTVAutoSizeHelper", "Failed to obtain TextDirectionHeuristic, auto size may be incorrect");
            }
            return builderObtain.build();
        }
    }

    private static class b extends d {
        b() {
        }

        @Override // androidx.appcompat.widget.E.d
        void a(StaticLayout.Builder builder, TextView textView) {
            builder.setTextDirection((TextDirectionHeuristic) E.m(textView, "getTextDirectionHeuristic", TextDirectionHeuristics.FIRSTSTRONG_LTR));
        }
    }

    private static class c extends b {
        c() {
        }

        @Override // androidx.appcompat.widget.E.b, androidx.appcompat.widget.E.d
        void a(StaticLayout.Builder builder, TextView textView) {
            builder.setTextDirection(textView.getTextDirectionHeuristic());
        }

        @Override // androidx.appcompat.widget.E.d
        boolean b(TextView textView) {
            return textView.isHorizontallyScrollable();
        }
    }

    private static class d {
        d() {
        }

        abstract void a(StaticLayout.Builder builder, TextView textView);

        boolean b(TextView textView) {
            return ((Boolean) E.m(textView, "getHorizontallyScrolling", Boolean.FALSE)).booleanValue();
        }
    }

    E(TextView textView) {
        this.f3756i = textView;
        this.f3757j = textView.getContext();
        if (Build.VERSION.SDK_INT >= 29) {
            this.f3758k = new c();
        } else {
            this.f3758k = new b();
        }
    }

    private int[] b(int[] iArr) {
        int length = iArr.length;
        if (length == 0) {
            return iArr;
        }
        Arrays.sort(iArr);
        ArrayList arrayList = new ArrayList();
        for (int i3 : iArr) {
            if (i3 > 0 && Collections.binarySearch(arrayList, Integer.valueOf(i3)) < 0) {
                arrayList.add(Integer.valueOf(i3));
            }
        }
        if (length == arrayList.size()) {
            return iArr;
        }
        int size = arrayList.size();
        int[] iArr2 = new int[size];
        for (int i4 = 0; i4 < size; i4++) {
            iArr2[i4] = ((Integer) arrayList.get(i4)).intValue();
        }
        return iArr2;
    }

    private void c() {
        this.f3748a = 0;
        this.f3751d = -1.0f;
        this.f3752e = -1.0f;
        this.f3750c = -1.0f;
        this.f3753f = new int[0];
        this.f3749b = false;
    }

    private int e(RectF rectF) {
        int length = this.f3753f.length;
        if (length == 0) {
            throw new IllegalStateException("No available text sizes to choose from.");
        }
        int i3 = 1;
        int i4 = length - 1;
        int i5 = 0;
        while (i3 <= i4) {
            int i6 = (i3 + i4) / 2;
            if (x(this.f3753f[i6], rectF)) {
                int i7 = i6 + 1;
                i5 = i3;
                i3 = i7;
            } else {
                i5 = i6 - 1;
                i4 = i5;
            }
        }
        return this.f3753f[i5];
    }

    private static Method k(String str) {
        try {
            Method declaredMethod = (Method) f3747m.get(str);
            if (declaredMethod == null && (declaredMethod = TextView.class.getDeclaredMethod(str, new Class[0])) != null) {
                declaredMethod.setAccessible(true);
                f3747m.put(str, declaredMethod);
            }
            return declaredMethod;
        } catch (Exception e3) {
            Log.w("ACTVAutoSizeHelper", "Failed to retrieve TextView#" + str + "() method", e3);
            return null;
        }
    }

    static Object m(Object obj, String str, Object obj2) {
        try {
            return k(str).invoke(obj, new Object[0]);
        } catch (Exception e3) {
            Log.w("ACTVAutoSizeHelper", "Failed to invoke TextView#" + str + "() method", e3);
            return obj2;
        }
    }

    private void s(float f3) {
        if (f3 != this.f3756i.getPaint().getTextSize()) {
            this.f3756i.getPaint().setTextSize(f3);
            boolean zIsInLayout = this.f3756i.isInLayout();
            if (this.f3756i.getLayout() != null) {
                this.f3749b = false;
                try {
                    Method methodK = k("nullLayouts");
                    if (methodK != null) {
                        methodK.invoke(this.f3756i, new Object[0]);
                    }
                } catch (Exception e3) {
                    Log.w("ACTVAutoSizeHelper", "Failed to invoke TextView#nullLayouts() method", e3);
                }
                if (zIsInLayout) {
                    this.f3756i.forceLayout();
                } else {
                    this.f3756i.requestLayout();
                }
                this.f3756i.invalidate();
            }
        }
    }

    private boolean u() {
        if (y() && this.f3748a == 1) {
            if (!this.f3754g || this.f3753f.length == 0) {
                int iFloor = ((int) Math.floor((this.f3752e - this.f3751d) / this.f3750c)) + 1;
                int[] iArr = new int[iFloor];
                for (int i3 = 0; i3 < iFloor; i3++) {
                    iArr[i3] = Math.round(this.f3751d + (i3 * this.f3750c));
                }
                this.f3753f = b(iArr);
            }
            this.f3749b = true;
        } else {
            this.f3749b = false;
        }
        return this.f3749b;
    }

    private void v(TypedArray typedArray) {
        int length = typedArray.length();
        int[] iArr = new int[length];
        if (length > 0) {
            for (int i3 = 0; i3 < length; i3++) {
                iArr[i3] = typedArray.getDimensionPixelSize(i3, -1);
            }
            this.f3753f = b(iArr);
            w();
        }
    }

    private boolean w() {
        boolean z3 = this.f3753f.length > 0;
        this.f3754g = z3;
        if (z3) {
            this.f3748a = 1;
            this.f3751d = r0[0];
            this.f3752e = r0[r1 - 1];
            this.f3750c = -1.0f;
        }
        return z3;
    }

    private boolean x(int i3, RectF rectF) {
        CharSequence transformation;
        CharSequence text = this.f3756i.getText();
        TransformationMethod transformationMethod = this.f3756i.getTransformationMethod();
        if (transformationMethod != null && (transformation = transformationMethod.getTransformation(text, this.f3756i)) != null) {
            text = transformation;
        }
        int maxLines = this.f3756i.getMaxLines();
        l(i3);
        StaticLayout staticLayoutD = d(text, (Layout.Alignment) m(this.f3756i, "getLayoutAlignment", Layout.Alignment.ALIGN_NORMAL), Math.round(rectF.right), maxLines);
        return (maxLines == -1 || (staticLayoutD.getLineCount() <= maxLines && staticLayoutD.getLineEnd(staticLayoutD.getLineCount() - 1) == text.length())) && ((float) staticLayoutD.getHeight()) <= rectF.bottom;
    }

    private boolean y() {
        return !(this.f3756i instanceof C0238l);
    }

    private void z(float f3, float f4, float f5) {
        if (f3 <= 0.0f) {
            throw new IllegalArgumentException("Minimum auto-size text size (" + f3 + "px) is less or equal to (0px)");
        }
        if (f4 <= f3) {
            throw new IllegalArgumentException("Maximum auto-size text size (" + f4 + "px) is less or equal to minimum auto-size text size (" + f3 + "px)");
        }
        if (f5 <= 0.0f) {
            throw new IllegalArgumentException("The auto-size step granularity (" + f5 + "px) is less or equal to (0px)");
        }
        this.f3748a = 1;
        this.f3751d = f3;
        this.f3752e = f4;
        this.f3750c = f5;
        this.f3754g = false;
    }

    void a() {
        if (n()) {
            if (this.f3749b) {
                if (this.f3756i.getMeasuredHeight() <= 0 || this.f3756i.getMeasuredWidth() <= 0) {
                    return;
                }
                int measuredWidth = this.f3758k.b(this.f3756i) ? 1048576 : (this.f3756i.getMeasuredWidth() - this.f3756i.getTotalPaddingLeft()) - this.f3756i.getTotalPaddingRight();
                int height = (this.f3756i.getHeight() - this.f3756i.getCompoundPaddingBottom()) - this.f3756i.getCompoundPaddingTop();
                if (measuredWidth <= 0 || height <= 0) {
                    return;
                }
                RectF rectF = f3746l;
                synchronized (rectF) {
                    try {
                        rectF.setEmpty();
                        rectF.right = measuredWidth;
                        rectF.bottom = height;
                        float fE = e(rectF);
                        if (fE != this.f3756i.getTextSize()) {
                            t(0, fE);
                        }
                    } finally {
                    }
                }
            }
            this.f3749b = true;
        }
    }

    StaticLayout d(CharSequence charSequence, Layout.Alignment alignment, int i3, int i4) {
        return a.a(charSequence, alignment, i3, i4, this.f3756i, this.f3755h, this.f3758k);
    }

    int f() {
        return Math.round(this.f3752e);
    }

    int g() {
        return Math.round(this.f3751d);
    }

    int h() {
        return Math.round(this.f3750c);
    }

    int[] i() {
        return this.f3753f;
    }

    int j() {
        return this.f3748a;
    }

    void l(int i3) {
        TextPaint textPaint = this.f3755h;
        if (textPaint == null) {
            this.f3755h = new TextPaint();
        } else {
            textPaint.reset();
        }
        this.f3755h.set(this.f3756i.getPaint());
        this.f3755h.setTextSize(i3);
    }

    boolean n() {
        return y() && this.f3748a != 0;
    }

    void o(AttributeSet attributeSet, int i3) {
        int resourceId;
        TypedArray typedArrayObtainStyledAttributes = this.f3757j.obtainStyledAttributes(attributeSet, d.j.f9067g0, i3, 0);
        TextView textView = this.f3756i;
        androidx.core.view.V.V(textView, textView.getContext(), d.j.f9067g0, attributeSet, typedArrayObtainStyledAttributes, i3, 0);
        if (typedArrayObtainStyledAttributes.hasValue(d.j.f9087l0)) {
            this.f3748a = typedArrayObtainStyledAttributes.getInt(d.j.f9087l0, 0);
        }
        float dimension = typedArrayObtainStyledAttributes.hasValue(d.j.f9083k0) ? typedArrayObtainStyledAttributes.getDimension(d.j.f9083k0, -1.0f) : -1.0f;
        float dimension2 = typedArrayObtainStyledAttributes.hasValue(d.j.f9075i0) ? typedArrayObtainStyledAttributes.getDimension(d.j.f9075i0, -1.0f) : -1.0f;
        float dimension3 = typedArrayObtainStyledAttributes.hasValue(d.j.f9071h0) ? typedArrayObtainStyledAttributes.getDimension(d.j.f9071h0, -1.0f) : -1.0f;
        if (typedArrayObtainStyledAttributes.hasValue(d.j.f9079j0) && (resourceId = typedArrayObtainStyledAttributes.getResourceId(d.j.f9079j0, 0)) > 0) {
            TypedArray typedArrayObtainTypedArray = typedArrayObtainStyledAttributes.getResources().obtainTypedArray(resourceId);
            v(typedArrayObtainTypedArray);
            typedArrayObtainTypedArray.recycle();
        }
        typedArrayObtainStyledAttributes.recycle();
        if (!y()) {
            this.f3748a = 0;
            return;
        }
        if (this.f3748a == 1) {
            if (!this.f3754g) {
                DisplayMetrics displayMetrics = this.f3757j.getResources().getDisplayMetrics();
                if (dimension2 == -1.0f) {
                    dimension2 = TypedValue.applyDimension(2, 12.0f, displayMetrics);
                }
                if (dimension3 == -1.0f) {
                    dimension3 = TypedValue.applyDimension(2, 112.0f, displayMetrics);
                }
                if (dimension == -1.0f) {
                    dimension = 1.0f;
                }
                z(dimension2, dimension3, dimension);
            }
            u();
        }
    }

    void p(int i3, int i4, int i5, int i6) {
        if (y()) {
            DisplayMetrics displayMetrics = this.f3757j.getResources().getDisplayMetrics();
            z(TypedValue.applyDimension(i6, i3, displayMetrics), TypedValue.applyDimension(i6, i4, displayMetrics), TypedValue.applyDimension(i6, i5, displayMetrics));
            if (u()) {
                a();
            }
        }
    }

    void q(int[] iArr, int i3) {
        if (y()) {
            int length = iArr.length;
            if (length > 0) {
                int[] iArrCopyOf = new int[length];
                if (i3 == 0) {
                    iArrCopyOf = Arrays.copyOf(iArr, length);
                } else {
                    DisplayMetrics displayMetrics = this.f3757j.getResources().getDisplayMetrics();
                    for (int i4 = 0; i4 < length; i4++) {
                        iArrCopyOf[i4] = Math.round(TypedValue.applyDimension(i3, iArr[i4], displayMetrics));
                    }
                }
                this.f3753f = b(iArrCopyOf);
                if (!w()) {
                    throw new IllegalArgumentException("None of the preset sizes is valid: " + Arrays.toString(iArr));
                }
            } else {
                this.f3754g = false;
            }
            if (u()) {
                a();
            }
        }
    }

    void r(int i3) {
        if (y()) {
            if (i3 == 0) {
                c();
                return;
            }
            if (i3 != 1) {
                throw new IllegalArgumentException("Unknown auto-size text type: " + i3);
            }
            DisplayMetrics displayMetrics = this.f3757j.getResources().getDisplayMetrics();
            z(TypedValue.applyDimension(2, 12.0f, displayMetrics), TypedValue.applyDimension(2, 112.0f, displayMetrics), 1.0f);
            if (u()) {
                a();
            }
        }
    }

    void t(int i3, float f3) {
        Context context = this.f3757j;
        s(TypedValue.applyDimension(i3, f3, (context == null ? Resources.getSystem() : context.getResources()).getDisplayMetrics()));
    }
}
