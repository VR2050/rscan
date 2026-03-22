package p005b.p081b0.p082a.p084b;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.NinePatchDrawable;
import android.text.style.ImageSpan;
import java.lang.ref.WeakReference;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: b.b0.a.b.a */
/* loaded from: classes2.dex */
public final class C1327a extends ImageSpan {

    /* renamed from: c */
    public int f1114c;

    /* renamed from: e */
    public int f1115e;

    /* renamed from: f */
    public int f1116f;

    /* renamed from: g */
    @NotNull
    public Rect f1117g;

    /* renamed from: h */
    @NotNull
    public Rect f1118h;

    /* renamed from: i */
    public int f1119i;

    /* renamed from: j */
    public int f1120j;

    /* renamed from: k */
    @Nullable
    public WeakReference<Drawable> f1121k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1327a(@NotNull Drawable drawable) {
        super(drawable);
        Intrinsics.checkNotNullParameter(drawable, "drawable");
        this.f1117g = new Rect();
        this.f1118h = new Rect();
        this.f1120j = 1;
    }

    /* renamed from: a */
    public void m335a(int i2, int i3) {
        Rect rect = this.f1117g;
        rect.left = i2;
        rect.right = i3;
        WeakReference<Drawable> weakReference = this.f1121k;
        if (weakReference == null) {
            return;
        }
        weakReference.clear();
    }

    /* renamed from: b */
    public void m336b(int i2, int i3) {
        Rect rect = this.f1117g;
        rect.top = i2;
        rect.bottom = i3;
        WeakReference<Drawable> weakReference = this.f1121k;
        if (weakReference == null) {
            return;
        }
        weakReference.clear();
    }

    @Override // android.text.style.DynamicDrawableSpan, android.text.style.ReplacementSpan
    public void draw(@NotNull Canvas canvas, @Nullable CharSequence charSequence, int i2, int i3, float f2, int i4, int i5, int i6, @NotNull Paint paint) {
        int height;
        int i7;
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Intrinsics.checkNotNullParameter(paint, "paint");
        canvas.save();
        Rect bounds = getDrawable().getBounds();
        Intrinsics.checkNotNullExpressionValue(bounds, "drawable.bounds");
        Paint.FontMetricsInt fontMetricsInt = paint.getFontMetricsInt();
        int i8 = this.f1120j;
        if (i8 != 0) {
            if (i8 == 1) {
                i7 = (((fontMetricsInt.descent + fontMetricsInt.ascent) - bounds.bottom) / 2) + i5;
            } else if (i8 != 2) {
                i7 = i8 != 3 ? 0 : (fontMetricsInt.ascent - fontMetricsInt.top) + i4;
            } else {
                height = ((bounds.height() + bounds.bottom) - fontMetricsInt.descent) / 2;
            }
            Rect rect = this.f1117g;
            canvas.translate(f2 + rect.left, (i7 - rect.bottom) + rect.top);
            getDrawable().draw(canvas);
            canvas.restore();
        }
        height = (bounds.height() + bounds.bottom) / 2;
        i7 = i5 - height;
        Rect rect2 = this.f1117g;
        canvas.translate(f2 + rect2.left, (i7 - rect2.bottom) + rect2.top);
        getDrawable().draw(canvas);
        canvas.restore();
    }

    @Override // android.text.style.ImageSpan, android.text.style.DynamicDrawableSpan
    @NotNull
    public Drawable getDrawable() {
        int width;
        int height;
        WeakReference<Drawable> weakReference = this.f1121k;
        Drawable drawable = weakReference == null ? null : weakReference.get();
        if (drawable == null) {
            drawable = super.getDrawable();
            Intrinsics.checkNotNullExpressionValue(drawable, "");
            int i2 = this.f1114c;
            if (i2 == -1) {
                width = this.f1118h.width();
            } else if (i2 != 1) {
                width = drawable.getIntrinsicWidth();
            } else {
                width = this.f1115e;
                if (width == 0) {
                    width = drawable.getIntrinsicWidth();
                }
            }
            this.f1115e = width;
            int i3 = this.f1114c;
            if (i3 == -1) {
                height = this.f1118h.height();
            } else if (i3 != 1) {
                height = drawable.getIntrinsicHeight();
            } else {
                height = this.f1116f;
                if (height == 0) {
                    height = drawable.getIntrinsicHeight();
                }
            }
            this.f1116f = height;
            int i4 = this.f1115e;
            if (drawable instanceof NinePatchDrawable) {
                NinePatchDrawable ninePatchDrawable = (NinePatchDrawable) drawable;
                i4 = Math.max(i4, ninePatchDrawable.getIntrinsicWidth());
                height = Math.max(height, ninePatchDrawable.getIntrinsicHeight());
            }
            drawable.getBounds().set(0, 0, i4, height);
            this.f1121k = new WeakReference<>(drawable);
            Intrinsics.checkNotNullExpressionValue(drawable, "super.getDrawable().apply {\n            setDrawableSize()\n            drawableRef = WeakReference(this)\n        }");
        }
        return drawable;
    }

    @Override // android.text.style.DynamicDrawableSpan, android.text.style.ReplacementSpan
    public int getSize(@NotNull Paint paint, @Nullable CharSequence charSequence, int i2, int i3, @Nullable Paint.FontMetricsInt fontMetricsInt) {
        Intrinsics.checkNotNullParameter(paint, "paint");
        Paint.FontMetricsInt fontMetricsInt2 = paint.getFontMetricsInt();
        int i4 = this.f1119i;
        if (i4 > 0) {
            paint.setTextSize(i4);
        }
        if (this.f1114c == -1) {
            Rect rect = new Rect();
            paint.getTextBounds(String.valueOf(charSequence), i2, i3, rect);
            this.f1118h.set(0, 0, rect.width() * 2, fontMetricsInt2.descent - fontMetricsInt2.ascent);
        }
        Rect bounds = getDrawable().getBounds();
        Intrinsics.checkNotNullExpressionValue(bounds, "drawable.bounds");
        if (fontMetricsInt != null) {
            int height = bounds.height();
            int i5 = this.f1120j;
            if (i5 == 0) {
                int i6 = fontMetricsInt2.descent;
                int i7 = (i6 - height) - i6;
                Rect rect2 = this.f1117g;
                fontMetricsInt.ascent = (i7 - rect2.top) - rect2.bottom;
                fontMetricsInt.descent = 0;
            } else if (i5 == 1) {
                int i8 = fontMetricsInt2.descent;
                int i9 = fontMetricsInt2.ascent;
                int i10 = i9 - ((height - (i8 - i9)) / 2);
                Rect rect3 = this.f1117g;
                int i11 = i10 - rect3.top;
                fontMetricsInt.ascent = i11;
                fontMetricsInt.descent = i11 + height + rect3.bottom;
            } else if (i5 == 2) {
                int i12 = (-fontMetricsInt2.descent) - height;
                Rect rect4 = this.f1117g;
                fontMetricsInt.ascent = (i12 - rect4.top) - rect4.bottom;
                fontMetricsInt.descent = 0;
            } else if (i5 == 3) {
                int i13 = fontMetricsInt2.ascent;
                Rect rect5 = this.f1117g;
                int i14 = i13 + rect5.top;
                fontMetricsInt.ascent = i14;
                fontMetricsInt.descent = i14 + height + rect5.bottom;
            }
            fontMetricsInt.top = fontMetricsInt.ascent;
            fontMetricsInt.bottom = fontMetricsInt.descent;
        }
        int i15 = bounds.right;
        Rect rect6 = this.f1117g;
        return i15 + rect6.left + rect6.right;
    }
}
