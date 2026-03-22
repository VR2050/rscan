package com.angcyo.tablayout;

import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000z\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\b\n\u0002\u0010\u0015\n\u0002\b\u0005\n\u0002\u0010\u0014\n\u0002\b\u000b\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u001f\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0016\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0012\u0010J\u001a\u0004\u0018\u00010\r2\b\u0010K\u001a\u0004\u0018\u00010LJ\u0016\u0010M\u001a\u00020N2\u0006\u0010O\u001a\u00020\u00132\u0006\u0010P\u001a\u00020\u0004J\u0016\u0010M\u001a\u00020N2\u0006\u0010O\u001a\u00020\u00132\u0006\u0010P\u001a\u00020\u001fJ\u0018\u0010M\u001a\u00020N2\u0006\u0010O\u001a\u00020\u00132\b\u0010Q\u001a\u0004\u0018\u00010LJ!\u0010R\u001a\u00020\u00002\u0017\u0010S\u001a\u0013\u0012\u0004\u0012\u00020\u0000\u0012\u0004\u0012\u00020N0T¢\u0006\u0002\bUH\u0016J\u000e\u0010V\u001a\u00020N2\u0006\u0010Q\u001a\u00020\u0013J\u000e\u0010W\u001a\u00020N2\u0006\u0010Q\u001a\u00020\u0004J\u000e\u0010X\u001a\u00020N2\u0006\u0010Q\u001a\u00020\u0004J\u000e\u0010Y\u001a\u00020N2\u0006\u0010Q\u001a\u00020\u0004J\u000e\u0010Z\u001a\u00020N2\u0006\u0010Q\u001a\u00020\u0004J\u000e\u0010[\u001a\u00020N2\u0006\u0010Q\u001a\u00020\u0004J.\u0010[\u001a\u00020N2\b\b\u0002\u0010\\\u001a\u00020\u00042\b\b\u0002\u0010]\u001a\u00020\u00042\b\b\u0002\u0010^\u001a\u00020\u00042\b\b\u0002\u0010_\u001a\u00020\u0004J\u0010\u0010`\u001a\u00020N2\u0006\u0010a\u001a\u00020bH\u0016J\u000e\u0010c\u001a\u00020N2\u0006\u0010P\u001a\u00020\u0004J\u000e\u0010c\u001a\u00020N2\u0006\u0010P\u001a\u00020\u001fJ\b\u0010d\u001a\u00020\rH\u0016J\b\u0010e\u001a\u00020fH\u0016J\u0012\u0010g\u001a\u00020N2\b\u0010h\u001a\u0004\u0018\u00010iH\u0016J\u0010\u0010j\u001a\u00020f2\u0006\u0010k\u001a\u00020\rH\u0016J\u0012\u0010l\u001a\u00020N2\b\u0010m\u001a\u0004\u0018\u00010nH\u0016J\n\u0010o\u001a\u0004\u0018\u00010pH\u0016R\u001a\u0010\u0003\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR\u001a\u0010\t\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\n\u0010\u0006\"\u0004\b\u000b\u0010\bR\u001c\u0010\f\u001a\u0004\u0018\u00010\rX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011R\u001c\u0010\u0012\u001a\u0004\u0018\u00010\u0013X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0014\u0010\u0015\"\u0004\b\u0016\u0010\u0017R\u001a\u0010\u0018\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0019\u0010\u0006\"\u0004\b\u001a\u0010\bR\u001a\u0010\u001b\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001c\u0010\u0006\"\u0004\b\u001d\u0010\bR\u001a\u0010\u001e\u001a\u00020\u001fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b \u0010!\"\u0004\b\"\u0010#R\u001a\u0010$\u001a\u00020%X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b&\u0010'\"\u0004\b(\u0010)R\u001a\u0010*\u001a\u00020\u0013X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b+\u0010\u0015\"\u0004\b,\u0010\u0017R\u001a\u0010-\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b.\u0010\u0006\"\u0004\b/\u0010\bR \u00100\u001a\u00020\u001fX\u0086\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b1\u0010\u0002\u001a\u0004\b2\u0010!\"\u0004\b3\u0010#R\u001a\u00104\u001a\u00020\u001fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b5\u0010!\"\u0004\b6\u0010#R\u001a\u00107\u001a\u00020\u001fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b8\u0010!\"\u0004\b9\u0010#R\u001a\u0010:\u001a\u00020\u001fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b;\u0010!\"\u0004\b<\u0010#R \u0010=\u001a\u00020\u001fX\u0086\u000e¢\u0006\u0014\n\u0000\u0012\u0004\b>\u0010\u0002\u001a\u0004\b?\u0010!\"\u0004\b@\u0010#R\u001a\u0010A\u001a\u00020\u001fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bB\u0010!\"\u0004\bC\u0010#R\u001c\u0010D\u001a\u0004\u0018\u00010EX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bF\u0010G\"\u0004\bH\u0010I¨\u0006q"}, m5311d2 = {"Lcom/angcyo/tablayout/DslGradientDrawable;", "Lcom/angcyo/tablayout/AbsDslDrawable;", "()V", "gradientCenterX", "", "getGradientCenterX", "()F", "setGradientCenterX", "(F)V", "gradientCenterY", "getGradientCenterY", "setGradientCenterY", "gradientColors", "", "getGradientColors", "()[I", "setGradientColors", "([I)V", "gradientColorsOffsets", "", "getGradientColorsOffsets", "()[F", "setGradientColorsOffsets", "([F)V", "gradientDashGap", "getGradientDashGap", "setGradientDashGap", "gradientDashWidth", "getGradientDashWidth", "setGradientDashWidth", "gradientHeightOffset", "", "getGradientHeightOffset", "()I", "setGradientHeightOffset", "(I)V", "gradientOrientation", "Landroid/graphics/drawable/GradientDrawable$Orientation;", "getGradientOrientation", "()Landroid/graphics/drawable/GradientDrawable$Orientation;", "setGradientOrientation", "(Landroid/graphics/drawable/GradientDrawable$Orientation;)V", "gradientRadii", "getGradientRadii", "setGradientRadii", "gradientRadius", "getGradientRadius", "setGradientRadius", "gradientShape", "getGradientShape$annotations", "getGradientShape", "setGradientShape", "gradientSolidColor", "getGradientSolidColor", "setGradientSolidColor", "gradientStrokeColor", "getGradientStrokeColor", "setGradientStrokeColor", "gradientStrokeWidth", "getGradientStrokeWidth", "setGradientStrokeWidth", "gradientType", "getGradientType$annotations", "getGradientType", "setGradientType", "gradientWidthOffset", "getGradientWidthOffset", "setGradientWidthOffset", "originDrawable", "Landroid/graphics/drawable/Drawable;", "getOriginDrawable", "()Landroid/graphics/drawable/Drawable;", "setOriginDrawable", "(Landroid/graphics/drawable/Drawable;)V", "_fillColor", "colors", "", "_fillRadii", "", "array", "radius", "radii", "configDrawable", "config", "Lkotlin/Function1;", "Lkotlin/ExtensionFunctionType;", "cornerRadii", "cornerRadiiBottom", "cornerRadiiLeft", "cornerRadiiRight", "cornerRadiiTop", "cornerRadius", "leftTop", "rightTop", "rightBottom", "leftBottom", "draw", "canvas", "Landroid/graphics/Canvas;", "fillRadii", "getState", "isValidConfig", "", "setColorFilter", "colorFilter", "Landroid/graphics/ColorFilter;", "setState", "stateSet", "setTintList", "tint", "Landroid/content/res/ColorStateList;", "updateOriginDrawable", "Landroid/graphics/drawable/GradientDrawable;", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.f, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public class DslGradientDrawable extends AbsDslDrawable {

    /* renamed from: b */
    public int f1553b;

    /* renamed from: c */
    public int f1554c;

    /* renamed from: d */
    public int f1555d;

    /* renamed from: e */
    public int f1556e;

    /* renamed from: f */
    public float f1557f;

    /* renamed from: g */
    public float f1558g;

    /* renamed from: i */
    @Nullable
    public int[] f1560i;

    /* renamed from: n */
    @Nullable
    public Drawable f1565n;

    /* renamed from: o */
    public int f1566o;

    /* renamed from: p */
    public int f1567p;

    /* renamed from: h */
    @NotNull
    public float[] f1559h = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};

    /* renamed from: j */
    public float f1561j = 0.5f;

    /* renamed from: k */
    public float f1562k = 0.5f;

    /* renamed from: l */
    public float f1563l = 0.5f;

    /* renamed from: m */
    @NotNull
    public GradientDrawable.Orientation f1564m = GradientDrawable.Orientation.LEFT_RIGHT;

    @Override // android.graphics.drawable.Drawable
    public void draw(@NotNull Canvas canvas) {
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        Drawable drawable = this.f1565n;
        if (drawable == null) {
            return;
        }
        drawable.setBounds(getBounds().left - (this.f1566o / 2), getBounds().top - (this.f1567p / 2), (this.f1566o / 2) + getBounds().right, (this.f1567p / 2) + getBounds().bottom);
        drawable.draw(canvas);
    }

    @Override // android.graphics.drawable.Drawable
    @NotNull
    public int[] getState() {
        Drawable drawable = this.f1565n;
        int[] state = drawable == null ? null : drawable.getState();
        if (state != null) {
            return state;
        }
        int[] state2 = super.getState();
        Intrinsics.checkNotNullExpressionValue(state2, "super.getState()");
        return state2;
    }

    /* renamed from: i */
    public boolean m655i() {
        return (this.f1554c == 0 && this.f1555d == 0 && this.f1560i == null) ? false : true;
    }

    /* renamed from: j */
    public final void m656j(@NotNull float[] fArr) {
        Intrinsics.checkNotNullParameter(fArr, "<set-?>");
        this.f1559h = fArr;
    }

    @Nullable
    /* renamed from: k */
    public GradientDrawable mo657k() {
        Drawable drawable = this.f1565n;
        GradientDrawable gradientDrawable = drawable == null ? new GradientDrawable() : drawable instanceof GradientDrawable ? (GradientDrawable) drawable : null;
        if (gradientDrawable != null) {
            gradientDrawable.setBounds(getBounds());
            gradientDrawable.setShape(this.f1553b);
            gradientDrawable.setStroke(this.f1556e, this.f1555d, this.f1557f, this.f1558g);
            gradientDrawable.setColor(this.f1554c);
            gradientDrawable.setCornerRadii(this.f1559h);
            if (this.f1560i != null) {
                int i2 = Build.VERSION.SDK_INT;
                if (i2 >= 24) {
                    gradientDrawable.setGradientCenter(this.f1561j, this.f1562k);
                }
                gradientDrawable.setGradientRadius(this.f1563l);
                gradientDrawable.setGradientType(0);
                gradientDrawable.setOrientation(this.f1564m);
                if (i2 >= 29) {
                    gradientDrawable.setColors(this.f1560i, null);
                } else {
                    gradientDrawable.setColors(this.f1560i);
                }
            }
            this.f1565n = gradientDrawable;
            gradientDrawable.invalidateSelf();
        }
        return gradientDrawable;
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(@Nullable ColorFilter colorFilter) {
        m649f().setColorFilter(colorFilter);
        invalidateSelf();
        Drawable drawable = this.f1565n;
        if (drawable == null) {
            return;
        }
        drawable.setColorFilter(colorFilter);
    }

    @Override // android.graphics.drawable.Drawable
    public boolean setState(@NotNull int[] stateSet) {
        Intrinsics.checkNotNullParameter(stateSet, "stateSet");
        Drawable drawable = this.f1565n;
        Boolean valueOf = drawable == null ? null : Boolean.valueOf(drawable.setState(stateSet));
        return valueOf == null ? super.setState(stateSet) : valueOf.booleanValue();
    }

    @Override // com.angcyo.tablayout.AbsDslDrawable, android.graphics.drawable.Drawable
    public void setTintList(@Nullable ColorStateList tint) {
        super.setTintList(tint);
        Drawable drawable = this.f1565n;
        if (drawable == null) {
            return;
        }
        drawable.setTintList(tint);
    }
}
