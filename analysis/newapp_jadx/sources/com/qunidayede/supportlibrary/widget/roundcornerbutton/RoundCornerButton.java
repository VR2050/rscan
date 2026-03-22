package com.qunidayede.supportlibrary.widget.roundcornerbutton;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.StateListDrawable;
import android.util.AttributeSet;
import androidx.appcompat.widget.AppCompatButton;
import com.qunidayede.supportlibrary.R$styleable;
import kotlin.Metadata;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p327w.p330b.p338e.p339b.C2864a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u0013\b\u0016\u0012\b\u0010\u001e\u001a\u0004\u0018\u00010\u001d¢\u0006\u0004\b\u001f\u0010 B'\b\u0017\u0012\b\u0010\u001e\u001a\u0004\u0018\u00010\u001d\u0012\b\u0010\"\u001a\u0004\u0018\u00010!\u0012\b\b\u0002\u0010#\u001a\u00020\u0004¢\u0006\u0004\b\u001f\u0010$J7\u0010\n\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\u0004H\u0014¢\u0006\u0004\b\n\u0010\u000bR\u0018\u0010\u000f\u001a\u0004\u0018\u00010\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\r\u0010\u000eR\u0016\u0010\u0012\u001a\u00020\u00048\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0010\u0010\u0011R\u0016\u0010\u0014\u001a\u00020\u00048\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0013\u0010\u0011R\u0018\u0010\u0016\u001a\u0004\u0018\u00010\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0015\u0010\u000eR\u0018\u0010\u0018\u001a\u0004\u0018\u00010\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0017\u0010\u000eR\u0016\u0010\u001c\u001a\u00020\u00198\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001a\u0010\u001b¨\u0006%"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/widget/roundcornerbutton/RoundCornerButton;", "Landroidx/appcompat/widget/AppCompatButton;", "", "changed", "", "left", "top", "right", "bottom", "", "onLayout", "(ZIIII)V", "Lb/w/b/e/b/a;", "h", "Lb/w/b/e/b/a;", "bgDrawablePressed", "c", "I", "colorNormal", C1568e.f1949a, "colorDisabled", "i", "bgDrawableDisabled", "g", "bgDrawableNormal", "", "f", "F", "cornerRadius", "Landroid/content/Context;", "context", "<init>", "(Landroid/content/Context;)V", "Landroid/util/AttributeSet;", "attrs", "defStyleAttr", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RoundCornerButton extends AppCompatButton {

    /* renamed from: c, reason: from kotlin metadata */
    public int colorNormal;

    /* renamed from: e, reason: from kotlin metadata */
    public int colorDisabled;

    /* renamed from: f, reason: from kotlin metadata */
    public float cornerRadius;

    /* renamed from: g, reason: from kotlin metadata */
    @Nullable
    public C2864a bgDrawableNormal;

    /* renamed from: h, reason: from kotlin metadata */
    @Nullable
    public C2864a bgDrawablePressed;

    /* renamed from: i, reason: from kotlin metadata */
    @Nullable
    public C2864a bgDrawableDisabled;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public RoundCornerButton(@Nullable Context context) {
        super(context);
        Intrinsics.checkNotNull(context);
    }

    @Override // androidx.appcompat.widget.AppCompatButton, android.widget.TextView, android.view.View
    public void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        C2864a c2864a = this.bgDrawableNormal;
        if (c2864a != null) {
            c2864a.m3307a(right - left, bottom - top);
        }
        C2864a c2864a2 = this.bgDrawablePressed;
        if (c2864a2 != null) {
            c2864a2.m3307a(right - left, bottom - top);
        }
        C2864a c2864a3 = this.bgDrawableDisabled;
        if (c2864a3 == null) {
            return;
        }
        c2864a3.m3307a(right - left, bottom - top);
    }

    @JvmOverloads
    public RoundCornerButton(@Nullable Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public RoundCornerButton(@Nullable Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNull(context);
        TypedArray obtainStyledAttributes = getContext().obtainStyledAttributes(attributeSet, R$styleable.RoundCornerButton, i2, 0);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttributes(attrs, R.styleable.RoundCornerButton, defStyleAttr, 0)");
        this.cornerRadius = obtainStyledAttributes.getDimension(R$styleable.RoundCornerButton_rcb_cornerRadius, 0.0f);
        int color = obtainStyledAttributes.getColor(R$styleable.RoundCornerButton_rcb_backgroundColor, 0);
        this.colorNormal = color;
        this.colorDisabled = obtainStyledAttributes.getColor(R$styleable.RoundCornerButton_rcb_backgroundColorDisabled, color);
        C2864a c2864a = new C2864a(this.colorNormal, this.cornerRadius);
        this.bgDrawableNormal = c2864a;
        c2864a.m3307a(getWidth(), getHeight());
        C2864a c2864a2 = new C2864a(1342177280 | (16777215 & this.colorNormal), this.cornerRadius);
        this.bgDrawablePressed = c2864a2;
        c2864a2.m3307a(getWidth(), getHeight());
        C2864a c2864a3 = new C2864a(this.colorDisabled, this.cornerRadius);
        this.bgDrawableDisabled = c2864a3;
        c2864a3.m3307a(getWidth(), getHeight());
        StateListDrawable stateListDrawable = new StateListDrawable();
        stateListDrawable.addState(new int[]{R.attr.state_enabled, -16842919}, this.bgDrawableNormal);
        stateListDrawable.addState(new int[]{R.attr.state_enabled, R.attr.state_pressed}, this.bgDrawablePressed);
        stateListDrawable.addState(new int[]{-16842910}, this.bgDrawableDisabled);
        setBackground(stateListDrawable);
        obtainStyledAttributes.recycle();
    }
}
