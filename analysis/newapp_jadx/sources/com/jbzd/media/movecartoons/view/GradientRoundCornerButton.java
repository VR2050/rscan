package com.jbzd.media.movecartoons.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Outline;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewOutlineProvider;
import androidx.appcompat.widget.AppCompatButton;
import com.jbzd.media.movecartoons.R$styleable;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B'\b\u0007\u0012\u0006\u0010\u0010\u001a\u00020\u000f\u0012\n\b\u0002\u0010\u0012\u001a\u0004\u0018\u00010\u0011\u0012\b\b\u0002\u0010\u0013\u001a\u00020\t¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0003\u001a\u00020\u0002H\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0004R\u0016\u0010\u0007\u001a\u00020\u00068\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0007\u0010\bR\u0018\u0010\n\u001a\u0004\u0018\u00010\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\n\u0010\u000bR\u0018\u0010\r\u001a\u0004\u0018\u00010\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\r\u0010\u000e¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "Landroidx/appcompat/widget/AppCompatButton;", "", "initView", "()V", "markRound", "", "cornerRadius", "F", "", "txtColor", "Ljava/lang/Integer;", "Landroid/graphics/drawable/Drawable;", "bg", "Landroid/graphics/drawable/Drawable;", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "defStyleAttr", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class GradientRoundCornerButton extends AppCompatButton {

    @Nullable
    private Drawable bg;
    private float cornerRadius;

    @Nullable
    private Integer txtColor;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public GradientRoundCornerButton(@NotNull Context context) {
        this(context, null, 0, 6, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public GradientRoundCornerButton(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0, 4, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ GradientRoundCornerButton(Context context, AttributeSet attributeSet, int i2, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i3 & 2) != 0 ? null : attributeSet, (i3 & 4) != 0 ? 0 : i2);
    }

    @SuppressLint({"ResourceType"})
    private final void initView() {
        if (this.bg == null) {
            this.bg = getResources().getDrawable(R.drawable.btn_update_style);
        }
        setBackground(this.bg);
        setGravity(17);
        Integer num = this.txtColor;
        if (num == null || (num != null && num.intValue() == -1)) {
            setTextColor(getResources().getColorStateList(R.drawable.selector_btn_text));
            return;
        }
        Resources resources = getResources();
        Integer num2 = this.txtColor;
        setTextColor(resources.getColorStateList(num2 == null ? 0 : num2.intValue()));
    }

    private final void markRound() {
        setOutlineProvider(new ViewOutlineProvider() { // from class: com.jbzd.media.movecartoons.view.GradientRoundCornerButton$markRound$1
            @Override // android.view.ViewOutlineProvider
            public void getOutline(@NotNull View view, @NotNull Outline outline) {
                float f2;
                Intrinsics.checkNotNullParameter(view, "view");
                Intrinsics.checkNotNullParameter(outline, "outline");
                int width = view.getWidth();
                int height = view.getHeight();
                f2 = GradientRoundCornerButton.this.cornerRadius;
                outline.setRoundRect(0, 0, width, height, f2);
            }
        });
        setClipToOutline(true);
    }

    public void _$_clearFindViewByIdCache() {
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public GradientRoundCornerButton(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        if (attributeSet != null) {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.GradientRoundCornerButton, i2, 0);
            Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttributes(\n                attrs,\n                R.styleable.GradientRoundCornerButton,\n                defStyleAttr,\n                0\n            )");
            this.cornerRadius = obtainStyledAttributes.getDimension(1, 0.0f);
            this.bg = obtainStyledAttributes.getDrawable(0);
            this.txtColor = Integer.valueOf(obtainStyledAttributes.getResourceId(2, -1));
            obtainStyledAttributes.recycle();
        }
        initView();
        if (this.cornerRadius > 0.0f) {
            markRound();
        }
    }
}
