package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.jbzd.media.movecartoons.R$styleable;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\u0018\u00002\u00020\u0001B'\b\u0007\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\n\b\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u0004\u0012\b\b\u0002\u0010\u001f\u001a\u00020\u001e¢\u0006\u0004\b \u0010!J!\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u000b\u0010\fJ\u0015\u0010\r\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\t¢\u0006\u0004\b\r\u0010\fR\u0018\u0010\u000e\u001a\u0004\u0018\u00010\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000e\u0010\u000fR\u0018\u0010\u0011\u001a\u0004\u0018\u00010\u00108\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0011\u0010\u0012R\u0018\u0010\u0014\u001a\u0004\u0018\u00010\u00138\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0014\u0010\u0015R\u0018\u0010\u0017\u001a\u0004\u0018\u00010\u00168\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0017\u0010\u0018R\u0018\u0010\u0019\u001a\u0004\u0018\u00010\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0019\u0010\u000fR\u0018\u0010\u001a\u001a\u0004\u0018\u00010\u00168\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001a\u0010\u0018R\u0018\u0010\u001c\u001a\u0004\u0018\u00010\u001b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001c\u0010\u001d¨\u0006\""}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/MineCell;", "Landroid/widget/LinearLayout;", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "", "getCustomStyle", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "", "info", "setRightText", "(Ljava/lang/String;)V", "setLeftText", "rightText", "Ljava/lang/String;", "Landroid/graphics/drawable/Drawable;", "mLeftIcon", "Landroid/graphics/drawable/Drawable;", "Landroid/view/View;", "mView", "Landroid/view/View;", "Landroid/widget/TextView;", "tvRight", "Landroid/widget/TextView;", "mLeftText", "tvTitle", "Landroid/widget/ImageView;", "iv", "Landroid/widget/ImageView;", "", "defStyleAttr", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MineCell extends LinearLayout {

    @Nullable
    private ImageView iv;

    @Nullable
    private Drawable mLeftIcon;

    @Nullable
    private String mLeftText;

    @Nullable
    private View mView;

    @Nullable
    private String rightText;

    @Nullable
    private TextView tvRight;

    @Nullable
    private TextView tvTitle;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public MineCell(@NotNull Context context) {
        this(context, null, 0, 6, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public MineCell(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0, 4, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ MineCell(Context context, AttributeSet attributeSet, int i2, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i3 & 2) != 0 ? null : attributeSet, (i3 & 4) != 0 ? 0 : i2);
    }

    private final void getCustomStyle(Context context, AttributeSet attrs) {
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attrs, R$styleable.MineCell);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttributes(attrs, R.styleable.MineCell)");
        int indexCount = obtainStyledAttributes.getIndexCount();
        if (indexCount > 0) {
            int i2 = 0;
            while (true) {
                int i3 = i2 + 1;
                int index = obtainStyledAttributes.getIndex(i2);
                if (index != 0) {
                    if (index == 1) {
                        String string = obtainStyledAttributes.getString(index);
                        this.rightText = string;
                        Intrinsics.checkNotNull(string);
                        if (string.length() == 0) {
                            TextView textView = this.tvRight;
                            Intrinsics.checkNotNull(textView);
                            textView.setVisibility(8);
                        } else {
                            TextView textView2 = this.tvRight;
                            Intrinsics.checkNotNull(textView2);
                            textView2.setText(this.rightText);
                        }
                    } else if (index == 2) {
                        this.mLeftText = obtainStyledAttributes.getString(index);
                        TextView textView3 = this.tvTitle;
                        Intrinsics.checkNotNull(textView3);
                        textView3.setText(this.mLeftText);
                    }
                } else {
                    Drawable drawable = obtainStyledAttributes.getDrawable(index);
                    this.mLeftIcon = drawable;
                    if (drawable != null) {
                        ImageView imageView = this.iv;
                        Intrinsics.checkNotNull(imageView);
                        imageView.setImageDrawable(this.mLeftIcon);
                        ImageView imageView2 = this.iv;
                        Intrinsics.checkNotNull(imageView2);
                        imageView2.setVisibility(0);
                    }
                }
                if (i3 >= indexCount) {
                    break;
                } else {
                    i2 = i3;
                }
            }
        }
        obtainStyledAttributes.recycle();
    }

    public void _$_clearFindViewByIdCache() {
    }

    public final void setLeftText(@NotNull String info) {
        Intrinsics.checkNotNullParameter(info, "info");
        TextView textView = this.tvTitle;
        Intrinsics.checkNotNull(textView);
        textView.setText(info);
        invalidate();
    }

    public final void setRightText(@NotNull String info) {
        Intrinsics.checkNotNullParameter(info, "info");
        TextView textView = this.tvRight;
        Intrinsics.checkNotNull(textView);
        textView.setText(info);
        invalidate();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public MineCell(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        View inflate = View.inflate(context, R.layout.mine_cell, this);
        this.mView = inflate;
        ImageView imageView = inflate == null ? null : (ImageView) inflate.findViewById(R.id.iv_left);
        Objects.requireNonNull(imageView, "null cannot be cast to non-null type android.widget.ImageView");
        this.iv = imageView;
        View view = this.mView;
        TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_title);
        Objects.requireNonNull(textView, "null cannot be cast to non-null type android.widget.TextView");
        this.tvTitle = textView;
        View view2 = this.mView;
        TextView textView2 = view2 != null ? (TextView) view2.findViewById(R.id.tv_right) : null;
        Objects.requireNonNull(textView2, "null cannot be cast to non-null type android.widget.TextView");
        this.tvRight = textView2;
        getCustomStyle(context, attributeSet);
    }
}
