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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u0004\u0018\u00002\u00020\u0001B'\b\u0007\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\n\b\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u0004\u0012\b\b\u0002\u0010%\u001a\u00020$¢\u0006\u0004\b&\u0010'J!\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u000b\u0010\fR\u0016\u0010\u000e\u001a\u00020\r8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000e\u0010\u000fR\u0018\u0010\u0011\u001a\u0004\u0018\u00010\u00108\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0011\u0010\u0012R\u0018\u0010\u0014\u001a\u0004\u0018\u00010\u00138\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0014\u0010\u0015R\u0018\u0010\u0017\u001a\u0004\u0018\u00010\u00168\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0017\u0010\u0018R\u0018\u0010\u0019\u001a\u0004\u0018\u00010\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0019\u0010\u001aR\u0016\u0010\u001b\u001a\u00020\r8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001b\u0010\u000fR\u0018\u0010\u001d\u001a\u0004\u0018\u00010\u001c8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001d\u0010\u001eR\u0018\u0010\u001f\u001a\u0004\u0018\u00010\u00108\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001f\u0010\u0012R\u0018\u0010 \u001a\u0004\u0018\u00010\u00138\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b \u0010\u0015R\u0018\u0010!\u001a\u0004\u0018\u00010\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b!\u0010\u001aR\u0018\u0010\"\u001a\u0004\u0018\u00010\u00168\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\"\u0010\u0018R\u0018\u0010#\u001a\u0004\u0018\u00010\u001c8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b#\u0010\u001e¨\u0006("}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/LSettingsItem;", "Landroid/widget/LinearLayout;", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "", "getCustomStyle", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "", "info", "setRight", "(Ljava/lang/String;)V", "", "showArrow", "Z", "Landroid/widget/TextView;", "tvTitle", "Landroid/widget/TextView;", "Landroid/graphics/drawable/Drawable;", "mLeftIcon", "Landroid/graphics/drawable/Drawable;", "Landroid/view/View;", "line", "Landroid/view/View;", "mLeftText", "Ljava/lang/String;", "showLine", "Landroid/widget/ImageView;", "ico", "Landroid/widget/ImageView;", "tvRight", "mRightIcon", "rightText", "mView", "arrow", "", "defStyleAttr", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class LSettingsItem extends LinearLayout {

    @Nullable
    private ImageView arrow;

    @Nullable
    private ImageView ico;

    @Nullable
    private View line;

    @Nullable
    private Drawable mLeftIcon;

    @Nullable
    private String mLeftText;

    @Nullable
    private Drawable mRightIcon;

    @Nullable
    private View mView;

    @Nullable
    private String rightText;
    private boolean showArrow;
    private boolean showLine;

    @Nullable
    private TextView tvRight;

    @Nullable
    private TextView tvTitle;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public LSettingsItem(@NotNull Context context) {
        this(context, null, 0, 6, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public LSettingsItem(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0, 4, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ LSettingsItem(Context context, AttributeSet attributeSet, int i2, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i3 & 2) != 0 ? null : attributeSet, (i3 & 4) != 0 ? 0 : i2);
    }

    private final void getCustomStyle(Context context, AttributeSet attrs) {
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attrs, R$styleable.LSettingsItem);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttributes(attrs, R.styleable.LSettingsItem)");
        int indexCount = obtainStyledAttributes.getIndexCount();
        if (indexCount > 0) {
            int i2 = 0;
            while (true) {
                int i3 = i2 + 1;
                int index = obtainStyledAttributes.getIndex(i2);
                if (index == 0) {
                    this.showArrow = obtainStyledAttributes.getBoolean(index, true);
                    ImageView imageView = this.arrow;
                    Intrinsics.checkNotNull(imageView);
                    imageView.setVisibility(this.showArrow ? 0 : 8);
                } else if (index == 1) {
                    Drawable drawable = obtainStyledAttributes.getDrawable(index);
                    this.mRightIcon = drawable;
                    if (drawable != null) {
                        ImageView imageView2 = this.arrow;
                        Intrinsics.checkNotNull(imageView2);
                        imageView2.setBackground(this.mRightIcon);
                    }
                } else if (index == 2) {
                    Drawable drawable2 = obtainStyledAttributes.getDrawable(index);
                    this.mLeftIcon = drawable2;
                    if (drawable2 != null) {
                        ImageView imageView3 = this.ico;
                        Intrinsics.checkNotNull(imageView3);
                        imageView3.setVisibility(0);
                        ImageView imageView4 = this.ico;
                        Intrinsics.checkNotNull(imageView4);
                        imageView4.setBackground(this.mLeftIcon);
                    }
                } else if (index == 3) {
                    this.showLine = obtainStyledAttributes.getBoolean(index, false);
                    View view = this.line;
                    Intrinsics.checkNotNull(view);
                    view.setVisibility(this.showLine ? 0 : 8);
                } else if (index == 4) {
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
                } else if (index == 5) {
                    this.mLeftText = obtainStyledAttributes.getString(index);
                    TextView textView3 = this.tvTitle;
                    Intrinsics.checkNotNull(textView3);
                    textView3.setText(this.mLeftText);
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

    public final void setRight(@NotNull String info) {
        Intrinsics.checkNotNullParameter(info, "info");
        TextView textView = this.tvRight;
        Intrinsics.checkNotNull(textView);
        textView.setText(info);
        invalidate();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public LSettingsItem(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        this.showArrow = true;
        View inflate = View.inflate(context, R.layout.lsettings_item, this);
        this.mView = inflate;
        TextView textView = inflate == null ? null : (TextView) inflate.findViewById(R.id.tvTitle);
        Objects.requireNonNull(textView, "null cannot be cast to non-null type android.widget.TextView");
        this.tvTitle = textView;
        View view = this.mView;
        TextView textView2 = view == null ? null : (TextView) view.findViewById(R.id.tvRight);
        Objects.requireNonNull(textView2, "null cannot be cast to non-null type android.widget.TextView");
        this.tvRight = textView2;
        View view2 = this.mView;
        View findViewById = view2 == null ? null : view2.findViewById(R.id.line);
        Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
        this.line = findViewById;
        View view3 = this.mView;
        ImageView imageView = view3 == null ? null : (ImageView) view3.findViewById(R.id.arrow);
        Objects.requireNonNull(imageView, "null cannot be cast to non-null type android.widget.ImageView");
        this.arrow = imageView;
        View view4 = this.mView;
        ImageView imageView2 = view4 != null ? (ImageView) view4.findViewById(R.id.iv_icon) : null;
        Objects.requireNonNull(imageView2, "null cannot be cast to non-null type android.widget.ImageView");
        this.ico = imageView2;
        getCustomStyle(context, attributeSet);
    }
}
