package com.view.text.view;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.util.AttributeSet;
import android.widget.LinearLayout;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.appcompat.widget.AppCompatTextView;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p081b0.p082a.p083a.C1325b;
import p005b.p081b0.p082a.p083a.EnumC1324a;
import p005b.p143g.p144a.p146l.C1568e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0000\u0018\u00002\u00020\u0001B'\b\u0007\u0012\u0006\u0010\u001d\u001a\u00020\u001c\u0012\n\b\u0002\u0010\u001f\u001a\u0004\u0018\u00010\u001e\u0012\b\b\u0002\u0010 \u001a\u00020\b¢\u0006\u0004\b!\u0010\"J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\u0007\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0007\u0010\u0006J\u0017\u0010\n\u001a\u00020\u00042\u0006\u0010\t\u001a\u00020\bH\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u0017\u0010\u000e\u001a\u00020\u00042\u0006\u0010\r\u001a\u00020\fH\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ\u0015\u0010\u0010\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0010\u0010\u0006R\u001d\u0010\u0016\u001a\u00020\u00118B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015R\u001d\u0010\u001b\u001a\u00020\u00178B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0013\u001a\u0004\b\u0019\u0010\u001a¨\u0006#"}, m5311d2 = {"Lcom/view/text/view/TagItemView;", "Landroid/widget/LinearLayout;", "Lb/b0/a/a/b;", "config", "", "setTextView", "(Lb/b0/a/a/b;)V", "setImage", "", "textMarginImage", "setMargin", "(I)V", "Lb/b0/a/a/a;", "orientation", "setOrientation", "(Lb/b0/a/a/a;)V", "setConfig", "Landroidx/appcompat/widget/AppCompatTextView;", C1568e.f1949a, "Lkotlin/Lazy;", "getTextView", "()Landroidx/appcompat/widget/AppCompatTextView;", "textView", "Landroidx/appcompat/widget/AppCompatImageView;", "c", "getImageView", "()Landroidx/appcompat/widget/AppCompatImageView;", "imageView", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "defStyleAttr", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "TagTextView_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TagItemView extends LinearLayout {

    /* renamed from: c, reason: from kotlin metadata */
    @NotNull
    public final Lazy imageView;

    /* renamed from: e, reason: from kotlin metadata */
    @NotNull
    public final Lazy textView;

    /* renamed from: com.view.text.view.TagItemView$a */
    public static final class C4156a extends Lambda implements Function0<AppCompatImageView> {

        /* renamed from: c */
        public final /* synthetic */ Context f10914c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4156a(Context context) {
            super(0);
            this.f10914c = context;
        }

        @Override // kotlin.jvm.functions.Function0
        public AppCompatImageView invoke() {
            return new AppCompatImageView(this.f10914c);
        }
    }

    /* renamed from: com.view.text.view.TagItemView$b */
    public static final class C4157b extends Lambda implements Function0<AppCompatTextView> {

        /* renamed from: c */
        public final /* synthetic */ Context f10915c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4157b(Context context) {
            super(0);
            this.f10915c = context;
        }

        @Override // kotlin.jvm.functions.Function0
        public AppCompatTextView invoke() {
            return new AppCompatTextView(this.f10915c);
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public TagItemView(@NotNull Context context) {
        this(context, null, 0, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public TagItemView(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ TagItemView(Context context, AttributeSet attributeSet, int i2, int i3) {
        this(context, (i3 & 2) != 0 ? null : attributeSet, (i3 & 4) != 0 ? 0 : i2);
    }

    private final AppCompatImageView getImageView() {
        return (AppCompatImageView) this.imageView.getValue();
    }

    private final AppCompatTextView getTextView() {
        return (AppCompatTextView) this.textView.getValue();
    }

    private final void setImage(C1325b config) {
        AppCompatImageView imageView = getImageView();
        Objects.requireNonNull(config);
        Drawable drawable = config.f1078E;
        if (drawable != null) {
            imageView.setImageDrawable(drawable);
        }
    }

    private final void setMargin(int textMarginImage) {
        setShowDividers(2);
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setSize(textMarginImage, textMarginImage);
        gradientDrawable.setColor(0);
        Unit unit = Unit.INSTANCE;
        setDividerDrawable(gradientDrawable);
    }

    private final void setOrientation(EnumC1324a orientation) {
        int ordinal = orientation.ordinal();
        if (ordinal == 0) {
            setOrientation(0);
            addView(getImageView());
            addView(getTextView(), -2, -2);
            return;
        }
        if (ordinal == 1) {
            setOrientation(1);
            addView(getImageView());
            addView(getTextView(), -2, -2);
        } else if (ordinal == 2) {
            setOrientation(0);
            addView(getTextView(), -2, -2);
            addView(getImageView());
        } else {
            if (ordinal != 3) {
                return;
            }
            setOrientation(1);
            addView(getTextView(), -2, -2);
            addView(getImageView());
        }
    }

    private final void setTextView(C1325b config) {
        AppCompatTextView textView = getTextView();
        textView.setText(config.f1077D);
        textView.setTextColor(config.f1085c);
        Float f2 = config.f1084b;
        textView.setTextSize(0, f2 == null ? textView.getTextSize() : f2.floatValue());
    }

    public final void setConfig(@NotNull C1325b config) {
        Intrinsics.checkNotNullParameter(config, "config");
        setOrientation(config.f1107y);
        Integer valueOf = Integer.valueOf(config.f1074A);
        Integer valueOf2 = Integer.valueOf(config.f1075B);
        getImageView().setLayoutParams(new LinearLayout.LayoutParams(valueOf == null ? (int) getTextView().getTextSize() : valueOf.intValue(), valueOf2 == null ? (int) getTextView().getTextSize() : valueOf2.intValue()));
        int ordinal = config.f1083a.ordinal();
        if (ordinal == 0) {
            getTextView().setVisibility(0);
            getImageView().setVisibility(8);
            setTextView(config);
        } else if (ordinal == 1) {
            getTextView().setVisibility(8);
            getImageView().setVisibility(0);
            setImage(config);
        } else {
            if (ordinal != 2) {
                throw new IllegalArgumentException(Intrinsics.stringPlus(TagItemView.class.getSimpleName(), "不支持此类型"));
            }
            getTextView().setVisibility(0);
            getImageView().setVisibility(0);
            setImage(config);
            setTextView(config);
            setMargin(config.f1082I);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public TagItemView(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        this.imageView = LazyKt__LazyJVMKt.lazy(new C4156a(context));
        this.textView = LazyKt__LazyJVMKt.lazy(new C4157b(context));
        setGravity(17);
    }
}
