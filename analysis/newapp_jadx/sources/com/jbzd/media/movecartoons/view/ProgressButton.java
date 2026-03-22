package com.jbzd.media.movecartoons.view;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;
import com.jbzd.media.movecartoons.R$styleable;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u0007\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0006\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u00002\u00020\u0001B'\b\u0007\u0012\u0006\u0010\b\u001a\u00020\u0007\u0012\n\b\u0002\u0010\n\u001a\u0004\u0018\u00010\t\u0012\b\b\u0002\u0010B\u001a\u000200¢\u0006\u0004\bC\u0010DJ\u0019\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J!\u0010\u000b\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\u00072\b\u0010\n\u001a\u0004\u0018\u00010\tH\u0003¢\u0006\u0004\b\u000b\u0010\fJ\u0015\u0010\u000f\u001a\u00020\u00042\u0006\u0010\u000e\u001a\u00020\r¢\u0006\u0004\b\u000f\u0010\u0010J\u0015\u0010\u0011\u001a\u00020\u00042\u0006\u0010\u000e\u001a\u00020\r¢\u0006\u0004\b\u0011\u0010\u0010J\r\u0010\u0012\u001a\u00020\r¢\u0006\u0004\b\u0012\u0010\u0013J\u0019\u0010\u0016\u001a\u00020\r2\b\u0010\u0015\u001a\u0004\u0018\u00010\u0014H\u0016¢\u0006\u0004\b\u0016\u0010\u0017J\u0015\u0010\u0019\u001a\u00020\u00042\u0006\u0010\u000e\u001a\u00020\u0018¢\u0006\u0004\b\u0019\u0010\u001aR\u001d\u0010 \u001a\u00020\u001b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u001d\u001a\u0004\b\u001e\u0010\u001fR\u0018\u0010\"\u001a\u0004\u0018\u00010!8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\"\u0010#R\u001d\u0010'\u001a\u00020\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u001d\u001a\u0004\b%\u0010&R\u0016\u0010)\u001a\u00020(8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b)\u0010*R%\u0010/\u001a\n +*\u0004\u0018\u00010\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u001d\u001a\u0004\b-\u0010.R\u0016\u00101\u001a\u0002008\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b1\u00102R\u0016\u00104\u001a\u0002038\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b4\u00105R\u0016\u00106\u001a\u00020\u00188\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b6\u00107R\u001d\u0010<\u001a\u0002088B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b9\u0010\u001d\u001a\u0004\b:\u0010;R\u0016\u0010=\u001a\u00020\r8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b=\u0010>R\u0018\u0010@\u001a\u0004\u0018\u00010?8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b@\u0010A¨\u0006E"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/ProgressButton;", "Landroid/widget/FrameLayout;", "Landroid/view/View;", "view", "", "addViewToFrame", "(Landroid/view/View;)V", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "getCustomStyle", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "", "value", "setEnable", "(Z)V", "setProgress", "getProgress", "()Z", "Landroid/view/MotionEvent;", NotificationCompat.CATEGORY_EVENT, "onTouchEvent", "(Landroid/view/MotionEvent;)Z", "", "setText", "(Ljava/lang/String;)V", "Lcom/jbzd/media/movecartoons/view/JuhuaView;", "juhuaView$delegate", "Lkotlin/Lazy;", "getJuhuaView", "()Lcom/jbzd/media/movecartoons/view/JuhuaView;", "juhuaView", "Landroid/graphics/drawable/Drawable;", "bg", "Landroid/graphics/drawable/Drawable;", "fl$delegate", "getFl", "()Landroid/widget/FrameLayout;", "fl", "", "textSize", "F", "kotlin.jvm.PlatformType", "mRoot$delegate", "getMRoot", "()Landroid/view/View;", "mRoot", "", "style", "I", "", "round", "D", "str", "Ljava/lang/String;", "Landroid/widget/TextView;", "text$delegate", "getText", "()Landroid/widget/TextView;", "text", "isSubmit", "Z", "Landroid/content/res/ColorStateList;", "color", "Landroid/content/res/ColorStateList;", "defStyleAttr", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ProgressButton extends FrameLayout {

    @Nullable
    private Drawable bg;

    @Nullable
    private ColorStateList color;

    /* renamed from: fl$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fl;
    private boolean isSubmit;

    /* renamed from: juhuaView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy juhuaView;

    /* renamed from: mRoot$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mRoot;
    private double round;

    @NotNull
    private String str;
    private int style;

    /* renamed from: text$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy text;
    private float textSize;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public ProgressButton(@NotNull Context context) {
        this(context, null, 0, 6, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public ProgressButton(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0, 4, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public /* synthetic */ ProgressButton(Context context, AttributeSet attributeSet, int i2, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, (i3 & 2) != 0 ? null : attributeSet, (i3 & 4) != 0 ? 0 : i2);
    }

    private final void addViewToFrame(View view) {
        if (view != null && getFl().indexOfChild(view) <= -1) {
            int min = Math.min(getText().getWidth(), getText().getHeight());
            getFl().addView(view, new FrameLayout.LayoutParams(min, min, 17));
            getJuhuaView().setAnimationSpeed(1.0f);
        }
    }

    @SuppressLint({"ResourceAsColor"})
    private final void getCustomStyle(Context context, AttributeSet attrs) {
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attrs, R$styleable.ProgressButton);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttributes(attrs, R.styleable.ProgressButton)");
        int indexCount = obtainStyledAttributes.getIndexCount();
        if (indexCount > 0) {
            int i2 = 0;
            while (true) {
                int i3 = i2 + 1;
                int index = obtainStyledAttributes.getIndex(i2);
                switch (index) {
                    case 0:
                        this.bg = obtainStyledAttributes.getDrawable(index);
                        break;
                    case 1:
                        boolean z = obtainStyledAttributes.getBoolean(index, true);
                        getFl().setEnabled(z);
                        getText().setEnabled(z);
                        break;
                    case 2:
                        String string = obtainStyledAttributes.getString(index);
                        if (string == null) {
                            string = "";
                        }
                        this.str = string;
                        getText().setText(this.str);
                        break;
                    case 3:
                        this.color = obtainStyledAttributes.getColorStateList(index);
                        break;
                    case 4:
                        this.textSize = obtainStyledAttributes.getFloat(index, 15.0f);
                        getText().setTextSize(this.textSize);
                        break;
                    case 5:
                        int i4 = obtainStyledAttributes.getInt(index, 0);
                        this.style = i4;
                        getText().setTypeface(Typeface.defaultFromStyle(i4 == 0 ? 0 : 1));
                        break;
                    case 6:
                        this.round = obtainStyledAttributes.getDimension(index, C2354n.m2437V(context, 15.0d));
                        FrameLayout view = getFl();
                        double d2 = this.round / 2;
                        Intrinsics.checkNotNullParameter(view, "view");
                        view.setOutlineProvider(new C0859m0(d2));
                        view.setClipToOutline(true);
                        break;
                }
                if (this.bg == null) {
                    this.bg = getResources().getDrawable(R.drawable.gradient_button_selector_red);
                }
                if (this.color == null) {
                    this.color = ContextCompat.getColorStateList(context, R.color.progress_btn_text_color);
                }
                if (i3 < indexCount) {
                    i2 = i3;
                }
            }
        }
        getFl().setBackground(this.bg);
        getFl().setPadding(getPaddingLeft(), getPaddingTop(), getPaddingRight(), getPaddingBottom());
        getText().setTextColor(this.color);
    }

    private final FrameLayout getFl() {
        return (FrameLayout) this.fl.getValue();
    }

    private final JuhuaView getJuhuaView() {
        return (JuhuaView) this.juhuaView.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getMRoot() {
        return (View) this.mRoot.getValue();
    }

    private final TextView getText() {
        return (TextView) this.text.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    /* renamed from: getProgress, reason: from getter */
    public final boolean getIsSubmit() {
        return this.isSubmit;
    }

    @Override // android.view.View
    public boolean onTouchEvent(@Nullable MotionEvent event) {
        if (!getFl().isEnabled() || this.isSubmit) {
            return false;
        }
        return super.onTouchEvent(event);
    }

    public final void setEnable(boolean value) {
        getFl().setEnabled(value);
        getText().setEnabled(value);
    }

    public final void setProgress(boolean value) {
        this.isSubmit = value;
        if (value) {
            addViewToFrame(getJuhuaView());
            getJuhuaView().setVisibility(0);
        } else {
            getJuhuaView().setVisibility(8);
        }
        getText().setVisibility(this.isSubmit ? 4 : 0);
    }

    public final void setText(@NotNull String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.str = value;
        getText().setText(value);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public ProgressButton(@NotNull final Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        this.mRoot = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.view.ProgressButton$mRoot$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return View.inflate(context, R.layout.progress_button, this);
            }
        });
        this.text = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.view.ProgressButton$text$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View mRoot;
                mRoot = ProgressButton.this.getMRoot();
                View findViewById = mRoot.findViewById(R.id.text);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.fl = LazyKt__LazyJVMKt.lazy(new Function0<FrameLayout>() { // from class: com.jbzd.media.movecartoons.view.ProgressButton$fl$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final FrameLayout invoke() {
                View mRoot;
                mRoot = ProgressButton.this.getMRoot();
                View findViewById = mRoot.findViewById(R.id.root);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.FrameLayout");
                return (FrameLayout) findViewById;
            }
        });
        this.juhuaView = LazyKt__LazyJVMKt.lazy(new Function0<JuhuaView>() { // from class: com.jbzd.media.movecartoons.view.ProgressButton$juhuaView$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final JuhuaView invoke() {
                return new JuhuaView(context);
            }
        });
        this.str = "";
        getCustomStyle(context, attributeSet);
    }
}
