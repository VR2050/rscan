package com.qunidayede.supportlibrary.widget;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.StateListDrawable;
import android.util.AttributeSet;
import androidx.appcompat.widget.AppCompatButton;
import com.qunidayede.supportlibrary.R$styleable;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p310s.p311a.C2743m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000^\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0014\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0018\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\u0010\u0007\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B'\b\u0007\u0012\u0006\u0010O\u001a\u00020N\u0012\n\b\u0002\u0010Q\u001a\u0004\u0018\u00010P\u0012\b\b\u0002\u0010R\u001a\u00020\b¢\u0006\u0004\bS\u0010TJ\u0011\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u001f\u0010\f\u001a\u00020\u000b2\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\bH\u0014¢\u0006\u0004\b\f\u0010\rJ7\u0010\u0014\u001a\u00020\u000b2\u0006\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u0010\u001a\u00020\b2\u0006\u0010\u0011\u001a\u00020\b2\u0006\u0010\u0012\u001a\u00020\b2\u0006\u0010\u0013\u001a\u00020\bH\u0014¢\u0006\u0004\b\u0014\u0010\u0015J\u0017\u0010\u0018\u001a\u00020\u000b2\u0006\u0010\u0017\u001a\u00020\u0016H\u0014¢\u0006\u0004\b\u0018\u0010\u0019J\u001f\u0010\u001c\u001a\u00020\u000e2\u0006\u0010\u001a\u001a\u00020\b2\u0006\u0010\u001b\u001a\u00020\bH\u0002¢\u0006\u0004\b\u001c\u0010\u001dR\u0016\u0010 \u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001e\u0010\u001fR\u0016\u0010\"\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b!\u0010\u001fR\u0016\u0010$\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b#\u0010\u001fR\u0016\u0010&\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b%\u0010\u001fR\u0016\u0010(\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b'\u0010\u001fR\u0016\u0010*\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b)\u0010\u001fR\u0016\u0010,\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b+\u0010\u001fR\u0016\u0010.\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b-\u0010\u001fR\u001d\u00104\u001a\u00020/8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b0\u00101\u001a\u0004\b2\u00103R\u001d\u00109\u001a\u0002058B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b6\u00101\u001a\u0004\b7\u00108R\u0016\u0010<\u001a\u00020\u000e8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b:\u0010;R\u0016\u0010>\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b=\u0010\u001fR\u0016\u0010@\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b?\u0010\u001fR\u0016\u0010B\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bA\u0010\u001fR\u0016\u0010D\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bC\u0010\u001fR\u001d\u0010G\u001a\u00020/8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bE\u00101\u001a\u0004\bF\u00103R\u0016\u0010K\u001a\u00020H8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bI\u0010JR\u0016\u0010M\u001a\u00020H8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bL\u0010J¨\u0006U"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/widget/CommonShapeButton;", "Landroidx/appcompat/widget/AppCompatButton;", "Landroid/app/Activity;", "getActivity", "()Landroid/app/Activity;", "", "getCornerRadiusByPosition", "()[F", "", "widthMeasureSpec", "heightMeasureSpec", "", "onMeasure", "(II)V", "", "changed", "left", "top", "right", "bottom", "onLayout", "(ZIIII)V", "Landroid/graphics/Canvas;", "canvas", "onDraw", "(Landroid/graphics/Canvas;)V", "flagSet", "flag", "a", "(II)Z", "j", "I", "mCornerRadius", C2743m.f7506a, "mStartColor", "n", "mEndColor", "i", "mStrokeWidth", "g", "mPressedColor", "k", "mCornerPosition", "o", "mOrientation", "h", "mStrokeColor", "Landroid/graphics/drawable/GradientDrawable;", "q", "Lkotlin/Lazy;", "getNormalGradientDrawable", "()Landroid/graphics/drawable/GradientDrawable;", "normalGradientDrawable", "Landroid/graphics/drawable/StateListDrawable;", "s", "getStateListDrawable", "()Landroid/graphics/drawable/StateListDrawable;", "stateListDrawable", "l", "Z", "mActiveEnable", C1568e.f1949a, "mFillColor", "f", "mTextColor", "c", "mShapeMode", "p", "mDrawablePosition", "r", "getPressedGradientDrawable", "pressedGradientDrawable", "", "t", "F", "contentWidth", "u", "contentHeight", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "defStyleAttr", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;I)V", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CommonShapeButton extends AppCompatButton {

    /* renamed from: c, reason: from kotlin metadata */
    public int mShapeMode;

    /* renamed from: e, reason: from kotlin metadata */
    public int mFillColor;

    /* renamed from: f, reason: from kotlin metadata */
    public int mTextColor;

    /* renamed from: g, reason: from kotlin metadata */
    public int mPressedColor;

    /* renamed from: h, reason: from kotlin metadata */
    public int mStrokeColor;

    /* renamed from: i, reason: from kotlin metadata */
    public int mStrokeWidth;

    /* renamed from: j, reason: from kotlin metadata */
    public int mCornerRadius;

    /* renamed from: k, reason: from kotlin metadata */
    public int mCornerPosition;

    /* renamed from: l, reason: from kotlin metadata */
    public boolean mActiveEnable;

    /* renamed from: m, reason: from kotlin metadata */
    public int mStartColor;

    /* renamed from: n, reason: from kotlin metadata */
    public int mEndColor;

    /* renamed from: o, reason: from kotlin metadata */
    public int mOrientation;

    /* renamed from: p, reason: from kotlin metadata */
    public int mDrawablePosition;

    /* renamed from: q, reason: from kotlin metadata */
    @NotNull
    public final Lazy normalGradientDrawable;

    /* renamed from: r, reason: from kotlin metadata */
    @NotNull
    public final Lazy pressedGradientDrawable;

    /* renamed from: s, reason: from kotlin metadata */
    @NotNull
    public final Lazy stateListDrawable;

    /* renamed from: t, reason: from kotlin metadata */
    public float contentWidth;

    /* renamed from: u, reason: from kotlin metadata */
    public float contentHeight;

    /* renamed from: com.qunidayede.supportlibrary.widget.CommonShapeButton$a */
    public static final class C4055a extends Lambda implements Function0<GradientDrawable> {

        /* renamed from: c */
        public static final C4055a f10362c = new C4055a(0);

        /* renamed from: e */
        public static final C4055a f10363e = new C4055a(1);

        /* renamed from: f */
        public final /* synthetic */ int f10364f;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4055a(int i2) {
            super(0);
            this.f10364f = i2;
        }

        @Override // kotlin.jvm.functions.Function0
        public final GradientDrawable invoke() {
            int i2 = this.f10364f;
            if (i2 == 0) {
                return new GradientDrawable();
            }
            if (i2 == 1) {
                return new GradientDrawable();
            }
            throw null;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.widget.CommonShapeButton$b */
    public static final class C4056b extends Lambda implements Function0<StateListDrawable> {

        /* renamed from: c */
        public static final C4056b f10365c = new C4056b();

        public C4056b() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public StateListDrawable invoke() {
            return new StateListDrawable();
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public CommonShapeButton(@NotNull Context context) {
        this(context, null, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final Activity getActivity() {
        for (Context context = getContext(); context instanceof ContextWrapper; context = ((ContextWrapper) context).getBaseContext()) {
            if (context instanceof Activity) {
                return (Activity) context;
            }
        }
        return null;
    }

    private final float[] getCornerRadiusByPosition() {
        float[] fArr = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
        float f2 = this.mCornerRadius;
        if (m4578a(this.mCornerPosition, 1)) {
            fArr[0] = f2;
            fArr[1] = f2;
        }
        if (m4578a(this.mCornerPosition, 2)) {
            fArr[2] = f2;
            fArr[3] = f2;
        }
        if (m4578a(this.mCornerPosition, 4)) {
            fArr[4] = f2;
            fArr[5] = f2;
        }
        if (m4578a(this.mCornerPosition, 8)) {
            fArr[6] = f2;
            fArr[7] = f2;
        }
        return fArr;
    }

    private final GradientDrawable getNormalGradientDrawable() {
        return (GradientDrawable) this.normalGradientDrawable.getValue();
    }

    private final GradientDrawable getPressedGradientDrawable() {
        return (GradientDrawable) this.pressedGradientDrawable.getValue();
    }

    private final StateListDrawable getStateListDrawable() {
        return (StateListDrawable) this.stateListDrawable.getValue();
    }

    /* renamed from: a */
    public final boolean m4578a(int flagSet, int flag) {
        return (flag | flagSet) == flagSet;
    }

    @Override // android.widget.TextView, android.view.View
    public void onDraw(@NotNull Canvas canvas) {
        int i2;
        int i3;
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        if (this.contentWidth > 0.0f && ((i3 = this.mDrawablePosition) == 0 || i3 == 2)) {
            canvas.translate((getWidth() - this.contentWidth) / 2, 0.0f);
        } else if (this.contentHeight > 0.0f && ((i2 = this.mDrawablePosition) == 1 || i2 == 3)) {
            canvas.translate(0.0f, (getHeight() - this.contentHeight) / 2);
        }
        super.onDraw(canvas);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x002c, code lost:
    
        if (r8 != 3) goto L20;
     */
    @Override // androidx.appcompat.widget.AppCompatButton, android.widget.TextView, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onLayout(boolean r5, int r6, int r7, int r8, int r9) {
        /*
            r4 = this;
            super.onLayout(r5, r6, r7, r8, r9)
            int r5 = r4.mDrawablePosition
            r6 = 1
            r7 = -1
            if (r5 <= r7) goto L94
            android.graphics.drawable.Drawable[] r5 = r4.getCompoundDrawables()
            if (r5 != 0) goto L11
            goto L94
        L11:
            android.graphics.drawable.Drawable[] r5 = r4.getCompoundDrawables()
            int r7 = r4.mDrawablePosition
            r5 = r5[r7]
            if (r5 != 0) goto L1d
            goto L94
        L1d:
            int r7 = r4.getCompoundDrawablePadding()
            int r8 = r4.mDrawablePosition
            r9 = 0
            if (r8 == 0) goto L6e
            if (r8 == r6) goto L2f
            r0 = 2
            if (r8 == r0) goto L6e
            r0 = 3
            if (r8 == r0) goto L2f
            goto L94
        L2f:
            int r5 = r5.getIntrinsicHeight()
            android.text.TextPaint r8 = r4.getPaint()
            android.graphics.Paint$FontMetrics r8 = r8.getFontMetrics()
            float r0 = r8.descent
            double r0 = (double) r0
            float r8 = r8.ascent
            double r2 = (double) r8
            double r0 = r0 - r2
            double r0 = java.lang.Math.ceil(r0)
            float r8 = (float) r0
            int r0 = r4.getLineCount()
            int r0 = r0 - r6
            float r0 = (float) r0
            float r1 = r4.getLineSpacingExtra()
            float r1 = r1 * r0
            int r0 = r4.getLineCount()
            float r0 = (float) r0
            float r8 = r8 * r0
            float r8 = r8 + r1
            float r5 = (float) r5
            float r8 = r8 + r5
            float r5 = (float) r7
            float r8 = r8 + r5
            r4.contentHeight = r8
            int r5 = r4.getHeight()
            float r5 = (float) r5
            float r7 = r4.contentHeight
            float r5 = r5 - r7
            int r5 = (int) r5
            r4.setPadding(r9, r9, r9, r5)
            goto L94
        L6e:
            int r5 = r5.getIntrinsicWidth()
            android.text.TextPaint r8 = r4.getPaint()
            java.lang.CharSequence r0 = r4.getText()
            java.lang.String r0 = r0.toString()
            float r8 = r8.measureText(r0)
            float r5 = (float) r5
            float r8 = r8 + r5
            float r5 = (float) r7
            float r8 = r8 + r5
            r4.contentWidth = r8
            int r5 = r4.getWidth()
            float r5 = (float) r5
            float r7 = r4.contentWidth
            float r5 = r5 - r7
            int r5 = (int) r5
            r4.setPadding(r9, r9, r5, r9)
        L94:
            r5 = 17
            r4.setGravity(r5)
            boolean r5 = r4.mActiveEnable
            if (r5 == 0) goto La0
            r4.setClickable(r6)
        La0:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.qunidayede.supportlibrary.widget.CommonShapeButton.onLayout(boolean, int, int, int, int):void");
    }

    @Override // android.widget.TextView, android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int i2;
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
        GradientDrawable normalGradientDrawable = getNormalGradientDrawable();
        int i3 = this.mStartColor;
        if (i3 == -1 || (i2 = this.mEndColor) == -1) {
            normalGradientDrawable.setColor(this.mFillColor);
        } else {
            normalGradientDrawable.setColors(new int[]{i3, i2});
            int i4 = this.mOrientation;
            if (i4 == 0) {
                normalGradientDrawable.setOrientation(GradientDrawable.Orientation.TOP_BOTTOM);
            } else if (i4 == 1) {
                normalGradientDrawable.setOrientation(GradientDrawable.Orientation.LEFT_RIGHT);
            }
        }
        int i5 = this.mShapeMode;
        if (i5 == 0) {
            normalGradientDrawable.setShape(0);
        } else if (i5 == 1) {
            normalGradientDrawable.setShape(1);
        } else if (i5 == 2) {
            normalGradientDrawable.setShape(2);
        } else if (i5 == 3) {
            normalGradientDrawable.setShape(3);
        }
        if (this.mCornerPosition == -1) {
            normalGradientDrawable.setCornerRadius(this.mCornerRadius);
        } else {
            normalGradientDrawable.setCornerRadii(getCornerRadiusByPosition());
        }
        int i6 = this.mStrokeColor;
        if (i6 != 0) {
            normalGradientDrawable.setStroke(this.mStrokeWidth, i6);
        }
        setBackground(this.mActiveEnable ? new RippleDrawable(ColorStateList.valueOf(this.mPressedColor), getNormalGradientDrawable(), null) : getNormalGradientDrawable());
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public CommonShapeButton(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        this(context, attributeSet, 0);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    @JvmOverloads
    public CommonShapeButton(@NotNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        Intrinsics.checkNotNullParameter(context, "context");
        this.mDrawablePosition = -1;
        this.normalGradientDrawable = LazyKt__LazyJVMKt.lazy(C4055a.f10362c);
        this.pressedGradientDrawable = LazyKt__LazyJVMKt.lazy(C4055a.f10363e);
        this.stateListDrawable = LazyKt__LazyJVMKt.lazy(C4056b.f10365c);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.CommonShapeButton);
        this.mShapeMode = obtainStyledAttributes.getInt(R$styleable.CommonShapeButton_csb_shapeMode, 0);
        this.mFillColor = obtainStyledAttributes.getColor(R$styleable.CommonShapeButton_csb_fillColor, -1);
        this.mPressedColor = obtainStyledAttributes.getColor(R$styleable.CommonShapeButton_csb_pressedColor, -10066330);
        this.mStrokeColor = obtainStyledAttributes.getColor(R$styleable.CommonShapeButton_csb_strokeColor, 0);
        this.mStrokeWidth = obtainStyledAttributes.getDimensionPixelSize(R$styleable.CommonShapeButton_csb_strokeWidth, 0);
        this.mCornerRadius = obtainStyledAttributes.getDimensionPixelSize(R$styleable.CommonShapeButton_csb_cornerRadius, 0);
        this.mCornerPosition = obtainStyledAttributes.getInt(R$styleable.CommonShapeButton_csb_cornerPosition, -1);
        this.mActiveEnable = obtainStyledAttributes.getBoolean(R$styleable.CommonShapeButton_csb_activeEnable, true);
        this.mDrawablePosition = obtainStyledAttributes.getInt(R$styleable.CommonShapeButton_csb_drawablePosition, -1);
        this.mStartColor = obtainStyledAttributes.getColor(R$styleable.CommonShapeButton_csb_startColor, -20992);
        this.mEndColor = obtainStyledAttributes.getColor(R$styleable.CommonShapeButton_csb_endColor, -42752);
        this.mOrientation = obtainStyledAttributes.getColor(R$styleable.CommonShapeButton_csb_orientation, 1);
        this.mTextColor = obtainStyledAttributes.getColor(R$styleable.CommonShapeButton_csb_textColor, -1);
        obtainStyledAttributes.getDimensionPixelSize(R$styleable.CommonShapeButton_csb_textSize, 16);
        obtainStyledAttributes.recycle();
        setTextColor(this.mTextColor);
    }
}
