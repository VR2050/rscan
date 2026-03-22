package com.mikhaellopez.circularprogressbar;

import android.animation.TimeInterpolator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.os.Handler;
import android.util.AttributeSet;
import android.view.View;
import androidx.core.view.ViewCompat;
import androidx.exifinterface.media.ExifInterface;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p310s.p311a.C2743m;
import p005b.p323u.p324a.C2813a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000|\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\u0011\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0014\n\u0002\u0018\u0002\n\u0002\b=\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u00002\u00020\u0001:\u0004¤\u0001¥\u0001B!\u0012\b\u0010\u009f\u0001\u001a\u00030\u009e\u0001\u0012\f\b\u0002\u0010¡\u0001\u001a\u0005\u0018\u00010 \u0001¢\u0006\u0006\b¢\u0001\u0010£\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0004J'\u0010\f\u001a\u00020\u000b2\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\tH\u0002¢\u0006\u0004\b\f\u0010\rJ\u0013\u0010\u0010\u001a\u00020\u000f*\u00020\u000eH\u0002¢\u0006\u0004\b\u0010\u0010\u0011J\u0013\u0010\u0012\u001a\u00020\t*\u00020\u0006H\u0002¢\u0006\u0004\b\u0012\u0010\u0013J\u000f\u0010\u0014\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0014\u0010\u0004J/\u0010\u0019\u001a\u00020\u00022\u0006\u0010\u0015\u001a\u00020\u00062\u0006\u0010\u0016\u001a\u00020\u00062\u0006\u0010\u0017\u001a\u00020\u00062\u0006\u0010\u0018\u001a\u00020\u0006H\u0014¢\u0006\u0004\b\u0019\u0010\u001aJ\u0017\u0010\u001d\u001a\u00020\u00022\u0006\u0010\u001c\u001a\u00020\u001bH\u0014¢\u0006\u0004\b\u001d\u0010\u001eJ\u0017\u0010 \u001a\u00020\u00022\u0006\u0010\u001f\u001a\u00020\u0006H\u0016¢\u0006\u0004\b \u0010!J\u001f\u0010$\u001a\u00020\u00022\u0006\u0010\"\u001a\u00020\u00062\u0006\u0010#\u001a\u00020\u0006H\u0014¢\u0006\u0004\b$\u0010%R*\u0010,\u001a\u00020\u00062\u0006\u0010&\u001a\u00020\u00068\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\b'\u0010(\u001a\u0004\b)\u0010*\"\u0004\b+\u0010!R0\u00105\u001a\u0010\u0012\u0004\u0012\u00020.\u0012\u0004\u0012\u00020\u0002\u0018\u00010-8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b/\u00100\u001a\u0004\b1\u00102\"\u0004\b3\u00104R\u0016\u00108\u001a\u0002068\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0003\u00107R*\u0010<\u001a\u00020\u00062\u0006\u0010&\u001a\u00020\u00068\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\b9\u0010(\u001a\u0004\b:\u0010*\"\u0004\b;\u0010!R\u0016\u0010@\u001a\u00020=8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b>\u0010?R*\u0010G\u001a\u00020\u000f2\u0006\u0010&\u001a\u00020\u000f8\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\bA\u0010B\u001a\u0004\bC\u0010D\"\u0004\bE\u0010FR\u0018\u0010J\u001a\u0004\u0018\u00010H8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0010\u0010IR\u0016\u0010M\u001a\u00020K8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0005\u0010LR*\u0010T\u001a\u00020\t2\u0006\u0010&\u001a\u00020\t8\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\bN\u0010O\u001a\u0004\bP\u0010Q\"\u0004\bR\u0010SR.\u0010[\u001a\u0004\u0018\u00010\u00062\b\u0010&\u001a\u0004\u0018\u00010\u00068\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\bU\u0010V\u001a\u0004\bW\u0010X\"\u0004\bY\u0010ZR0\u0010_\u001a\u0010\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\u0002\u0018\u00010-8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\\\u00100\u001a\u0004\b]\u00102\"\u0004\b^\u00104R\u0018\u0010c\u001a\u0004\u0018\u00010`8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\ba\u0010bR*\u0010j\u001a\u00020.2\u0006\u0010&\u001a\u00020.8\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\bd\u0010e\u001a\u0004\bf\u0010g\"\u0004\bh\u0010iR*\u0010m\u001a\u00020.2\u0006\u0010&\u001a\u00020.8\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\b\u0012\u0010e\u001a\u0004\bk\u0010g\"\u0004\bl\u0010iR*\u0010q\u001a\u00020\u000f2\u0006\u0010&\u001a\u00020\u000f8\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\bn\u0010B\u001a\u0004\bo\u0010D\"\u0004\bp\u0010FR$\u0010t\u001a\u00020.2\u0006\u0010&\u001a\u00020.8\u0002@BX\u0082\u000e¢\u0006\f\n\u0004\br\u0010e\"\u0004\bs\u0010iR*\u0010x\u001a\u00020.2\u0006\u0010&\u001a\u00020.8\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\bu\u0010e\u001a\u0004\bv\u0010g\"\u0004\bw\u0010iR*\u0010|\u001a\u00020.2\u0006\u0010&\u001a\u00020.8\u0006@FX\u0086\u000e¢\u0006\u0012\n\u0004\by\u0010e\u001a\u0004\bz\u0010g\"\u0004\b{\u0010iR\u0016\u0010}\u001a\u0002068\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0016\u00107R0\u0010\u0081\u0001\u001a\u0004\u0018\u00010\u00062\b\u0010&\u001a\u0004\u0018\u00010\u00068\u0006@FX\u0086\u000e¢\u0006\u0013\n\u0004\b~\u0010V\u001a\u0004\b\u007f\u0010X\"\u0005\b\u0080\u0001\u0010ZR.\u0010\u0085\u0001\u001a\u00020\t2\u0006\u0010&\u001a\u00020\t8\u0006@FX\u0086\u000e¢\u0006\u0015\n\u0005\b\u0082\u0001\u0010O\u001a\u0005\b\u0083\u0001\u0010Q\"\u0005\b\u0084\u0001\u0010SR2\u0010\u0089\u0001\u001a\u0004\u0018\u00010\u00062\b\u0010&\u001a\u0004\u0018\u00010\u00068\u0006@FX\u0086\u000e¢\u0006\u0015\n\u0005\b\u0086\u0001\u0010V\u001a\u0005\b\u0087\u0001\u0010X\"\u0005\b\u0088\u0001\u0010ZR2\u0010\u008d\u0001\u001a\u0004\u0018\u00010\u00062\b\u0010&\u001a\u0004\u0018\u00010\u00068\u0006@FX\u0086\u000e¢\u0006\u0015\n\u0005\b\u008a\u0001\u0010V\u001a\u0005\b\u008b\u0001\u0010X\"\u0005\b\u008c\u0001\u0010ZR)\u0010\u0092\u0001\u001a\u00020\u000e2\u0006\u0010&\u001a\u00020\u000e8\u0002@BX\u0082\u000e¢\u0006\u0010\n\u0006\b\u008e\u0001\u0010\u008f\u0001\"\u0006\b\u0090\u0001\u0010\u0091\u0001R'\u0010\u0095\u0001\u001a\u00020.2\u0006\u0010&\u001a\u00020.8\u0002@BX\u0082\u000e¢\u0006\u000e\n\u0005\b\u0093\u0001\u0010e\"\u0005\b\u0094\u0001\u0010iR.\u0010\u0099\u0001\u001a\u00020.2\u0006\u0010&\u001a\u00020.8\u0006@FX\u0086\u000e¢\u0006\u0015\n\u0005\b\u0096\u0001\u0010e\u001a\u0005\b\u0097\u0001\u0010g\"\u0005\b\u0098\u0001\u0010iR0\u0010\u009d\u0001\u001a\u00020\u000e2\u0006\u0010&\u001a\u00020\u000e8\u0006@FX\u0086\u000e¢\u0006\u0017\n\u0005\b\u0015\u0010\u008f\u0001\u001a\u0006\b\u009a\u0001\u0010\u009b\u0001\"\u0006\b\u009c\u0001\u0010\u0091\u0001¨\u0006¦\u0001"}, m5311d2 = {"Lcom/mikhaellopez/circularprogressbar/CircularProgressBar;", "Landroid/view/View;", "", "g", "()V", "f", "", "startColor", "endColor", "Lcom/mikhaellopez/circularprogressbar/CircularProgressBar$a;", "gradientDirection", "Landroid/graphics/LinearGradient;", "d", "(IILcom/mikhaellopez/circularprogressbar/CircularProgressBar$a;)Landroid/graphics/LinearGradient;", "Lcom/mikhaellopez/circularprogressbar/CircularProgressBar$b;", "", C1568e.f1949a, "(Lcom/mikhaellopez/circularprogressbar/CircularProgressBar$b;)Z", "i", "(I)Lcom/mikhaellopez/circularprogressbar/CircularProgressBar$a;", "onDetachedFromWindow", "w", "h", "oldw", "oldh", "onSizeChanged", "(IIII)V", "Landroid/graphics/Canvas;", "canvas", "onDraw", "(Landroid/graphics/Canvas;)V", "backgroundColor", "setBackgroundColor", "(I)V", "widthMeasureSpec", "heightMeasureSpec", "onMeasure", "(II)V", "value", C2743m.f7506a, "I", "getProgressBarColor", "()I", "setProgressBarColor", "progressBarColor", "Lkotlin/Function1;", "", "y", "Lkotlin/jvm/functions/Function1;", "getOnProgressChangeListener", "()Lkotlin/jvm/functions/Function1;", "setOnProgressChangeListener", "(Lkotlin/jvm/functions/Function1;)V", "onProgressChangeListener", "Landroid/graphics/Paint;", "Landroid/graphics/Paint;", "backgroundPaint", "q", "getBackgroundProgressBarColor", "setBackgroundProgressBarColor", "backgroundProgressBarColor", "Ljava/lang/Runnable;", "D", "Ljava/lang/Runnable;", "indeterminateModeRunnable", "x", "Z", "getIndeterminateMode", "()Z", "setIndeterminateMode", "(Z)V", "indeterminateMode", "Landroid/os/Handler;", "Landroid/os/Handler;", "indeterminateModeHandler", "Landroid/graphics/RectF;", "Landroid/graphics/RectF;", "rectF", "p", "Lcom/mikhaellopez/circularprogressbar/CircularProgressBar$a;", "getProgressBarColorDirection", "()Lcom/mikhaellopez/circularprogressbar/CircularProgressBar$a;", "setProgressBarColorDirection", "(Lcom/mikhaellopez/circularprogressbar/CircularProgressBar$a;)V", "progressBarColorDirection", "n", "Ljava/lang/Integer;", "getProgressBarColorStart", "()Ljava/lang/Integer;", "setProgressBarColorStart", "(Ljava/lang/Integer;)V", "progressBarColorStart", "z", "getOnIndeterminateModeChangeListener", "setOnIndeterminateModeChangeListener", "onIndeterminateModeChangeListener", "Landroid/animation/ValueAnimator;", "c", "Landroid/animation/ValueAnimator;", "progressAnimator", "j", "F", "getProgressMax", "()F", "setProgressMax", "(F)V", "progressMax", "getProgress", "setProgress", "progress", "u", "getRoundBorder", "setRoundBorder", "roundBorder", "C", "setStartAngleIndeterminateMode", "startAngleIndeterminateMode", "v", "getStartAngle", "setStartAngle", "startAngle", "k", "getProgressBarWidth", "setProgressBarWidth", "progressBarWidth", "foregroundPaint", "r", "getBackgroundProgressBarColorStart", "setBackgroundProgressBarColorStart", "backgroundProgressBarColorStart", "t", "getBackgroundProgressBarColorDirection", "setBackgroundProgressBarColorDirection", "backgroundProgressBarColorDirection", "o", "getProgressBarColorEnd", "setProgressBarColorEnd", "progressBarColorEnd", "s", "getBackgroundProgressBarColorEnd", "setBackgroundProgressBarColorEnd", "backgroundProgressBarColorEnd", "B", "Lcom/mikhaellopez/circularprogressbar/CircularProgressBar$b;", "setProgressDirectionIndeterminateMode", "(Lcom/mikhaellopez/circularprogressbar/CircularProgressBar$b;)V", "progressDirectionIndeterminateMode", ExifInterface.GPS_MEASUREMENT_IN_PROGRESS, "setProgressIndeterminateMode", "progressIndeterminateMode", "l", "getBackgroundProgressBarWidth", "setBackgroundProgressBarWidth", "backgroundProgressBarWidth", "getProgressDirection", "()Lcom/mikhaellopez/circularprogressbar/CircularProgressBar$b;", "setProgressDirection", "progressDirection", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "a", "b", "circularprogressbar_release"}, m5312k = 1, m5313mv = {1, 4, 0})
/* loaded from: classes2.dex */
public final class CircularProgressBar extends View {

    /* renamed from: A, reason: from kotlin metadata */
    public float progressIndeterminateMode;

    /* renamed from: B, reason: from kotlin metadata */
    public EnumC4024b progressDirectionIndeterminateMode;

    /* renamed from: C, reason: from kotlin metadata */
    public float startAngleIndeterminateMode;

    /* renamed from: D, reason: from kotlin metadata */
    public final Runnable indeterminateModeRunnable;

    /* renamed from: c, reason: from kotlin metadata */
    public ValueAnimator progressAnimator;

    /* renamed from: e, reason: from kotlin metadata */
    public Handler indeterminateModeHandler;

    /* renamed from: f, reason: from kotlin metadata */
    public RectF rectF;

    /* renamed from: g, reason: from kotlin metadata */
    public Paint backgroundPaint;

    /* renamed from: h, reason: from kotlin metadata */
    public Paint foregroundPaint;

    /* renamed from: i, reason: from kotlin metadata */
    public float progress;

    /* renamed from: j, reason: from kotlin metadata */
    public float progressMax;

    /* renamed from: k, reason: from kotlin metadata */
    public float progressBarWidth;

    /* renamed from: l, reason: from kotlin metadata */
    public float backgroundProgressBarWidth;

    /* renamed from: m, reason: from kotlin metadata */
    public int progressBarColor;

    /* renamed from: n, reason: from kotlin metadata */
    @Nullable
    public Integer progressBarColorStart;

    /* renamed from: o, reason: from kotlin metadata */
    @Nullable
    public Integer progressBarColorEnd;

    /* renamed from: p, reason: from kotlin metadata */
    @NotNull
    public EnumC4023a progressBarColorDirection;

    /* renamed from: q, reason: from kotlin metadata */
    public int backgroundProgressBarColor;

    /* renamed from: r, reason: from kotlin metadata */
    @Nullable
    public Integer backgroundProgressBarColorStart;

    /* renamed from: s, reason: from kotlin metadata */
    @Nullable
    public Integer backgroundProgressBarColorEnd;

    /* renamed from: t, reason: from kotlin metadata */
    @NotNull
    public EnumC4023a backgroundProgressBarColorDirection;

    /* renamed from: u, reason: from kotlin metadata */
    public boolean roundBorder;

    /* renamed from: v, reason: from kotlin metadata */
    public float startAngle;

    /* renamed from: w, reason: from kotlin metadata */
    @NotNull
    public EnumC4024b progressDirection;

    /* renamed from: x, reason: from kotlin metadata */
    public boolean indeterminateMode;

    /* renamed from: y, reason: from kotlin metadata */
    @Nullable
    public Function1<? super Float, Unit> onProgressChangeListener;

    /* renamed from: z, reason: from kotlin metadata */
    @Nullable
    public Function1<? super Boolean, Unit> onIndeterminateModeChangeListener;

    /* renamed from: com.mikhaellopez.circularprogressbar.CircularProgressBar$a */
    public enum EnumC4023a {
        LEFT_TO_RIGHT(1),
        RIGHT_TO_LEFT(2),
        TOP_TO_BOTTOM(3),
        BOTTOM_TO_END(4);


        /* renamed from: i */
        public final int f10247i;

        EnumC4023a(int i2) {
            this.f10247i = i2;
        }
    }

    /* renamed from: com.mikhaellopez.circularprogressbar.CircularProgressBar$b */
    public enum EnumC4024b {
        TO_RIGHT(1),
        TO_LEFT(2);


        /* renamed from: g */
        public final int f10251g;

        EnumC4024b(int i2) {
            this.f10251g = i2;
        }
    }

    /* renamed from: com.mikhaellopez.circularprogressbar.CircularProgressBar$c */
    public static final class RunnableC4025c implements Runnable {
        public RunnableC4025c() {
        }

        @Override // java.lang.Runnable
        public final void run() {
            if (CircularProgressBar.this.getIndeterminateMode()) {
                CircularProgressBar circularProgressBar = CircularProgressBar.this;
                Handler handler = circularProgressBar.indeterminateModeHandler;
                if (handler != null) {
                    handler.postDelayed(circularProgressBar.indeterminateModeRunnable, 1500L);
                }
                CircularProgressBar circularProgressBar2 = CircularProgressBar.this;
                circularProgressBar2.setProgressDirectionIndeterminateMode(circularProgressBar2.m4562e(circularProgressBar2.progressDirectionIndeterminateMode) ? EnumC4024b.TO_LEFT : EnumC4024b.TO_RIGHT);
                CircularProgressBar circularProgressBar3 = CircularProgressBar.this;
                if (circularProgressBar3.m4562e(circularProgressBar3.progressDirectionIndeterminateMode)) {
                    CircularProgressBar.m4560h(CircularProgressBar.this, 0.0f, 1500L, null, null, 12);
                } else {
                    CircularProgressBar circularProgressBar4 = CircularProgressBar.this;
                    CircularProgressBar.m4560h(circularProgressBar4, circularProgressBar4.getProgressMax(), 1500L, null, null, 12);
                }
            }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CircularProgressBar(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        Intrinsics.checkParameterIsNotNull(context, "context");
        this.rectF = new RectF();
        Paint paint = new Paint();
        paint.setAntiAlias(true);
        paint.setStyle(Paint.Style.STROKE);
        this.backgroundPaint = paint;
        Paint paint2 = new Paint();
        paint2.setAntiAlias(true);
        paint2.setStyle(Paint.Style.STROKE);
        this.foregroundPaint = paint2;
        this.progressMax = 100.0f;
        this.progressBarWidth = getResources().getDimension(R$dimen.default_stroke_width);
        this.backgroundProgressBarWidth = getResources().getDimension(R$dimen.default_background_stroke_width);
        this.progressBarColor = ViewCompat.MEASURED_STATE_MASK;
        EnumC4023a enumC4023a = EnumC4023a.LEFT_TO_RIGHT;
        this.progressBarColorDirection = enumC4023a;
        this.backgroundProgressBarColor = -7829368;
        this.backgroundProgressBarColorDirection = enumC4023a;
        this.startAngle = 270.0f;
        EnumC4024b enumC4024b = EnumC4024b.TO_RIGHT;
        this.progressDirection = enumC4024b;
        this.progressDirectionIndeterminateMode = enumC4024b;
        this.startAngleIndeterminateMode = 270.0f;
        this.indeterminateModeRunnable = new RunnableC4025c();
        TypedArray obtainStyledAttributes = context.getTheme().obtainStyledAttributes(attributeSet, R$styleable.CircularProgressBar, 0, 0);
        Intrinsics.checkExpressionValueIsNotNull(obtainStyledAttributes, "context.theme.obtainStyl…ircularProgressBar, 0, 0)");
        setProgress(obtainStyledAttributes.getFloat(R$styleable.CircularProgressBar_cpb_progress, this.progress));
        setProgressMax(obtainStyledAttributes.getFloat(R$styleable.CircularProgressBar_cpb_progress_max, this.progressMax));
        float dimension = obtainStyledAttributes.getDimension(R$styleable.CircularProgressBar_cpb_progressbar_width, this.progressBarWidth);
        Resources system = Resources.getSystem();
        Intrinsics.checkExpressionValueIsNotNull(system, "Resources.getSystem()");
        setProgressBarWidth(dimension / system.getDisplayMetrics().density);
        float dimension2 = obtainStyledAttributes.getDimension(R$styleable.CircularProgressBar_cpb_background_progressbar_width, this.backgroundProgressBarWidth);
        Resources system2 = Resources.getSystem();
        Intrinsics.checkExpressionValueIsNotNull(system2, "Resources.getSystem()");
        setBackgroundProgressBarWidth(dimension2 / system2.getDisplayMetrics().density);
        setProgressBarColor(obtainStyledAttributes.getInt(R$styleable.CircularProgressBar_cpb_progressbar_color, this.progressBarColor));
        int color = obtainStyledAttributes.getColor(R$styleable.CircularProgressBar_cpb_progressbar_color_start, 0);
        if (color != 0) {
            setProgressBarColorStart(Integer.valueOf(color));
        }
        int color2 = obtainStyledAttributes.getColor(R$styleable.CircularProgressBar_cpb_progressbar_color_end, 0);
        if (color2 != 0) {
            setProgressBarColorEnd(Integer.valueOf(color2));
        }
        setProgressBarColorDirection(m4565i(obtainStyledAttributes.getInteger(R$styleable.CircularProgressBar_cpb_progressbar_color_direction, this.progressBarColorDirection.f10247i)));
        setBackgroundProgressBarColor(obtainStyledAttributes.getInt(R$styleable.CircularProgressBar_cpb_background_progressbar_color, this.backgroundProgressBarColor));
        int color3 = obtainStyledAttributes.getColor(R$styleable.CircularProgressBar_cpb_background_progressbar_color_start, 0);
        if (color3 != 0) {
            setBackgroundProgressBarColorStart(Integer.valueOf(color3));
        }
        int color4 = obtainStyledAttributes.getColor(R$styleable.CircularProgressBar_cpb_background_progressbar_color_end, 0);
        if (color4 != 0) {
            setBackgroundProgressBarColorEnd(Integer.valueOf(color4));
        }
        setBackgroundProgressBarColorDirection(m4565i(obtainStyledAttributes.getInteger(R$styleable.CircularProgressBar_cpb_background_progressbar_color_direction, this.backgroundProgressBarColorDirection.f10247i)));
        int integer = obtainStyledAttributes.getInteger(R$styleable.CircularProgressBar_cpb_progress_direction, this.progressDirection.f10251g);
        if (integer != 1) {
            if (integer != 2) {
                throw new IllegalArgumentException(C1499a.m626l("This value is not supported for ProgressDirection: ", integer));
            }
            enumC4024b = EnumC4024b.TO_LEFT;
        }
        setProgressDirection(enumC4024b);
        setRoundBorder(obtainStyledAttributes.getBoolean(R$styleable.CircularProgressBar_cpb_round_border, this.roundBorder));
        setStartAngle(obtainStyledAttributes.getFloat(R$styleable.CircularProgressBar_cpb_start_angle, 0.0f));
        setIndeterminateMode(obtainStyledAttributes.getBoolean(R$styleable.CircularProgressBar_cpb_indeterminate_mode, this.indeterminateMode));
        obtainStyledAttributes.recycle();
    }

    /* renamed from: h */
    public static void m4560h(CircularProgressBar circularProgressBar, float f2, Long l2, TimeInterpolator timeInterpolator, Long l3, int i2) {
        if ((i2 & 2) != 0) {
            l2 = null;
        }
        int i3 = i2 & 4;
        int i4 = i2 & 8;
        ValueAnimator valueAnimator = circularProgressBar.progressAnimator;
        if (valueAnimator != null) {
            valueAnimator.cancel();
        }
        float[] fArr = new float[2];
        fArr[0] = circularProgressBar.indeterminateMode ? circularProgressBar.progressIndeterminateMode : circularProgressBar.progress;
        fArr[1] = f2;
        circularProgressBar.progressAnimator = ValueAnimator.ofFloat(fArr);
        if (l2 != null) {
            long longValue = l2.longValue();
            ValueAnimator valueAnimator2 = circularProgressBar.progressAnimator;
            if (valueAnimator2 != null) {
                valueAnimator2.setDuration(longValue);
            }
        }
        ValueAnimator valueAnimator3 = circularProgressBar.progressAnimator;
        if (valueAnimator3 != null) {
            valueAnimator3.addUpdateListener(new C2813a(circularProgressBar));
        }
        ValueAnimator valueAnimator4 = circularProgressBar.progressAnimator;
        if (valueAnimator4 != null) {
            valueAnimator4.start();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setProgressDirectionIndeterminateMode(EnumC4024b enumC4024b) {
        this.progressDirectionIndeterminateMode = enumC4024b;
        invalidate();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setProgressIndeterminateMode(float f2) {
        this.progressIndeterminateMode = f2;
        invalidate();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setStartAngleIndeterminateMode(float f2) {
        this.startAngleIndeterminateMode = f2;
        invalidate();
    }

    /* renamed from: d */
    public final LinearGradient m4561d(int startColor, int endColor, EnumC4023a gradientDirection) {
        float width;
        float f2;
        float f3;
        float f4;
        int ordinal = gradientDirection.ordinal();
        if (ordinal != 0) {
            if (ordinal == 1) {
                f2 = getWidth();
            } else {
                if (ordinal == 2) {
                    f4 = getHeight();
                    f2 = 0.0f;
                    f3 = 0.0f;
                    width = 0.0f;
                    return new LinearGradient(f2, f3, width, f4, startColor, endColor, Shader.TileMode.CLAMP);
                }
                if (ordinal != 3) {
                    f2 = 0.0f;
                } else {
                    f3 = getHeight();
                    f2 = 0.0f;
                    width = 0.0f;
                }
            }
            f3 = 0.0f;
            width = 0.0f;
        } else {
            width = getWidth();
            f2 = 0.0f;
            f3 = 0.0f;
        }
        f4 = 0.0f;
        return new LinearGradient(f2, f3, width, f4, startColor, endColor, Shader.TileMode.CLAMP);
    }

    /* renamed from: e */
    public final boolean m4562e(@NotNull EnumC4024b enumC4024b) {
        return enumC4024b == EnumC4024b.TO_RIGHT;
    }

    /* renamed from: f */
    public final void m4563f() {
        Paint paint = this.backgroundPaint;
        Integer num = this.backgroundProgressBarColorStart;
        int intValue = num != null ? num.intValue() : this.backgroundProgressBarColor;
        Integer num2 = this.backgroundProgressBarColorEnd;
        paint.setShader(m4561d(intValue, num2 != null ? num2.intValue() : this.backgroundProgressBarColor, this.backgroundProgressBarColorDirection));
    }

    /* renamed from: g */
    public final void m4564g() {
        Paint paint = this.foregroundPaint;
        Integer num = this.progressBarColorStart;
        int intValue = num != null ? num.intValue() : this.progressBarColor;
        Integer num2 = this.progressBarColorEnd;
        paint.setShader(m4561d(intValue, num2 != null ? num2.intValue() : this.progressBarColor, this.progressBarColorDirection));
    }

    public final int getBackgroundProgressBarColor() {
        return this.backgroundProgressBarColor;
    }

    @NotNull
    public final EnumC4023a getBackgroundProgressBarColorDirection() {
        return this.backgroundProgressBarColorDirection;
    }

    @Nullable
    public final Integer getBackgroundProgressBarColorEnd() {
        return this.backgroundProgressBarColorEnd;
    }

    @Nullable
    public final Integer getBackgroundProgressBarColorStart() {
        return this.backgroundProgressBarColorStart;
    }

    public final float getBackgroundProgressBarWidth() {
        return this.backgroundProgressBarWidth;
    }

    public final boolean getIndeterminateMode() {
        return this.indeterminateMode;
    }

    @Nullable
    public final Function1<Boolean, Unit> getOnIndeterminateModeChangeListener() {
        return this.onIndeterminateModeChangeListener;
    }

    @Nullable
    public final Function1<Float, Unit> getOnProgressChangeListener() {
        return this.onProgressChangeListener;
    }

    public final float getProgress() {
        return this.progress;
    }

    public final int getProgressBarColor() {
        return this.progressBarColor;
    }

    @NotNull
    public final EnumC4023a getProgressBarColorDirection() {
        return this.progressBarColorDirection;
    }

    @Nullable
    public final Integer getProgressBarColorEnd() {
        return this.progressBarColorEnd;
    }

    @Nullable
    public final Integer getProgressBarColorStart() {
        return this.progressBarColorStart;
    }

    public final float getProgressBarWidth() {
        return this.progressBarWidth;
    }

    @NotNull
    public final EnumC4024b getProgressDirection() {
        return this.progressDirection;
    }

    public final float getProgressMax() {
        return this.progressMax;
    }

    public final boolean getRoundBorder() {
        return this.roundBorder;
    }

    public final float getStartAngle() {
        return this.startAngle;
    }

    /* renamed from: i */
    public final EnumC4023a m4565i(int i2) {
        if (i2 == 1) {
            return EnumC4023a.LEFT_TO_RIGHT;
        }
        if (i2 == 2) {
            return EnumC4023a.RIGHT_TO_LEFT;
        }
        if (i2 == 3) {
            return EnumC4023a.TOP_TO_BOTTOM;
        }
        if (i2 == 4) {
            return EnumC4023a.BOTTOM_TO_END;
        }
        throw new IllegalArgumentException(C1499a.m626l("This value is not supported for GradientDirection: ", i2));
    }

    @Override // android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        ValueAnimator valueAnimator = this.progressAnimator;
        if (valueAnimator != null) {
            valueAnimator.cancel();
        }
        Handler handler = this.indeterminateModeHandler;
        if (handler != null) {
            handler.removeCallbacks(this.indeterminateModeRunnable);
        }
    }

    @Override // android.view.View
    public void onDraw(@NotNull Canvas canvas) {
        Intrinsics.checkParameterIsNotNull(canvas, "canvas");
        super.onDraw(canvas);
        canvas.drawOval(this.rectF, this.backgroundPaint);
        boolean z = this.indeterminateMode;
        canvas.drawArc(this.rectF, this.indeterminateMode ? this.startAngleIndeterminateMode : this.startAngle, ((((z && m4562e(this.progressDirectionIndeterminateMode)) || (!this.indeterminateMode && m4562e(this.progressDirection))) ? 360 : -360) * (((z ? this.progressIndeterminateMode : this.progress) * 100.0f) / this.progressMax)) / 100, false, this.foregroundPaint);
    }

    @Override // android.view.View
    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int min = Math.min(View.getDefaultSize(getSuggestedMinimumWidth(), widthMeasureSpec), View.getDefaultSize(getSuggestedMinimumHeight(), heightMeasureSpec));
        setMeasuredDimension(min, min);
        float f2 = this.progressBarWidth;
        float f3 = this.backgroundProgressBarWidth;
        if (f2 <= f3) {
            f2 = f3;
        }
        float f4 = f2 / 2;
        float f5 = 0 + f4;
        float f6 = min - f4;
        this.rectF.set(f5, f5, f6, f6);
    }

    @Override // android.view.View
    public void onSizeChanged(int w, int h2, int oldw, int oldh) {
        super.onSizeChanged(w, h2, oldw, oldh);
        m4564g();
        m4563f();
        invalidate();
    }

    @Override // android.view.View
    public void setBackgroundColor(int backgroundColor) {
        setBackgroundProgressBarColor(backgroundColor);
    }

    public final void setBackgroundProgressBarColor(int i2) {
        this.backgroundProgressBarColor = i2;
        m4563f();
        invalidate();
    }

    public final void setBackgroundProgressBarColorDirection(@NotNull EnumC4023a value) {
        Intrinsics.checkParameterIsNotNull(value, "value");
        this.backgroundProgressBarColorDirection = value;
        m4563f();
        invalidate();
    }

    public final void setBackgroundProgressBarColorEnd(@Nullable Integer num) {
        this.backgroundProgressBarColorEnd = num;
        m4563f();
        invalidate();
    }

    public final void setBackgroundProgressBarColorStart(@Nullable Integer num) {
        this.backgroundProgressBarColorStart = num;
        m4563f();
        invalidate();
    }

    public final void setBackgroundProgressBarWidth(float f2) {
        Resources system = Resources.getSystem();
        Intrinsics.checkExpressionValueIsNotNull(system, "Resources.getSystem()");
        float f3 = f2 * system.getDisplayMetrics().density;
        this.backgroundProgressBarWidth = f3;
        this.backgroundPaint.setStrokeWidth(f3);
        requestLayout();
        invalidate();
    }

    public final void setIndeterminateMode(boolean z) {
        this.indeterminateMode = z;
        Function1<? super Boolean, Unit> function1 = this.onIndeterminateModeChangeListener;
        if (function1 != null) {
            function1.invoke(Boolean.valueOf(z));
        }
        setProgressIndeterminateMode(0.0f);
        setProgressDirectionIndeterminateMode(EnumC4024b.TO_RIGHT);
        setStartAngleIndeterminateMode(270.0f);
        Handler handler = this.indeterminateModeHandler;
        if (handler != null) {
            handler.removeCallbacks(this.indeterminateModeRunnable);
        }
        ValueAnimator valueAnimator = this.progressAnimator;
        if (valueAnimator != null) {
            valueAnimator.cancel();
        }
        Handler handler2 = new Handler();
        this.indeterminateModeHandler = handler2;
        if (!this.indeterminateMode || handler2 == null) {
            return;
        }
        handler2.post(this.indeterminateModeRunnable);
    }

    public final void setOnIndeterminateModeChangeListener(@Nullable Function1<? super Boolean, Unit> function1) {
        this.onIndeterminateModeChangeListener = function1;
    }

    public final void setOnProgressChangeListener(@Nullable Function1<? super Float, Unit> function1) {
        this.onProgressChangeListener = function1;
    }

    public final void setProgress(float f2) {
        float f3 = this.progress;
        float f4 = this.progressMax;
        if (f3 > f4) {
            f2 = f4;
        }
        this.progress = f2;
        Function1<? super Float, Unit> function1 = this.onProgressChangeListener;
        if (function1 != null) {
            function1.invoke(Float.valueOf(f2));
        }
        invalidate();
    }

    public final void setProgressBarColor(int i2) {
        this.progressBarColor = i2;
        m4564g();
        invalidate();
    }

    public final void setProgressBarColorDirection(@NotNull EnumC4023a value) {
        Intrinsics.checkParameterIsNotNull(value, "value");
        this.progressBarColorDirection = value;
        m4564g();
        invalidate();
    }

    public final void setProgressBarColorEnd(@Nullable Integer num) {
        this.progressBarColorEnd = num;
        m4564g();
        invalidate();
    }

    public final void setProgressBarColorStart(@Nullable Integer num) {
        this.progressBarColorStart = num;
        m4564g();
        invalidate();
    }

    public final void setProgressBarWidth(float f2) {
        Resources system = Resources.getSystem();
        Intrinsics.checkExpressionValueIsNotNull(system, "Resources.getSystem()");
        float f3 = f2 * system.getDisplayMetrics().density;
        this.progressBarWidth = f3;
        this.foregroundPaint.setStrokeWidth(f3);
        requestLayout();
        invalidate();
    }

    public final void setProgressDirection(@NotNull EnumC4024b value) {
        Intrinsics.checkParameterIsNotNull(value, "value");
        this.progressDirection = value;
        invalidate();
    }

    public final void setProgressMax(float f2) {
        if (this.progressMax < 0) {
            f2 = 100.0f;
        }
        this.progressMax = f2;
        invalidate();
    }

    @JvmOverloads
    public final void setProgressWithAnimation(float f2) {
        m4560h(this, f2, null, null, null, 14);
    }

    public final void setRoundBorder(boolean z) {
        this.roundBorder = z;
        this.foregroundPaint.setStrokeCap(z ? Paint.Cap.ROUND : Paint.Cap.BUTT);
        invalidate();
    }

    public final void setStartAngle(float f2) {
        float f3;
        float f4 = f2 + 270.0f;
        while (true) {
            f3 = 360;
            if (f4 <= f3) {
                break;
            } else {
                f4 -= f3;
            }
        }
        if (f4 < 0) {
            f4 = 0.0f;
        } else if (f4 > f3) {
            f4 = 360.0f;
        }
        this.startAngle = f4;
        invalidate();
    }
}
