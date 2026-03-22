package me.jingbin.library.skeleton;

import android.animation.Animator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ComposeShader;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.Shader;
import android.os.Build;
import android.util.AttributeSet;
import android.view.ViewTreeObserver;
import android.widget.FrameLayout;
import me.jingbin.library.R$color;
import me.jingbin.library.R$styleable;

/* loaded from: classes3.dex */
public class ShimmerLayout extends FrameLayout {

    /* renamed from: c */
    public int f12729c;

    /* renamed from: e */
    public Rect f12730e;

    /* renamed from: f */
    public Paint f12731f;

    /* renamed from: g */
    public ValueAnimator f12732g;

    /* renamed from: h */
    public Bitmap f12733h;

    /* renamed from: i */
    public Bitmap f12734i;

    /* renamed from: j */
    public Canvas f12735j;

    /* renamed from: k */
    public boolean f12736k;

    /* renamed from: l */
    public boolean f12737l;

    /* renamed from: m */
    public boolean f12738m;

    /* renamed from: n */
    public int f12739n;

    /* renamed from: o */
    public int f12740o;

    /* renamed from: p */
    public int f12741p;

    /* renamed from: q */
    public float f12742q;

    /* renamed from: r */
    public float f12743r;

    /* renamed from: s */
    public ViewTreeObserver.OnPreDrawListener f12744s;

    /* renamed from: me.jingbin.library.skeleton.ShimmerLayout$a */
    public class ViewTreeObserverOnPreDrawListenerC4970a implements ViewTreeObserver.OnPreDrawListener {
        public ViewTreeObserverOnPreDrawListenerC4970a() {
        }

        @Override // android.view.ViewTreeObserver.OnPreDrawListener
        public boolean onPreDraw() {
            ShimmerLayout.this.getViewTreeObserver().removeOnPreDrawListener(this);
            ShimmerLayout.this.m5640c();
            return true;
        }
    }

    /* renamed from: me.jingbin.library.skeleton.ShimmerLayout$b */
    public class C4971b implements ValueAnimator.AnimatorUpdateListener {

        /* renamed from: c */
        public final /* synthetic */ int f12746c;

        /* renamed from: e */
        public final /* synthetic */ int f12747e;

        public C4971b(int i2, int i3) {
            this.f12746c = i2;
            this.f12747e = i3;
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            ShimmerLayout.this.f12729c = ((Integer) valueAnimator.getAnimatedValue()).intValue() + this.f12746c;
            ShimmerLayout shimmerLayout = ShimmerLayout.this;
            if (shimmerLayout.f12729c + this.f12747e >= 0) {
                shimmerLayout.invalidate();
            }
        }
    }

    public ShimmerLayout(Context context) {
        this(context, null);
    }

    private float[] getGradientColorDistribution() {
        float[] fArr = {0.0f, 0.5f - (r1 / 2.0f), (r1 / 2.0f) + 0.5f, 1.0f};
        float f2 = this.f12743r;
        return fArr;
    }

    private Bitmap getMaskBitmap() {
        Bitmap bitmap;
        if (this.f12734i == null) {
            try {
                bitmap = Bitmap.createBitmap(this.f12730e.width(), getHeight(), Bitmap.Config.ALPHA_8);
            } catch (OutOfMemoryError unused) {
                System.gc();
                bitmap = null;
            }
            this.f12734i = bitmap;
        }
        return this.f12734i;
    }

    private Animator getShimmerAnimation() {
        ValueAnimator ofInt;
        ValueAnimator valueAnimator = this.f12732g;
        if (valueAnimator != null) {
            return valueAnimator;
        }
        if (this.f12730e == null) {
            this.f12730e = new Rect(0, 0, (int) ((Math.tan(Math.toRadians(Math.abs(this.f12741p))) * getHeight()) + (((getWidth() / 2) * this.f12742q) / Math.cos(Math.toRadians(Math.abs(this.f12741p))))), getHeight());
        }
        int width = getWidth();
        int i2 = getWidth() > this.f12730e.width() ? -width : -this.f12730e.width();
        int width2 = this.f12730e.width();
        int i3 = width - i2;
        int[] iArr = new int[2];
        if (this.f12736k) {
            iArr[0] = i3;
            iArr[1] = 0;
            ofInt = ValueAnimator.ofInt(iArr);
        } else {
            iArr[0] = 0;
            iArr[1] = i3;
            ofInt = ValueAnimator.ofInt(iArr);
        }
        this.f12732g = ofInt;
        ofInt.setDuration(this.f12739n);
        this.f12732g.setRepeatCount(-1);
        this.f12732g.addUpdateListener(new C4971b(i2, width2));
        return this.f12732g;
    }

    /* renamed from: a */
    public final void m5638a() {
        if (this.f12737l) {
            m5639b();
            m5640c();
        }
    }

    /* renamed from: b */
    public final void m5639b() {
        ValueAnimator valueAnimator = this.f12732g;
        if (valueAnimator != null) {
            valueAnimator.end();
            this.f12732g.removeAllUpdateListeners();
        }
        this.f12732g = null;
        this.f12731f = null;
        this.f12737l = false;
        this.f12735j = null;
        Bitmap bitmap = this.f12734i;
        if (bitmap != null) {
            bitmap.recycle();
            this.f12734i = null;
        }
    }

    /* renamed from: c */
    public void m5640c() {
        if (this.f12737l) {
            return;
        }
        if (getWidth() == 0) {
            this.f12744s = new ViewTreeObserverOnPreDrawListenerC4970a();
            getViewTreeObserver().addOnPreDrawListener(this.f12744s);
        } else {
            getShimmerAnimation().start();
            this.f12737l = true;
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public void dispatchDraw(Canvas canvas) {
        if (!this.f12737l || getWidth() <= 0 || getHeight() <= 0) {
            super.dispatchDraw(canvas);
            return;
        }
        super.dispatchDraw(canvas);
        Bitmap maskBitmap = getMaskBitmap();
        this.f12733h = maskBitmap;
        if (maskBitmap == null) {
            return;
        }
        if (this.f12735j == null) {
            this.f12735j = new Canvas(this.f12733h);
        }
        this.f12735j.drawColor(0, PorterDuff.Mode.CLEAR);
        this.f12735j.save();
        this.f12735j.translate(-this.f12729c, 0.0f);
        super.dispatchDraw(this.f12735j);
        this.f12735j.restore();
        if (this.f12731f == null) {
            int i2 = this.f12740o;
            int argb = Color.argb(0, Color.red(i2), Color.green(i2), Color.blue(i2));
            float width = (getWidth() / 2) * this.f12742q;
            float height = this.f12741p >= 0 ? getHeight() : 0.0f;
            float cos = ((float) Math.cos(Math.toRadians(this.f12741p))) * width;
            float sin = (((float) Math.sin(Math.toRadians(this.f12741p))) * width) + height;
            int i3 = this.f12740o;
            LinearGradient linearGradient = new LinearGradient(0.0f, height, cos, sin, new int[]{argb, i3, i3, argb}, getGradientColorDistribution(), Shader.TileMode.CLAMP);
            Bitmap bitmap = this.f12733h;
            Shader.TileMode tileMode = Shader.TileMode.CLAMP;
            ComposeShader composeShader = new ComposeShader(linearGradient, new BitmapShader(bitmap, tileMode, tileMode), PorterDuff.Mode.DST_IN);
            Paint paint = new Paint();
            this.f12731f = paint;
            paint.setAntiAlias(true);
            this.f12731f.setDither(true);
            this.f12731f.setFilterBitmap(true);
            this.f12731f.setShader(composeShader);
        }
        canvas.save();
        canvas.translate(this.f12729c, 0.0f);
        Rect rect = this.f12730e;
        canvas.drawRect(rect.left, 0.0f, rect.width(), this.f12730e.height(), this.f12731f);
        canvas.restore();
        this.f12733h = null;
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        m5639b();
        super.onDetachedFromWindow();
    }

    public void setAnimationReversed(boolean z) {
        this.f12736k = z;
        m5638a();
    }

    public void setGradientCenterColorWidth(float f2) {
        if (f2 <= 0.0f || 1.0f <= f2) {
            throw new IllegalArgumentException(String.format("gradientCenterColorWidth value must be higher than %d and less than %d", (byte) 0, (byte) 1));
        }
        this.f12743r = f2;
        m5638a();
    }

    public void setMaskWidth(float f2) {
        if (f2 <= 0.0f || 1.0f < f2) {
            throw new IllegalArgumentException(String.format("maskWidth value must be higher than %d and less or equal to %d", (byte) 0, (byte) 1));
        }
        this.f12742q = f2;
        m5638a();
    }

    public void setShimmerAngle(int i2) {
        if (i2 < -45 || 45 < i2) {
            throw new IllegalArgumentException(String.format("shimmerAngle value must be between %d and %d", (byte) -45, (byte) 45));
        }
        this.f12741p = i2;
        m5638a();
    }

    public void setShimmerAnimationDuration(int i2) {
        this.f12739n = i2;
        m5638a();
    }

    public void setShimmerColor(int i2) {
        this.f12740o = i2;
        m5638a();
    }

    @Override // android.view.View
    public void setVisibility(int i2) {
        super.setVisibility(i2);
        if (i2 == 0) {
            if (this.f12738m) {
                m5640c();
            }
        } else {
            if (this.f12744s != null) {
                getViewTreeObserver().removeOnPreDrawListener(this.f12744s);
            }
            m5639b();
        }
    }

    public ShimmerLayout(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public ShimmerLayout(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        int color;
        setWillNotDraw(false);
        TypedArray obtainStyledAttributes = context.getTheme().obtainStyledAttributes(attributeSet, R$styleable.ShimmerLayout, 0, 0);
        try {
            this.f12741p = obtainStyledAttributes.getInteger(R$styleable.ShimmerLayout_shimmer_angle, 20);
            this.f12739n = obtainStyledAttributes.getInteger(R$styleable.ShimmerLayout_shimmer_animation_duration, 1500);
            int i3 = R$styleable.ShimmerLayout_shimmer_color;
            int i4 = R$color.by_skeleton_shimmer_color;
            if (Build.VERSION.SDK_INT >= 23) {
                color = getContext().getColor(i4);
            } else {
                color = getResources().getColor(i4);
            }
            this.f12740o = obtainStyledAttributes.getColor(i3, color);
            this.f12738m = obtainStyledAttributes.getBoolean(R$styleable.ShimmerLayout_shimmer_auto_start, false);
            this.f12742q = obtainStyledAttributes.getFloat(R$styleable.ShimmerLayout_shimmer_mask_width, 0.5f);
            this.f12743r = obtainStyledAttributes.getFloat(R$styleable.ShimmerLayout_shimmer_gradient_center_color_width, 0.1f);
            this.f12736k = obtainStyledAttributes.getBoolean(R$styleable.ShimmerLayout_shimmer_reverse_animation, false);
            obtainStyledAttributes.recycle();
            setMaskWidth(this.f12742q);
            setGradientCenterColorWidth(this.f12743r);
            setShimmerAngle(this.f12741p);
            if (this.f12738m && getVisibility() == 0) {
                m5640c();
            }
        } catch (Throwable th) {
            obtainStyledAttributes.recycle();
            throw th;
        }
    }
}
