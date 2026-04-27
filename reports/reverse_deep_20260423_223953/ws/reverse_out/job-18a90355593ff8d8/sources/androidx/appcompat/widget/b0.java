package androidx.appcompat.widget;

import android.R;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.Region;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.InputFilter;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.method.TransformationMethod;
import android.util.AttributeSet;
import android.util.Property;
import android.view.ActionMode;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.CompoundButton;
import androidx.emoji2.text.f;
import d.AbstractC0502a;
import e.AbstractC0510a;
import h.C0544a;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes.dex */
public abstract class b0 extends CompoundButton {

    /* JADX INFO: renamed from: T, reason: collision with root package name */
    private static final Property f3960T = new a(Float.class, "thumbPos");

    /* JADX INFO: renamed from: U, reason: collision with root package name */
    private static final int[] f3961U = {R.attr.state_checked};

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    float f3962A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private int f3963B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private int f3964C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private int f3965D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private int f3966E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private int f3967F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private int f3968G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private int f3969H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private boolean f3970I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private final TextPaint f3971J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private ColorStateList f3972K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    private Layout f3973L;

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    private Layout f3974M;

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    private TransformationMethod f3975N;

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    ObjectAnimator f3976O;

    /* JADX INFO: renamed from: P, reason: collision with root package name */
    private final C f3977P;

    /* JADX INFO: renamed from: Q, reason: collision with root package name */
    private C0240n f3978Q;

    /* JADX INFO: renamed from: R, reason: collision with root package name */
    private b f3979R;

    /* JADX INFO: renamed from: S, reason: collision with root package name */
    private final Rect f3980S;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Drawable f3981b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private ColorStateList f3982c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private PorterDuff.Mode f3983d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f3984e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f3985f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Drawable f3986g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private ColorStateList f3987h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private PorterDuff.Mode f3988i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f3989j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f3990k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private int f3991l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private int f3992m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private int f3993n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private boolean f3994o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private CharSequence f3995p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private CharSequence f3996q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private CharSequence f3997r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private CharSequence f3998s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private boolean f3999t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private int f4000u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private int f4001v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private float f4002w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private float f4003x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private VelocityTracker f4004y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private int f4005z;

    class a extends Property {
        a(Class cls, String str) {
            super(cls, str);
        }

        @Override // android.util.Property
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Float get(b0 b0Var) {
            return Float.valueOf(b0Var.f3962A);
        }

        @Override // android.util.Property
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void set(b0 b0Var, Float f3) {
            b0Var.setThumbPosition(f3.floatValue());
        }
    }

    static class b extends f.AbstractC0070f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Reference f4006a;

        b(b0 b0Var) {
            this.f4006a = new WeakReference(b0Var);
        }

        @Override // androidx.emoji2.text.f.AbstractC0070f
        public void a(Throwable th) {
            b0 b0Var = (b0) this.f4006a.get();
            if (b0Var != null) {
                b0Var.j();
            }
        }

        @Override // androidx.emoji2.text.f.AbstractC0070f
        public void b() {
            b0 b0Var = (b0) this.f4006a.get();
            if (b0Var != null) {
                b0Var.j();
            }
        }
    }

    public b0(Context context) {
        this(context, null);
    }

    private void a(boolean z3) {
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(this, (Property<b0, Float>) f3960T, z3 ? 1.0f : 0.0f);
        this.f3976O = objectAnimatorOfFloat;
        objectAnimatorOfFloat.setDuration(250L);
        this.f3976O.setAutoCancel(true);
        this.f3976O.start();
    }

    private void b() {
        Drawable drawable = this.f3981b;
        if (drawable != null) {
            if (this.f3984e || this.f3985f) {
                Drawable drawableMutate = androidx.core.graphics.drawable.a.j(drawable).mutate();
                this.f3981b = drawableMutate;
                if (this.f3984e) {
                    androidx.core.graphics.drawable.a.g(drawableMutate, this.f3982c);
                }
                if (this.f3985f) {
                    androidx.core.graphics.drawable.a.h(this.f3981b, this.f3983d);
                }
                if (this.f3981b.isStateful()) {
                    this.f3981b.setState(getDrawableState());
                }
            }
        }
    }

    private void c() {
        Drawable drawable = this.f3986g;
        if (drawable != null) {
            if (this.f3989j || this.f3990k) {
                Drawable drawableMutate = androidx.core.graphics.drawable.a.j(drawable).mutate();
                this.f3986g = drawableMutate;
                if (this.f3989j) {
                    androidx.core.graphics.drawable.a.g(drawableMutate, this.f3987h);
                }
                if (this.f3990k) {
                    androidx.core.graphics.drawable.a.h(this.f3986g, this.f3988i);
                }
                if (this.f3986g.isStateful()) {
                    this.f3986g.setState(getDrawableState());
                }
            }
        }
    }

    private void d() {
        ObjectAnimator objectAnimator = this.f3976O;
        if (objectAnimator != null) {
            objectAnimator.cancel();
        }
    }

    private void e(MotionEvent motionEvent) {
        MotionEvent motionEventObtain = MotionEvent.obtain(motionEvent);
        motionEventObtain.setAction(3);
        super.onTouchEvent(motionEventObtain);
        motionEventObtain.recycle();
    }

    private static float f(float f3, float f4, float f5) {
        return f3 < f4 ? f4 : f3 > f5 ? f5 : f3;
    }

    private CharSequence g(CharSequence charSequence) {
        TransformationMethod transformationMethodF = getEmojiTextViewHelper().f(this.f3975N);
        return transformationMethodF != null ? transformationMethodF.getTransformation(charSequence, this) : charSequence;
    }

    private C0240n getEmojiTextViewHelper() {
        if (this.f3978Q == null) {
            this.f3978Q = new C0240n(this);
        }
        return this.f3978Q;
    }

    private boolean getTargetCheckedState() {
        return this.f3962A > 0.5f;
    }

    private int getThumbOffset() {
        return (int) (((r0.b(this) ? 1.0f - this.f3962A : this.f3962A) * getThumbScrollRange()) + 0.5f);
    }

    private int getThumbScrollRange() {
        Drawable drawable = this.f3986g;
        if (drawable == null) {
            return 0;
        }
        Rect rect = this.f3980S;
        drawable.getPadding(rect);
        Drawable drawable2 = this.f3981b;
        Rect rectC = drawable2 != null ? O.c(drawable2) : O.f3766c;
        return ((((this.f3963B - this.f3965D) - rect.left) - rect.right) - rectC.left) - rectC.right;
    }

    private boolean h(float f3, float f4) {
        if (this.f3981b == null) {
            return false;
        }
        int thumbOffset = getThumbOffset();
        this.f3981b.getPadding(this.f3980S);
        int i3 = this.f3967F;
        int i4 = this.f4001v;
        int i5 = i3 - i4;
        int i6 = (this.f3966E + thumbOffset) - i4;
        int i7 = this.f3965D + i6;
        Rect rect = this.f3980S;
        return f3 > ((float) i6) && f3 < ((float) (((i7 + rect.left) + rect.right) + i4)) && f4 > ((float) i5) && f4 < ((float) (this.f3969H + i4));
    }

    private Layout i(CharSequence charSequence) {
        return new StaticLayout(charSequence, this.f3971J, charSequence != null ? (int) Math.ceil(Layout.getDesiredWidth(charSequence, r2)) : 0, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, true);
    }

    private void k() {
        if (Build.VERSION.SDK_INT >= 30) {
            CharSequence string = this.f3997r;
            if (string == null) {
                string = getResources().getString(d.h.f8929b);
            }
            androidx.core.view.V.l0(this, string);
        }
    }

    private void l() {
        if (Build.VERSION.SDK_INT >= 30) {
            CharSequence string = this.f3995p;
            if (string == null) {
                string = getResources().getString(d.h.f8930c);
            }
            androidx.core.view.V.l0(this, string);
        }
    }

    private void o(int i3, int i4) {
        n(i3 != 1 ? i3 != 2 ? i3 != 3 ? null : Typeface.MONOSPACE : Typeface.SERIF : Typeface.SANS_SERIF, i4);
    }

    private void p() {
        if (this.f3979R == null && this.f3978Q.b() && androidx.emoji2.text.f.i()) {
            androidx.emoji2.text.f fVarC = androidx.emoji2.text.f.c();
            int iE = fVarC.e();
            if (iE == 3 || iE == 0) {
                b bVar = new b(this);
                this.f3979R = bVar;
                fVarC.t(bVar);
            }
        }
    }

    private void q(MotionEvent motionEvent) {
        this.f4000u = 0;
        boolean targetCheckedState = true;
        boolean z3 = motionEvent.getAction() == 1 && isEnabled();
        boolean zIsChecked = isChecked();
        if (z3) {
            this.f4004y.computeCurrentVelocity(1000);
            float xVelocity = this.f4004y.getXVelocity();
            if (Math.abs(xVelocity) <= this.f4005z) {
                targetCheckedState = getTargetCheckedState();
            } else if (!r0.b(this) ? xVelocity <= 0.0f : xVelocity >= 0.0f) {
                targetCheckedState = false;
            }
        } else {
            targetCheckedState = zIsChecked;
        }
        if (targetCheckedState != zIsChecked) {
            playSoundEffect(0);
        }
        setChecked(targetCheckedState);
        e(motionEvent);
    }

    private void setTextOffInternal(CharSequence charSequence) {
        this.f3997r = charSequence;
        this.f3998s = g(charSequence);
        this.f3974M = null;
        if (this.f3999t) {
            p();
        }
    }

    private void setTextOnInternal(CharSequence charSequence) {
        this.f3995p = charSequence;
        this.f3996q = g(charSequence);
        this.f3973L = null;
        if (this.f3999t) {
            p();
        }
    }

    @Override // android.view.View
    public void draw(Canvas canvas) {
        int i3;
        int i4;
        Rect rect = this.f3980S;
        int i5 = this.f3966E;
        int i6 = this.f3967F;
        int i7 = this.f3968G;
        int i8 = this.f3969H;
        int thumbOffset = getThumbOffset() + i5;
        Drawable drawable = this.f3981b;
        Rect rectC = drawable != null ? O.c(drawable) : O.f3766c;
        Drawable drawable2 = this.f3986g;
        if (drawable2 != null) {
            drawable2.getPadding(rect);
            int i9 = rect.left;
            thumbOffset += i9;
            if (rectC != null) {
                int i10 = rectC.left;
                if (i10 > i9) {
                    i5 += i10 - i9;
                }
                int i11 = rectC.top;
                int i12 = rect.top;
                i3 = i11 > i12 ? (i11 - i12) + i6 : i6;
                int i13 = rectC.right;
                int i14 = rect.right;
                if (i13 > i14) {
                    i7 -= i13 - i14;
                }
                int i15 = rectC.bottom;
                int i16 = rect.bottom;
                if (i15 > i16) {
                    i4 = i8 - (i15 - i16);
                }
                this.f3986g.setBounds(i5, i3, i7, i4);
            } else {
                i3 = i6;
            }
            i4 = i8;
            this.f3986g.setBounds(i5, i3, i7, i4);
        }
        Drawable drawable3 = this.f3981b;
        if (drawable3 != null) {
            drawable3.getPadding(rect);
            int i17 = thumbOffset - rect.left;
            int i18 = thumbOffset + this.f3965D + rect.right;
            this.f3981b.setBounds(i17, i6, i18, i8);
            Drawable background = getBackground();
            if (background != null) {
                androidx.core.graphics.drawable.a.d(background, i17, i6, i18, i8);
            }
        }
        super.draw(canvas);
    }

    @Override // android.widget.CompoundButton, android.widget.TextView, android.view.View
    public void drawableHotspotChanged(float f3, float f4) {
        super.drawableHotspotChanged(f3, f4);
        Drawable drawable = this.f3981b;
        if (drawable != null) {
            androidx.core.graphics.drawable.a.c(drawable, f3, f4);
        }
        Drawable drawable2 = this.f3986g;
        if (drawable2 != null) {
            androidx.core.graphics.drawable.a.c(drawable2, f3, f4);
        }
    }

    @Override // android.widget.CompoundButton, android.widget.TextView, android.view.View
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        int[] drawableState = getDrawableState();
        Drawable drawable = this.f3981b;
        boolean state = (drawable == null || !drawable.isStateful()) ? false : drawable.setState(drawableState);
        Drawable drawable2 = this.f3986g;
        if (drawable2 != null && drawable2.isStateful()) {
            state |= drawable2.setState(drawableState);
        }
        if (state) {
            invalidate();
        }
    }

    @Override // android.widget.CompoundButton, android.widget.TextView
    public int getCompoundPaddingLeft() {
        if (!r0.b(this)) {
            return super.getCompoundPaddingLeft();
        }
        int compoundPaddingLeft = super.getCompoundPaddingLeft() + this.f3963B;
        return !TextUtils.isEmpty(getText()) ? compoundPaddingLeft + this.f3993n : compoundPaddingLeft;
    }

    @Override // android.widget.CompoundButton, android.widget.TextView
    public int getCompoundPaddingRight() {
        if (r0.b(this)) {
            return super.getCompoundPaddingRight();
        }
        int compoundPaddingRight = super.getCompoundPaddingRight() + this.f3963B;
        return !TextUtils.isEmpty(getText()) ? compoundPaddingRight + this.f3993n : compoundPaddingRight;
    }

    @Override // android.widget.TextView
    public ActionMode.Callback getCustomSelectionActionModeCallback() {
        return androidx.core.widget.i.n(super.getCustomSelectionActionModeCallback());
    }

    public boolean getShowText() {
        return this.f3999t;
    }

    public boolean getSplitTrack() {
        return this.f3994o;
    }

    public int getSwitchMinWidth() {
        return this.f3992m;
    }

    public int getSwitchPadding() {
        return this.f3993n;
    }

    public CharSequence getTextOff() {
        return this.f3997r;
    }

    public CharSequence getTextOn() {
        return this.f3995p;
    }

    public Drawable getThumbDrawable() {
        return this.f3981b;
    }

    protected final float getThumbPosition() {
        return this.f3962A;
    }

    public int getThumbTextPadding() {
        return this.f3991l;
    }

    public ColorStateList getThumbTintList() {
        return this.f3982c;
    }

    public PorterDuff.Mode getThumbTintMode() {
        return this.f3983d;
    }

    public Drawable getTrackDrawable() {
        return this.f3986g;
    }

    public ColorStateList getTrackTintList() {
        return this.f3987h;
    }

    public PorterDuff.Mode getTrackTintMode() {
        return this.f3988i;
    }

    void j() {
        setTextOnInternal(this.f3995p);
        setTextOffInternal(this.f3997r);
        requestLayout();
    }

    @Override // android.widget.CompoundButton, android.widget.TextView, android.view.View
    public void jumpDrawablesToCurrentState() {
        super.jumpDrawablesToCurrentState();
        Drawable drawable = this.f3981b;
        if (drawable != null) {
            drawable.jumpToCurrentState();
        }
        Drawable drawable2 = this.f3986g;
        if (drawable2 != null) {
            drawable2.jumpToCurrentState();
        }
        ObjectAnimator objectAnimator = this.f3976O;
        if (objectAnimator == null || !objectAnimator.isStarted()) {
            return;
        }
        this.f3976O.end();
        this.f3976O = null;
    }

    public void m(Context context, int i3) {
        g0 g0VarS = g0.s(context, i3, d.j.f8952B2);
        ColorStateList colorStateListC = g0VarS.c(d.j.f8968F2);
        if (colorStateListC != null) {
            this.f3972K = colorStateListC;
        } else {
            this.f3972K = getTextColors();
        }
        int iE = g0VarS.e(d.j.f8956C2, 0);
        if (iE != 0) {
            float f3 = iE;
            if (f3 != this.f3971J.getTextSize()) {
                this.f3971J.setTextSize(f3);
                requestLayout();
            }
        }
        o(g0VarS.j(d.j.f8960D2, -1), g0VarS.j(d.j.f8964E2, -1));
        if (g0VarS.a(d.j.f8988K2, false)) {
            this.f3975N = new C0544a(getContext());
        } else {
            this.f3975N = null;
        }
        setTextOnInternal(this.f3995p);
        setTextOffInternal(this.f3997r);
        g0VarS.w();
    }

    public void n(Typeface typeface, int i3) {
        if (i3 <= 0) {
            this.f3971J.setFakeBoldText(false);
            this.f3971J.setTextSkewX(0.0f);
            setSwitchTypeface(typeface);
        } else {
            Typeface typefaceDefaultFromStyle = typeface == null ? Typeface.defaultFromStyle(i3) : Typeface.create(typeface, i3);
            setSwitchTypeface(typefaceDefaultFromStyle);
            int i4 = (~(typefaceDefaultFromStyle != null ? typefaceDefaultFromStyle.getStyle() : 0)) & i3;
            this.f3971J.setFakeBoldText((i4 & 1) != 0);
            this.f3971J.setTextSkewX((i4 & 2) != 0 ? -0.25f : 0.0f);
        }
    }

    @Override // android.widget.CompoundButton, android.widget.TextView, android.view.View
    protected int[] onCreateDrawableState(int i3) {
        int[] iArrOnCreateDrawableState = super.onCreateDrawableState(i3 + 1);
        if (isChecked()) {
            View.mergeDrawableStates(iArrOnCreateDrawableState, f3961U);
        }
        return iArrOnCreateDrawableState;
    }

    @Override // android.widget.CompoundButton, android.widget.TextView, android.view.View
    protected void onDraw(Canvas canvas) {
        int width;
        super.onDraw(canvas);
        Rect rect = this.f3980S;
        Drawable drawable = this.f3986g;
        if (drawable != null) {
            drawable.getPadding(rect);
        } else {
            rect.setEmpty();
        }
        int i3 = this.f3967F;
        int i4 = this.f3969H;
        int i5 = i3 + rect.top;
        int i6 = i4 - rect.bottom;
        Drawable drawable2 = this.f3981b;
        if (drawable != null) {
            if (!this.f3994o || drawable2 == null) {
                drawable.draw(canvas);
            } else {
                Rect rectC = O.c(drawable2);
                drawable2.copyBounds(rect);
                rect.left += rectC.left;
                rect.right -= rectC.right;
                int iSave = canvas.save();
                canvas.clipRect(rect, Region.Op.DIFFERENCE);
                drawable.draw(canvas);
                canvas.restoreToCount(iSave);
            }
        }
        int iSave2 = canvas.save();
        if (drawable2 != null) {
            drawable2.draw(canvas);
        }
        Layout layout = getTargetCheckedState() ? this.f3973L : this.f3974M;
        if (layout != null) {
            int[] drawableState = getDrawableState();
            ColorStateList colorStateList = this.f3972K;
            if (colorStateList != null) {
                this.f3971J.setColor(colorStateList.getColorForState(drawableState, 0));
            }
            this.f3971J.drawableState = drawableState;
            if (drawable2 != null) {
                Rect bounds = drawable2.getBounds();
                width = bounds.left + bounds.right;
            } else {
                width = getWidth();
            }
            canvas.translate((width / 2) - (layout.getWidth() / 2), ((i5 + i6) / 2) - (layout.getHeight() / 2));
            layout.draw(canvas);
        }
        canvas.restoreToCount(iSave2);
    }

    @Override // android.view.View
    public void onInitializeAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        super.onInitializeAccessibilityEvent(accessibilityEvent);
        accessibilityEvent.setClassName("android.widget.Switch");
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setClassName("android.widget.Switch");
        if (Build.VERSION.SDK_INT < 30) {
            CharSequence charSequence = isChecked() ? this.f3995p : this.f3997r;
            if (TextUtils.isEmpty(charSequence)) {
                return;
            }
            CharSequence text = accessibilityNodeInfo.getText();
            if (TextUtils.isEmpty(text)) {
                accessibilityNodeInfo.setText(charSequence);
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append(text);
            sb.append(' ');
            sb.append(charSequence);
            accessibilityNodeInfo.setText(sb);
        }
    }

    @Override // android.widget.TextView, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        int iMax;
        int width;
        int paddingLeft;
        int i7;
        int paddingTop;
        int height;
        super.onLayout(z3, i3, i4, i5, i6);
        int iMax2 = 0;
        if (this.f3981b != null) {
            Rect rect = this.f3980S;
            Drawable drawable = this.f3986g;
            if (drawable != null) {
                drawable.getPadding(rect);
            } else {
                rect.setEmpty();
            }
            Rect rectC = O.c(this.f3981b);
            iMax = Math.max(0, rectC.left - rect.left);
            iMax2 = Math.max(0, rectC.right - rect.right);
        } else {
            iMax = 0;
        }
        if (r0.b(this)) {
            paddingLeft = getPaddingLeft() + iMax;
            width = ((this.f3963B + paddingLeft) - iMax) - iMax2;
        } else {
            width = (getWidth() - getPaddingRight()) - iMax2;
            paddingLeft = (width - this.f3963B) + iMax + iMax2;
        }
        int gravity = getGravity() & 112;
        if (gravity == 16) {
            int paddingTop2 = ((getPaddingTop() + getHeight()) - getPaddingBottom()) / 2;
            i7 = this.f3964C;
            paddingTop = paddingTop2 - (i7 / 2);
        } else {
            if (gravity == 80) {
                height = getHeight() - getPaddingBottom();
                paddingTop = height - this.f3964C;
                this.f3966E = paddingLeft;
                this.f3967F = paddingTop;
                this.f3969H = height;
                this.f3968G = width;
            }
            paddingTop = getPaddingTop();
            i7 = this.f3964C;
        }
        height = i7 + paddingTop;
        this.f3966E = paddingLeft;
        this.f3967F = paddingTop;
        this.f3969H = height;
        this.f3968G = width;
    }

    @Override // android.widget.TextView, android.view.View
    public void onMeasure(int i3, int i4) {
        int intrinsicWidth;
        int intrinsicHeight;
        if (this.f3999t) {
            if (this.f3973L == null) {
                this.f3973L = i(this.f3996q);
            }
            if (this.f3974M == null) {
                this.f3974M = i(this.f3998s);
            }
        }
        Rect rect = this.f3980S;
        Drawable drawable = this.f3981b;
        int intrinsicHeight2 = 0;
        if (drawable != null) {
            drawable.getPadding(rect);
            intrinsicWidth = (this.f3981b.getIntrinsicWidth() - rect.left) - rect.right;
            intrinsicHeight = this.f3981b.getIntrinsicHeight();
        } else {
            intrinsicWidth = 0;
            intrinsicHeight = 0;
        }
        this.f3965D = Math.max(this.f3999t ? Math.max(this.f3973L.getWidth(), this.f3974M.getWidth()) + (this.f3991l * 2) : 0, intrinsicWidth);
        Drawable drawable2 = this.f3986g;
        if (drawable2 != null) {
            drawable2.getPadding(rect);
            intrinsicHeight2 = this.f3986g.getIntrinsicHeight();
        } else {
            rect.setEmpty();
        }
        int iMax = rect.left;
        int iMax2 = rect.right;
        Drawable drawable3 = this.f3981b;
        if (drawable3 != null) {
            Rect rectC = O.c(drawable3);
            iMax = Math.max(iMax, rectC.left);
            iMax2 = Math.max(iMax2, rectC.right);
        }
        int iMax3 = this.f3970I ? Math.max(this.f3992m, (this.f3965D * 2) + iMax + iMax2) : this.f3992m;
        int iMax4 = Math.max(intrinsicHeight2, intrinsicHeight);
        this.f3963B = iMax3;
        this.f3964C = iMax4;
        super.onMeasure(i3, i4);
        if (getMeasuredHeight() < iMax4) {
            setMeasuredDimension(getMeasuredWidthAndState(), iMax4);
        }
    }

    @Override // android.view.View
    public void onPopulateAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        super.onPopulateAccessibilityEvent(accessibilityEvent);
        CharSequence charSequence = isChecked() ? this.f3995p : this.f3997r;
        if (charSequence != null) {
            accessibilityEvent.getText().add(charSequence);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x0089  */
    @Override // android.widget.TextView, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r7) {
        /*
            r6 = this;
            android.view.VelocityTracker r0 = r6.f4004y
            r0.addMovement(r7)
            int r0 = r7.getActionMasked()
            r1 = 1
            if (r0 == 0) goto L9d
            r2 = 2
            if (r0 == r1) goto L89
            if (r0 == r2) goto L16
            r3 = 3
            if (r0 == r3) goto L89
            goto Lb7
        L16:
            int r0 = r6.f4000u
            if (r0 == r1) goto L55
            if (r0 == r2) goto L1e
            goto Lb7
        L1e:
            float r7 = r7.getX()
            int r0 = r6.getThumbScrollRange()
            float r2 = r6.f4002w
            float r2 = r7 - r2
            r3 = 1065353216(0x3f800000, float:1.0)
            r4 = 0
            if (r0 == 0) goto L32
            float r0 = (float) r0
            float r2 = r2 / r0
            goto L3b
        L32:
            int r0 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r0 <= 0) goto L38
            r2 = r3
            goto L3b
        L38:
            r0 = -1082130432(0xffffffffbf800000, float:-1.0)
            r2 = r0
        L3b:
            boolean r0 = androidx.appcompat.widget.r0.b(r6)
            if (r0 == 0) goto L42
            float r2 = -r2
        L42:
            float r0 = r6.f3962A
            float r0 = r0 + r2
            float r0 = f(r0, r4, r3)
            float r2 = r6.f3962A
            int r2 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r2 == 0) goto L54
            r6.f4002w = r7
            r6.setThumbPosition(r0)
        L54:
            return r1
        L55:
            float r0 = r7.getX()
            float r3 = r7.getY()
            float r4 = r6.f4002w
            float r4 = r0 - r4
            float r4 = java.lang.Math.abs(r4)
            int r5 = r6.f4001v
            float r5 = (float) r5
            int r4 = (r4 > r5 ? 1 : (r4 == r5 ? 0 : -1))
            if (r4 > 0) goto L7b
            float r4 = r6.f4003x
            float r4 = r3 - r4
            float r4 = java.lang.Math.abs(r4)
            int r5 = r6.f4001v
            float r5 = (float) r5
            int r4 = (r4 > r5 ? 1 : (r4 == r5 ? 0 : -1))
            if (r4 <= 0) goto Lb7
        L7b:
            r6.f4000u = r2
            android.view.ViewParent r7 = r6.getParent()
            r7.requestDisallowInterceptTouchEvent(r1)
            r6.f4002w = r0
            r6.f4003x = r3
            return r1
        L89:
            int r0 = r6.f4000u
            if (r0 != r2) goto L94
            r6.q(r7)
            super.onTouchEvent(r7)
            return r1
        L94:
            r0 = 0
            r6.f4000u = r0
            android.view.VelocityTracker r0 = r6.f4004y
            r0.clear()
            goto Lb7
        L9d:
            float r0 = r7.getX()
            float r2 = r7.getY()
            boolean r3 = r6.isEnabled()
            if (r3 == 0) goto Lb7
            boolean r3 = r6.h(r0, r2)
            if (r3 == 0) goto Lb7
            r6.f4000u = r1
            r6.f4002w = r0
            r6.f4003x = r2
        Lb7:
            boolean r7 = super.onTouchEvent(r7)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.b0.onTouchEvent(android.view.MotionEvent):boolean");
    }

    @Override // android.widget.TextView
    public void setAllCaps(boolean z3) {
        super.setAllCaps(z3);
        getEmojiTextViewHelper().d(z3);
    }

    @Override // android.widget.CompoundButton, android.widget.Checkable
    public void setChecked(boolean z3) {
        super.setChecked(z3);
        boolean zIsChecked = isChecked();
        if (zIsChecked) {
            l();
        } else {
            k();
        }
        if (getWindowToken() != null && isLaidOut()) {
            a(zIsChecked);
        } else {
            d();
            setThumbPosition(zIsChecked ? 1.0f : 0.0f);
        }
    }

    @Override // android.widget.TextView
    public void setCustomSelectionActionModeCallback(ActionMode.Callback callback) {
        super.setCustomSelectionActionModeCallback(androidx.core.widget.i.o(this, callback));
    }

    public void setEmojiCompatEnabled(boolean z3) {
        getEmojiTextViewHelper().e(z3);
        setTextOnInternal(this.f3995p);
        setTextOffInternal(this.f3997r);
        requestLayout();
    }

    protected final void setEnforceSwitchWidth(boolean z3) {
        this.f3970I = z3;
        invalidate();
    }

    @Override // android.widget.TextView
    public void setFilters(InputFilter[] inputFilterArr) {
        super.setFilters(getEmojiTextViewHelper().a(inputFilterArr));
    }

    public void setShowText(boolean z3) {
        if (this.f3999t != z3) {
            this.f3999t = z3;
            requestLayout();
            if (z3) {
                p();
            }
        }
    }

    public void setSplitTrack(boolean z3) {
        this.f3994o = z3;
        invalidate();
    }

    public void setSwitchMinWidth(int i3) {
        this.f3992m = i3;
        requestLayout();
    }

    public void setSwitchPadding(int i3) {
        this.f3993n = i3;
        requestLayout();
    }

    public void setSwitchTypeface(Typeface typeface) {
        if ((this.f3971J.getTypeface() == null || this.f3971J.getTypeface().equals(typeface)) && (this.f3971J.getTypeface() != null || typeface == null)) {
            return;
        }
        this.f3971J.setTypeface(typeface);
        requestLayout();
        invalidate();
    }

    public void setTextOff(CharSequence charSequence) {
        setTextOffInternal(charSequence);
        requestLayout();
        if (isChecked()) {
            return;
        }
        k();
    }

    public void setTextOn(CharSequence charSequence) {
        setTextOnInternal(charSequence);
        requestLayout();
        if (isChecked()) {
            l();
        }
    }

    public void setThumbDrawable(Drawable drawable) {
        Drawable drawable2 = this.f3981b;
        if (drawable2 != null) {
            drawable2.setCallback(null);
        }
        this.f3981b = drawable;
        if (drawable != null) {
            drawable.setCallback(this);
        }
        requestLayout();
    }

    void setThumbPosition(float f3) {
        this.f3962A = f3;
        invalidate();
    }

    public void setThumbResource(int i3) {
        setThumbDrawable(AbstractC0510a.b(getContext(), i3));
    }

    public void setThumbTextPadding(int i3) {
        this.f3991l = i3;
        requestLayout();
    }

    public void setThumbTintList(ColorStateList colorStateList) {
        this.f3982c = colorStateList;
        this.f3984e = true;
        b();
    }

    public void setThumbTintMode(PorterDuff.Mode mode) {
        this.f3983d = mode;
        this.f3985f = true;
        b();
    }

    public void setTrackDrawable(Drawable drawable) {
        Drawable drawable2 = this.f3986g;
        if (drawable2 != null) {
            drawable2.setCallback(null);
        }
        this.f3986g = drawable;
        if (drawable != null) {
            drawable.setCallback(this);
        }
        requestLayout();
    }

    public void setTrackResource(int i3) {
        setTrackDrawable(AbstractC0510a.b(getContext(), i3));
    }

    public void setTrackTintList(ColorStateList colorStateList) {
        this.f3987h = colorStateList;
        this.f3989j = true;
        c();
    }

    public void setTrackTintMode(PorterDuff.Mode mode) {
        this.f3988i = mode;
        this.f3990k = true;
        c();
    }

    @Override // android.widget.CompoundButton, android.widget.Checkable
    public void toggle() {
        setChecked(!isChecked());
    }

    @Override // android.widget.CompoundButton, android.widget.TextView, android.view.View
    protected boolean verifyDrawable(Drawable drawable) {
        return super.verifyDrawable(drawable) || drawable == this.f3981b || drawable == this.f3986g;
    }

    public b0(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8786G);
    }

    public b0(Context context, AttributeSet attributeSet, int i3) {
        super(context, attributeSet, i3);
        this.f3982c = null;
        this.f3983d = null;
        this.f3984e = false;
        this.f3985f = false;
        this.f3987h = null;
        this.f3988i = null;
        this.f3989j = false;
        this.f3990k = false;
        this.f4004y = VelocityTracker.obtain();
        this.f3970I = true;
        this.f3980S = new Rect();
        c0.a(this, getContext());
        TextPaint textPaint = new TextPaint(1);
        this.f3971J = textPaint;
        textPaint.density = getResources().getDisplayMetrics().density;
        g0 g0VarU = g0.u(context, attributeSet, d.j.f9093m2, i3, 0);
        androidx.core.view.V.V(this, context, d.j.f9093m2, attributeSet, g0VarU.q(), i3, 0);
        Drawable drawableF = g0VarU.f(d.j.f9105p2);
        this.f3981b = drawableF;
        if (drawableF != null) {
            drawableF.setCallback(this);
        }
        Drawable drawableF2 = g0VarU.f(d.j.f9141y2);
        this.f3986g = drawableF2;
        if (drawableF2 != null) {
            drawableF2.setCallback(this);
        }
        setTextOnInternal(g0VarU.o(d.j.f9097n2));
        setTextOffInternal(g0VarU.o(d.j.f9101o2));
        this.f3999t = g0VarU.a(d.j.f9109q2, true);
        this.f3991l = g0VarU.e(d.j.f9129v2, 0);
        this.f3992m = g0VarU.e(d.j.f9117s2, 0);
        this.f3993n = g0VarU.e(d.j.f9121t2, 0);
        this.f3994o = g0VarU.a(d.j.f9113r2, false);
        ColorStateList colorStateListC = g0VarU.c(d.j.f9133w2);
        if (colorStateListC != null) {
            this.f3982c = colorStateListC;
            this.f3984e = true;
        }
        PorterDuff.Mode modeD = O.d(g0VarU.j(d.j.f9137x2, -1), null);
        if (this.f3983d != modeD) {
            this.f3983d = modeD;
            this.f3985f = true;
        }
        if (this.f3984e || this.f3985f) {
            b();
        }
        ColorStateList colorStateListC2 = g0VarU.c(d.j.f9145z2);
        if (colorStateListC2 != null) {
            this.f3987h = colorStateListC2;
            this.f3989j = true;
        }
        PorterDuff.Mode modeD2 = O.d(g0VarU.j(d.j.f8948A2, -1), null);
        if (this.f3988i != modeD2) {
            this.f3988i = modeD2;
            this.f3990k = true;
        }
        if (this.f3989j || this.f3990k) {
            c();
        }
        int iM = g0VarU.m(d.j.f9125u2, 0);
        if (iM != 0) {
            m(context, iM);
        }
        C c3 = new C(this);
        this.f3977P = c3;
        c3.m(attributeSet, i3);
        g0VarU.w();
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        this.f4001v = viewConfiguration.getScaledTouchSlop();
        this.f4005z = viewConfiguration.getScaledMinimumFlingVelocity();
        getEmojiTextViewHelper().c(attributeSet, i3);
        refreshDrawableState();
        setChecked(isChecked());
    }
}
