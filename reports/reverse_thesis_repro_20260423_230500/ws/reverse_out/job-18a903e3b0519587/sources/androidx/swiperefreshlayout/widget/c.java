package androidx.swiperefreshlayout.widget;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Transformation;
import android.widget.ListView;
import androidx.core.view.A;
import androidx.core.view.B;
import androidx.core.view.C;
import androidx.core.view.D;
import androidx.core.view.V;

/* JADX INFO: loaded from: classes.dex */
public abstract class c extends ViewGroup implements C, B {

    /* JADX INFO: renamed from: Q, reason: collision with root package name */
    private static final String f5321Q = "c";

    /* JADX INFO: renamed from: R, reason: collision with root package name */
    private static final int[] f5322R = {R.attr.enabled};

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    protected int f5323A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    int f5324B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    int f5325C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    androidx.swiperefreshlayout.widget.b f5326D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private Animation f5327E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private Animation f5328F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private Animation f5329G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private Animation f5330H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private Animation f5331I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    boolean f5332J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private int f5333K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    boolean f5334L;

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    private boolean f5335M;

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    private Animation.AnimationListener f5336N;

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    private final Animation f5337O;

    /* JADX INFO: renamed from: P, reason: collision with root package name */
    private final Animation f5338P;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private View f5339b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    j f5340c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    boolean f5341d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f5342e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private float f5343f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private float f5344g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final D f5345h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final A f5346i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final int[] f5347j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final int[] f5348k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final int[] f5349l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f5350m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private int f5351n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    int f5352o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private float f5353p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private float f5354q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private boolean f5355r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private int f5356s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    boolean f5357t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private boolean f5358u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final DecelerateInterpolator f5359v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    androidx.swiperefreshlayout.widget.a f5360w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private int f5361x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    protected int f5362y;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    float f5363z;

    class a implements Animation.AnimationListener {
        a() {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationEnd(Animation animation) {
            j jVar;
            c cVar = c.this;
            if (!cVar.f5341d) {
                cVar.r();
                return;
            }
            cVar.f5326D.setAlpha(255);
            c.this.f5326D.start();
            c cVar2 = c.this;
            if (cVar2.f5332J && (jVar = cVar2.f5340c) != null) {
                jVar.a();
            }
            c cVar3 = c.this;
            cVar3.f5352o = cVar3.f5360w.getTop();
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationRepeat(Animation animation) {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationStart(Animation animation) {
        }
    }

    class b extends Animation {
        b() {
        }

        @Override // android.view.animation.Animation
        public void applyTransformation(float f3, Transformation transformation) {
            c.this.setAnimationProgress(f3);
        }
    }

    /* JADX INFO: renamed from: androidx.swiperefreshlayout.widget.c$c, reason: collision with other inner class name */
    class C0084c extends Animation {
        C0084c() {
        }

        @Override // android.view.animation.Animation
        public void applyTransformation(float f3, Transformation transformation) {
            c.this.setAnimationProgress(1.0f - f3);
        }
    }

    class d extends Animation {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ int f5367b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f5368c;

        d(int i3, int i4) {
            this.f5367b = i3;
            this.f5368c = i4;
        }

        @Override // android.view.animation.Animation
        public void applyTransformation(float f3, Transformation transformation) {
            c.this.f5326D.setAlpha((int) (this.f5367b + ((this.f5368c - r0) * f3)));
        }
    }

    class e implements Animation.AnimationListener {
        e() {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationEnd(Animation animation) {
            c cVar = c.this;
            if (cVar.f5357t) {
                return;
            }
            cVar.y(null);
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationRepeat(Animation animation) {
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationStart(Animation animation) {
        }
    }

    class f extends Animation {
        f() {
        }

        @Override // android.view.animation.Animation
        public void applyTransformation(float f3, Transformation transformation) {
            c cVar = c.this;
            int iAbs = !cVar.f5334L ? cVar.f5324B - Math.abs(cVar.f5323A) : cVar.f5324B;
            c cVar2 = c.this;
            c.this.setTargetOffsetTopAndBottom((cVar2.f5362y + ((int) ((iAbs - r1) * f3))) - cVar2.f5360w.getTop());
            c.this.f5326D.e(1.0f - f3);
        }
    }

    class g extends Animation {
        g() {
        }

        @Override // android.view.animation.Animation
        public void applyTransformation(float f3, Transformation transformation) {
            c.this.p(f3);
        }
    }

    class h extends Animation {
        h() {
        }

        @Override // android.view.animation.Animation
        public void applyTransformation(float f3, Transformation transformation) {
            c cVar = c.this;
            float f4 = cVar.f5363z;
            cVar.setAnimationProgress(f4 + ((-f4) * f3));
            c.this.p(f3);
        }
    }

    public interface i {
    }

    public interface j {
        void a();
    }

    public c(Context context) {
        this(context, null);
    }

    private void A(Animation.AnimationListener animationListener) {
        this.f5360w.setVisibility(0);
        this.f5326D.setAlpha(255);
        b bVar = new b();
        this.f5327E = bVar;
        bVar.setDuration(this.f5351n);
        if (animationListener != null) {
            this.f5360w.b(animationListener);
        }
        this.f5360w.clearAnimation();
        this.f5360w.startAnimation(this.f5327E);
    }

    private void a(int i3, Animation.AnimationListener animationListener) {
        this.f5362y = i3;
        this.f5337O.reset();
        this.f5337O.setDuration(200L);
        this.f5337O.setInterpolator(this.f5359v);
        if (animationListener != null) {
            this.f5360w.b(animationListener);
        }
        this.f5360w.clearAnimation();
        this.f5360w.startAnimation(this.f5337O);
    }

    private void b(int i3, Animation.AnimationListener animationListener) {
        if (this.f5357t) {
            z(i3, animationListener);
            return;
        }
        this.f5362y = i3;
        this.f5338P.reset();
        this.f5338P.setDuration(200L);
        this.f5338P.setInterpolator(this.f5359v);
        if (animationListener != null) {
            this.f5360w.b(animationListener);
        }
        this.f5360w.clearAnimation();
        this.f5360w.startAnimation(this.f5338P);
    }

    private void e() {
        this.f5360w = new androidx.swiperefreshlayout.widget.a(getContext());
        androidx.swiperefreshlayout.widget.b bVar = new androidx.swiperefreshlayout.widget.b(getContext());
        this.f5326D = bVar;
        bVar.l(1);
        this.f5360w.setImageDrawable(this.f5326D);
        this.f5360w.setVisibility(8);
        addView(this.f5360w);
    }

    private void g() {
        if (this.f5339b == null) {
            for (int i3 = 0; i3 < getChildCount(); i3++) {
                View childAt = getChildAt(i3);
                if (!childAt.equals(this.f5360w)) {
                    this.f5339b = childAt;
                    return;
                }
            }
        }
    }

    private void h(float f3) {
        if (f3 > this.f5343f) {
            t(true, true);
            return;
        }
        this.f5341d = false;
        this.f5326D.j(0.0f, 0.0f);
        b(this.f5352o, !this.f5357t ? new e() : null);
        this.f5326D.d(false);
    }

    private boolean k(Animation animation) {
        return (animation == null || !animation.hasStarted() || animation.hasEnded()) ? false : true;
    }

    private void l(float f3) {
        this.f5326D.d(true);
        float fMin = Math.min(1.0f, Math.abs(f3 / this.f5343f));
        float fMax = (((float) Math.max(((double) fMin) - 0.4d, 0.0d)) * 5.0f) / 3.0f;
        float fAbs = Math.abs(f3) - this.f5343f;
        int i3 = this.f5325C;
        if (i3 <= 0) {
            i3 = this.f5334L ? this.f5324B - this.f5323A : this.f5324B;
        }
        float f4 = i3;
        double dMax = Math.max(0.0f, Math.min(fAbs, f4 * 2.0f) / f4) / 4.0f;
        float fPow = ((float) (dMax - Math.pow(dMax, 2.0d))) * 2.0f;
        int i4 = this.f5323A + ((int) ((f4 * fMin) + (f4 * fPow * 2.0f)));
        if (this.f5360w.getVisibility() != 0) {
            this.f5360w.setVisibility(0);
        }
        if (!this.f5357t) {
            this.f5360w.setScaleX(1.0f);
            this.f5360w.setScaleY(1.0f);
        }
        if (this.f5357t) {
            setAnimationProgress(Math.min(1.0f, f3 / this.f5343f));
        }
        if (f3 < this.f5343f) {
            if (this.f5326D.getAlpha() > 76 && !k(this.f5329G)) {
                x();
            }
        } else if (this.f5326D.getAlpha() < 255 && !k(this.f5330H)) {
            w();
        }
        this.f5326D.j(0.0f, Math.min(0.8f, fMax * 0.8f));
        this.f5326D.e(Math.min(1.0f, fMax));
        this.f5326D.g((((fMax * 0.4f) - 0.25f) + (fPow * 2.0f)) * 0.5f);
        setTargetOffsetTopAndBottom(i4 - this.f5352o);
    }

    private void q(MotionEvent motionEvent) {
        int actionIndex = motionEvent.getActionIndex();
        if (motionEvent.getPointerId(actionIndex) == this.f5356s) {
            this.f5356s = motionEvent.getPointerId(actionIndex == 0 ? 1 : 0);
        }
    }

    private void setColorViewAlpha(int i3) {
        this.f5360w.getBackground().setAlpha(i3);
        this.f5326D.setAlpha(i3);
    }

    private void t(boolean z3, boolean z4) {
        if (this.f5341d != z3) {
            this.f5332J = z4;
            g();
            this.f5341d = z3;
            if (z3) {
                a(this.f5352o, this.f5336N);
            } else {
                y(this.f5336N);
            }
        }
    }

    private Animation u(int i3, int i4) {
        d dVar = new d(i3, i4);
        dVar.setDuration(300L);
        this.f5360w.b(null);
        this.f5360w.clearAnimation();
        this.f5360w.startAnimation(dVar);
        return dVar;
    }

    private void v(float f3) {
        float f4 = this.f5354q;
        float f5 = f3 - f4;
        int i3 = this.f5342e;
        if (f5 <= i3 || this.f5355r) {
            return;
        }
        this.f5353p = f4 + i3;
        this.f5355r = true;
        this.f5326D.setAlpha(76);
    }

    private void w() {
        this.f5330H = u(this.f5326D.getAlpha(), 255);
    }

    private void x() {
        this.f5329G = u(this.f5326D.getAlpha(), 76);
    }

    private void z(int i3, Animation.AnimationListener animationListener) {
        this.f5362y = i3;
        this.f5363z = this.f5360w.getScaleX();
        h hVar = new h();
        this.f5331I = hVar;
        hVar.setDuration(150L);
        if (animationListener != null) {
            this.f5360w.b(animationListener);
        }
        this.f5360w.clearAnimation();
        this.f5360w.startAnimation(this.f5331I);
    }

    @Override // androidx.core.view.B
    public void c(View view, View view2, int i3, int i4) {
        if (i4 == 0) {
            onNestedScrollAccepted(view, view2, i3);
        }
    }

    public boolean d() {
        View view = this.f5339b;
        return view instanceof ListView ? androidx.core.widget.g.a((ListView) view, -1) : view.canScrollVertically(-1);
    }

    @Override // android.view.View
    public boolean dispatchNestedFling(float f3, float f4, boolean z3) {
        return this.f5346i.a(f3, f4, z3);
    }

    @Override // android.view.View
    public boolean dispatchNestedPreFling(float f3, float f4) {
        return this.f5346i.b(f3, f4);
    }

    @Override // android.view.View
    public boolean dispatchNestedPreScroll(int i3, int i4, int[] iArr, int[] iArr2) {
        return this.f5346i.c(i3, i4, iArr, iArr2);
    }

    @Override // android.view.View
    public boolean dispatchNestedScroll(int i3, int i4, int i5, int i6, int[] iArr) {
        return this.f5346i.f(i3, i4, i5, i6, iArr);
    }

    public void f(int i3, int i4, int i5, int i6, int[] iArr, int i7, int[] iArr2) {
        if (i7 == 0) {
            this.f5346i.e(i3, i4, i5, i6, iArr, i7, iArr2);
        }
    }

    @Override // android.view.ViewGroup
    protected int getChildDrawingOrder(int i3, int i4) {
        int i5 = this.f5361x;
        return i5 < 0 ? i4 : i4 == i3 + (-1) ? i5 : i4 >= i5 ? i4 + 1 : i4;
    }

    @Override // android.view.ViewGroup
    public int getNestedScrollAxes() {
        return this.f5345h.a();
    }

    public int getProgressCircleDiameter() {
        return this.f5333K;
    }

    public int getProgressViewEndOffset() {
        return this.f5324B;
    }

    public int getProgressViewStartOffset() {
        return this.f5323A;
    }

    @Override // android.view.View
    public boolean hasNestedScrollingParent() {
        return this.f5346i.j();
    }

    @Override // androidx.core.view.B
    public void i(View view, int i3) {
        if (i3 == 0) {
            onStopNestedScroll(view);
        }
    }

    @Override // android.view.View
    public boolean isNestedScrollingEnabled() {
        return this.f5346i.l();
    }

    @Override // androidx.core.view.B
    public void j(View view, int i3, int i4, int[] iArr, int i5) {
        if (i5 == 0) {
            onNestedPreScroll(view, i3, i4, iArr);
        }
    }

    @Override // androidx.core.view.C
    public void m(View view, int i3, int i4, int i5, int i6, int i7, int[] iArr) {
        if (i7 != 0) {
            return;
        }
        int i8 = iArr[1];
        f(i3, i4, i5, i6, this.f5348k, i7, iArr);
        int i9 = i6 - (iArr[1] - i8);
        if ((i9 == 0 ? i6 + this.f5348k[1] : i9) >= 0 || d()) {
            return;
        }
        float fAbs = this.f5344g + Math.abs(r1);
        this.f5344g = fAbs;
        l(fAbs);
        iArr[1] = iArr[1] + i9;
    }

    @Override // androidx.core.view.B
    public void n(View view, int i3, int i4, int i5, int i6, int i7) {
        m(view, i3, i4, i5, i6, i7, this.f5349l);
    }

    @Override // androidx.core.view.B
    public boolean o(View view, View view2, int i3, int i4) {
        if (i4 == 0) {
            return onStartNestedScroll(view, view2, i3);
        }
        return false;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        r();
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x0058  */
    @Override // android.view.ViewGroup
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onInterceptTouchEvent(android.view.MotionEvent r5) {
        /*
            r4 = this;
            r4.g()
            int r0 = r5.getActionMasked()
            boolean r1 = r4.f5358u
            r2 = 0
            if (r1 == 0) goto L10
            if (r0 != 0) goto L10
            r4.f5358u = r2
        L10:
            boolean r1 = r4.isEnabled()
            if (r1 == 0) goto L81
            boolean r1 = r4.f5358u
            if (r1 != 0) goto L81
            boolean r1 = r4.d()
            if (r1 != 0) goto L81
            boolean r1 = r4.f5341d
            if (r1 != 0) goto L81
            boolean r1 = r4.f5350m
            if (r1 == 0) goto L29
            goto L81
        L29:
            if (r0 == 0) goto L5d
            r1 = 1
            r3 = -1
            if (r0 == r1) goto L58
            r1 = 2
            if (r0 == r1) goto L3d
            r1 = 3
            if (r0 == r1) goto L58
            r1 = 6
            if (r0 == r1) goto L39
            goto L7e
        L39:
            r4.q(r5)
            goto L7e
        L3d:
            int r0 = r4.f5356s
            if (r0 != r3) goto L49
            java.lang.String r5 = androidx.swiperefreshlayout.widget.c.f5321Q
            java.lang.String r0 = "Got ACTION_MOVE event but don't have an active pointer id."
            android.util.Log.e(r5, r0)
            return r2
        L49:
            int r0 = r5.findPointerIndex(r0)
            if (r0 >= 0) goto L50
            return r2
        L50:
            float r5 = r5.getY(r0)
            r4.v(r5)
            goto L7e
        L58:
            r4.f5355r = r2
            r4.f5356s = r3
            goto L7e
        L5d:
            int r0 = r4.f5323A
            androidx.swiperefreshlayout.widget.a r1 = r4.f5360w
            int r1 = r1.getTop()
            int r0 = r0 - r1
            r4.setTargetOffsetTopAndBottom(r0)
            int r0 = r5.getPointerId(r2)
            r4.f5356s = r0
            r4.f5355r = r2
            int r0 = r5.findPointerIndex(r0)
            if (r0 >= 0) goto L78
            return r2
        L78:
            float r5 = r5.getY(r0)
            r4.f5354q = r5
        L7e:
            boolean r5 = r4.f5355r
            return r5
        L81:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.swiperefreshlayout.widget.c.onInterceptTouchEvent(android.view.MotionEvent):boolean");
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        int measuredWidth = getMeasuredWidth();
        int measuredHeight = getMeasuredHeight();
        if (getChildCount() == 0) {
            return;
        }
        if (this.f5339b == null) {
            g();
        }
        View view = this.f5339b;
        if (view == null) {
            return;
        }
        int paddingLeft = getPaddingLeft();
        int paddingTop = getPaddingTop();
        view.layout(paddingLeft, paddingTop, ((measuredWidth - getPaddingLeft()) - getPaddingRight()) + paddingLeft, ((measuredHeight - getPaddingTop()) - getPaddingBottom()) + paddingTop);
        int measuredWidth2 = this.f5360w.getMeasuredWidth();
        int measuredHeight2 = this.f5360w.getMeasuredHeight();
        int i7 = measuredWidth / 2;
        int i8 = measuredWidth2 / 2;
        int i9 = this.f5352o;
        this.f5360w.layout(i7 - i8, i9, i7 + i8, measuredHeight2 + i9);
    }

    @Override // android.view.View
    public void onMeasure(int i3, int i4) {
        super.onMeasure(i3, i4);
        if (this.f5339b == null) {
            g();
        }
        View view = this.f5339b;
        if (view == null) {
            return;
        }
        view.measure(View.MeasureSpec.makeMeasureSpec((getMeasuredWidth() - getPaddingLeft()) - getPaddingRight(), 1073741824), View.MeasureSpec.makeMeasureSpec((getMeasuredHeight() - getPaddingTop()) - getPaddingBottom(), 1073741824));
        this.f5360w.measure(View.MeasureSpec.makeMeasureSpec(this.f5333K, 1073741824), View.MeasureSpec.makeMeasureSpec(this.f5333K, 1073741824));
        this.f5361x = -1;
        for (int i5 = 0; i5 < getChildCount(); i5++) {
            if (getChildAt(i5) == this.f5360w) {
                this.f5361x = i5;
                return;
            }
        }
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public boolean onNestedFling(View view, float f3, float f4, boolean z3) {
        return dispatchNestedFling(f3, f4, z3);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public boolean onNestedPreFling(View view, float f3, float f4) {
        return dispatchNestedPreFling(f3, f4);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void onNestedPreScroll(View view, int i3, int i4, int[] iArr) {
        if (i4 > 0) {
            float f3 = this.f5344g;
            if (f3 > 0.0f) {
                float f4 = i4;
                if (f4 > f3) {
                    iArr[1] = (int) f3;
                    this.f5344g = 0.0f;
                } else {
                    this.f5344g = f3 - f4;
                    iArr[1] = i4;
                }
                l(this.f5344g);
            }
        }
        if (this.f5334L && i4 > 0 && this.f5344g == 0.0f && Math.abs(i4 - iArr[1]) > 0) {
            this.f5360w.setVisibility(8);
        }
        int[] iArr2 = this.f5347j;
        if (dispatchNestedPreScroll(i3 - iArr[0], i4 - iArr[1], iArr2, null)) {
            iArr[0] = iArr[0] + iArr2[0];
            iArr[1] = iArr[1] + iArr2[1];
        }
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void onNestedScroll(View view, int i3, int i4, int i5, int i6) {
        m(view, i3, i4, i5, i6, 0, this.f5349l);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void onNestedScrollAccepted(View view, View view2, int i3) {
        this.f5345h.b(view, view2, i3);
        startNestedScroll(i3 & 2);
        this.f5344g = 0.0f;
        this.f5350m = true;
    }

    @Override // android.view.View
    protected void onRestoreInstanceState(Parcelable parcelable) {
        k kVar = (k) parcelable;
        super.onRestoreInstanceState(kVar.getSuperState());
        setRefreshing(kVar.f5374a);
    }

    @Override // android.view.View
    protected Parcelable onSaveInstanceState() {
        return new k(super.onSaveInstanceState(), this.f5341d);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public boolean onStartNestedScroll(View view, View view2, int i3) {
        return (!isEnabled() || this.f5358u || this.f5341d || (i3 & 2) == 0) ? false : true;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void onStopNestedScroll(View view) {
        this.f5345h.d(view);
        this.f5350m = false;
        float f3 = this.f5344g;
        if (f3 > 0.0f) {
            h(f3);
            this.f5344g = 0.0f;
        }
        stopNestedScroll();
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        int actionMasked = motionEvent.getActionMasked();
        if (this.f5358u && actionMasked == 0) {
            this.f5358u = false;
        }
        if (!isEnabled() || this.f5358u || d() || this.f5341d || this.f5350m) {
            return false;
        }
        if (actionMasked == 0) {
            this.f5356s = motionEvent.getPointerId(0);
            this.f5355r = false;
        } else {
            if (actionMasked == 1) {
                int iFindPointerIndex = motionEvent.findPointerIndex(this.f5356s);
                if (iFindPointerIndex < 0) {
                    Log.e(f5321Q, "Got ACTION_UP event but don't have an active pointer id.");
                    return false;
                }
                if (this.f5355r) {
                    float y3 = (motionEvent.getY(iFindPointerIndex) - this.f5353p) * 0.5f;
                    this.f5355r = false;
                    h(y3);
                }
                this.f5356s = -1;
                return false;
            }
            if (actionMasked == 2) {
                int iFindPointerIndex2 = motionEvent.findPointerIndex(this.f5356s);
                if (iFindPointerIndex2 < 0) {
                    Log.e(f5321Q, "Got ACTION_MOVE event but have an invalid active pointer id.");
                    return false;
                }
                float y4 = motionEvent.getY(iFindPointerIndex2);
                v(y4);
                if (this.f5355r) {
                    float f3 = (y4 - this.f5353p) * 0.5f;
                    if (f3 <= 0.0f) {
                        return false;
                    }
                    getParent().requestDisallowInterceptTouchEvent(true);
                    l(f3);
                }
            } else {
                if (actionMasked == 3) {
                    return false;
                }
                if (actionMasked == 5) {
                    int actionIndex = motionEvent.getActionIndex();
                    if (actionIndex < 0) {
                        Log.e(f5321Q, "Got ACTION_POINTER_DOWN event but have an invalid action index.");
                        return false;
                    }
                    this.f5356s = motionEvent.getPointerId(actionIndex);
                } else if (actionMasked == 6) {
                    q(motionEvent);
                }
            }
        }
        return true;
    }

    void p(float f3) {
        setTargetOffsetTopAndBottom((this.f5362y + ((int) ((this.f5323A - r0) * f3))) - this.f5360w.getTop());
    }

    void r() {
        this.f5360w.clearAnimation();
        this.f5326D.stop();
        this.f5360w.setVisibility(8);
        setColorViewAlpha(255);
        if (this.f5357t) {
            setAnimationProgress(0.0f);
        } else {
            setTargetOffsetTopAndBottom(this.f5323A - this.f5352o);
        }
        this.f5352o = this.f5360w.getTop();
    }

    public void s(boolean z3, int i3, int i4) {
        this.f5357t = z3;
        this.f5323A = i3;
        this.f5324B = i4;
        this.f5334L = true;
        r();
        this.f5341d = false;
    }

    void setAnimationProgress(float f3) {
        this.f5360w.setScaleX(f3);
        this.f5360w.setScaleY(f3);
    }

    @Deprecated
    public void setColorScheme(int... iArr) {
        setColorSchemeResources(iArr);
    }

    public void setColorSchemeColors(int... iArr) {
        g();
        this.f5326D.f(iArr);
    }

    public void setColorSchemeResources(int... iArr) {
        Context context = getContext();
        int[] iArr2 = new int[iArr.length];
        for (int i3 = 0; i3 < iArr.length; i3++) {
            iArr2[i3] = androidx.core.content.a.b(context, iArr[i3]);
        }
        setColorSchemeColors(iArr2);
    }

    public void setDistanceToTriggerSync(int i3) {
        this.f5343f = i3;
    }

    @Override // android.view.View
    public void setEnabled(boolean z3) {
        super.setEnabled(z3);
        if (z3) {
            return;
        }
        r();
    }

    @Deprecated
    public void setLegacyRequestDisallowInterceptTouchEventEnabled(boolean z3) {
        this.f5335M = z3;
    }

    @Override // android.view.View
    public void setNestedScrollingEnabled(boolean z3) {
        this.f5346i.m(z3);
    }

    public void setOnChildScrollUpCallback(i iVar) {
    }

    public void setOnRefreshListener(j jVar) {
        this.f5340c = jVar;
    }

    @Deprecated
    public void setProgressBackgroundColor(int i3) {
        setProgressBackgroundColorSchemeResource(i3);
    }

    public void setProgressBackgroundColorSchemeColor(int i3) {
        this.f5360w.setBackgroundColor(i3);
    }

    public void setProgressBackgroundColorSchemeResource(int i3) {
        setProgressBackgroundColorSchemeColor(androidx.core.content.a.b(getContext(), i3));
    }

    public void setRefreshing(boolean z3) {
        if (!z3 || this.f5341d == z3) {
            t(z3, false);
            return;
        }
        this.f5341d = z3;
        setTargetOffsetTopAndBottom((!this.f5334L ? this.f5324B + this.f5323A : this.f5324B) - this.f5352o);
        this.f5332J = false;
        A(this.f5336N);
    }

    public void setSize(int i3) {
        if (i3 == 0 || i3 == 1) {
            DisplayMetrics displayMetrics = getResources().getDisplayMetrics();
            if (i3 == 0) {
                this.f5333K = (int) (displayMetrics.density * 56.0f);
            } else {
                this.f5333K = (int) (displayMetrics.density * 40.0f);
            }
            this.f5360w.setImageDrawable(null);
            this.f5326D.l(i3);
            this.f5360w.setImageDrawable(this.f5326D);
        }
    }

    public void setSlingshotDistance(int i3) {
        this.f5325C = i3;
    }

    void setTargetOffsetTopAndBottom(int i3) {
        this.f5360w.bringToFront();
        V.L(this.f5360w, i3);
        this.f5352o = this.f5360w.getTop();
    }

    @Override // android.view.View
    public boolean startNestedScroll(int i3) {
        return this.f5346i.o(i3);
    }

    @Override // android.view.View
    public void stopNestedScroll() {
        this.f5346i.q();
    }

    void y(Animation.AnimationListener animationListener) {
        C0084c c0084c = new C0084c();
        this.f5328F = c0084c;
        c0084c.setDuration(150L);
        this.f5360w.b(animationListener);
        this.f5360w.clearAnimation();
        this.f5360w.startAnimation(this.f5328F);
    }

    static class k extends View.BaseSavedState {
        public static final Parcelable.Creator<k> CREATOR = new a();

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final boolean f5374a;

        class a implements Parcelable.Creator {
            a() {
            }

            @Override // android.os.Parcelable.Creator
            /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
            public k createFromParcel(Parcel parcel) {
                return new k(parcel);
            }

            @Override // android.os.Parcelable.Creator
            /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
            public k[] newArray(int i3) {
                return new k[i3];
            }
        }

        k(Parcelable parcelable, boolean z3) {
            super(parcelable);
            this.f5374a = z3;
        }

        @Override // android.view.View.BaseSavedState, android.view.AbsSavedState, android.os.Parcelable
        public void writeToParcel(Parcel parcel, int i3) {
            super.writeToParcel(parcel, i3);
            parcel.writeByte(this.f5374a ? (byte) 1 : (byte) 0);
        }

        k(Parcel parcel) {
            super(parcel);
            this.f5374a = parcel.readByte() != 0;
        }
    }

    public c(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f5341d = false;
        this.f5343f = -1.0f;
        this.f5347j = new int[2];
        this.f5348k = new int[2];
        this.f5349l = new int[2];
        this.f5356s = -1;
        this.f5361x = -1;
        this.f5336N = new a();
        this.f5337O = new f();
        this.f5338P = new g();
        this.f5342e = ViewConfiguration.get(context).getScaledTouchSlop();
        this.f5351n = getResources().getInteger(R.integer.config_mediumAnimTime);
        setWillNotDraw(false);
        this.f5359v = new DecelerateInterpolator(2.0f);
        DisplayMetrics displayMetrics = getResources().getDisplayMetrics();
        this.f5333K = (int) (displayMetrics.density * 40.0f);
        e();
        setChildrenDrawingOrderEnabled(true);
        int i3 = (int) (displayMetrics.density * 64.0f);
        this.f5324B = i3;
        this.f5343f = i3;
        this.f5345h = new D(this);
        this.f5346i = new A(this);
        setNestedScrollingEnabled(true);
        int i4 = -this.f5333K;
        this.f5352o = i4;
        this.f5323A = i4;
        p(1.0f);
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, f5322R);
        setEnabled(typedArrayObtainStyledAttributes.getBoolean(0, true));
        typedArrayObtainStyledAttributes.recycle();
    }
}
