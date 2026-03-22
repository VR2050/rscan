package com.github.anzewei.parallaxbacklayout.widget;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.FrameLayout;
import androidx.core.view.ViewCompat;
import com.github.anzewei.parallaxbacklayout.R$anim;
import java.util.Objects;
import p005b.p190k.p191a.p192a.C1882c;
import p005b.p190k.p191a.p192a.C1883d;
import p005b.p190k.p191a.p192a.p193e.InterfaceC1885b;
import p005b.p190k.p191a.p192a.p194f.C1888a;

/* loaded from: classes.dex */
public class ParallaxBackLayout extends FrameLayout {

    /* renamed from: c */
    public float f9188c;

    /* renamed from: e */
    public Activity f9189e;

    /* renamed from: f */
    public Rect f9190f;

    /* renamed from: g */
    public boolean f9191g;

    /* renamed from: h */
    public View f9192h;

    /* renamed from: i */
    public C1883d f9193i;

    /* renamed from: j */
    public InterfaceC3255c f9194j;

    /* renamed from: k */
    public InterfaceC1885b f9195k;

    /* renamed from: l */
    public int f9196l;

    /* renamed from: m */
    public int f9197m;

    /* renamed from: n */
    public int f9198n;

    /* renamed from: o */
    public int f9199o;

    /* renamed from: p */
    public InterfaceC3254b f9200p;

    /* renamed from: q */
    public Drawable f9201q;

    /* renamed from: r */
    public boolean f9202r;

    /* renamed from: s */
    public int f9203s;

    /* renamed from: t */
    public int f9204t;

    /* renamed from: u */
    public int f9205u;

    /* renamed from: com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout$b */
    public interface InterfaceC3254b {
    }

    /* renamed from: com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout$c */
    public interface InterfaceC3255c {
        /* renamed from: a */
        void m4019a(float f2);

        /* renamed from: b */
        void m4020b(int i2);
    }

    /* renamed from: com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout$d */
    public class C3256d extends C1883d.c {

        /* renamed from: a */
        public float f9206a;

        public C3256d(C3253a c3253a) {
        }

        @Override // p005b.p190k.p191a.p192a.C1883d.c
        /* renamed from: a */
        public void mo1232a(View view, int i2, int i3, int i4, int i5) {
            if ((ParallaxBackLayout.this.f9203s & 1) != 0) {
                this.f9206a = Math.abs((i2 - r1.f9190f.left) / r1.f9192h.getWidth());
            }
            if ((ParallaxBackLayout.this.f9203s & 2) != 0) {
                this.f9206a = Math.abs((i2 - r1.f9190f.left) / r1.f9192h.getWidth());
            }
            if ((ParallaxBackLayout.this.f9203s & 8) != 0) {
                this.f9206a = Math.abs((i3 - r1.getSystemTop()) / ParallaxBackLayout.this.f9192h.getHeight());
            }
            if ((ParallaxBackLayout.this.f9203s & 4) != 0) {
                this.f9206a = Math.abs(i3 / r1.f9192h.getHeight());
            }
            ParallaxBackLayout parallaxBackLayout = ParallaxBackLayout.this;
            parallaxBackLayout.f9196l = i2;
            parallaxBackLayout.f9198n = i3;
            parallaxBackLayout.invalidate();
            InterfaceC3255c interfaceC3255c = ParallaxBackLayout.this.f9194j;
            if (interfaceC3255c != null) {
                interfaceC3255c.m4019a(this.f9206a);
            }
            if (this.f9206a < 0.999f || ParallaxBackLayout.this.f9189e.isFinishing()) {
                return;
            }
            ParallaxBackLayout.this.f9189e.finish();
            ParallaxBackLayout.this.f9189e.overridePendingTransition(0, R$anim.parallax_exit);
        }
    }

    public ParallaxBackLayout(Context context) {
        super(context);
        this.f9188c = 0.5f;
        this.f9190f = new Rect();
        this.f9191g = true;
        this.f9197m = 1;
        this.f9199o = 1;
        this.f9204t = 30;
        this.f9205u = -1;
        this.f9193i = new C1883d(getContext(), this, new C3256d(null));
        setEdgeFlag(1);
    }

    private void setContentView(View view) {
        this.f9192h = view;
    }

    /* renamed from: a */
    public final void m4017a() {
        Rect rect = this.f9190f;
        if (rect == null) {
            return;
        }
        if (this.f9197m == 0) {
            this.f9193i.f2932p = Math.max(getWidth(), getHeight());
            return;
        }
        int i2 = this.f9205u;
        if (i2 == 4) {
            C1883d c1883d = this.f9193i;
            c1883d.f2932p = rect.top + c1883d.f2933q;
        } else if (i2 == 8) {
            C1883d c1883d2 = this.f9193i;
            c1883d2.f2932p = rect.bottom + c1883d2.f2933q;
        } else if (i2 == 1) {
            C1883d c1883d3 = this.f9193i;
            c1883d3.f2932p = c1883d3.f2933q + rect.left;
        } else {
            C1883d c1883d4 = this.f9193i;
            c1883d4.f2932p = c1883d4.f2933q + rect.right;
        }
    }

    /* renamed from: b */
    public void m4018b(Activity activity) {
        this.f9189e = activity;
        ViewGroup viewGroup = (ViewGroup) activity.getWindow().getDecorView();
        ViewGroup viewGroup2 = (ViewGroup) viewGroup.getChildAt(0);
        viewGroup.removeView(viewGroup2);
        addView(viewGroup2, -1, -1);
        setContentView(viewGroup2);
        viewGroup.addView(this);
    }

    @Override // android.view.View
    public void computeScroll() {
        C1883d c1883d = this.f9193i;
        if (c1883d.f2918b == 2) {
            boolean computeScrollOffset = c1883d.f2935s.computeScrollOffset();
            int currX = c1883d.f2935s.getCurrX();
            int currY = c1883d.f2935s.getCurrY();
            int left = currX - c1883d.f2937u.getLeft();
            int top = currY - c1883d.f2937u.getTop();
            if (left != 0) {
                c1883d.f2937u.offsetLeftAndRight(left);
            }
            if (top != 0) {
                c1883d.f2937u.offsetTopAndBottom(top);
            }
            if (left != 0 || top != 0) {
                c1883d.f2936t.mo1232a(c1883d.f2937u, currX, currY, left, top);
            }
            if (computeScrollOffset && currX == c1883d.f2935s.getFinalX() && currY == c1883d.f2935s.getFinalY()) {
                c1883d.f2935s.abortAnimation();
                computeScrollOffset = c1883d.f2935s.isFinished();
            }
            if (!computeScrollOffset) {
                c1883d.f2939w.post(c1883d.f2940x);
            }
        }
        if (c1883d.f2918b == 2) {
            ViewCompat.postInvalidateOnAnimation(this);
        }
    }

    @Override // android.view.ViewGroup
    public boolean drawChild(Canvas canvas, View view, long j2) {
        Drawable drawable;
        boolean z = view == this.f9192h;
        if (this.f9191g && (this.f9196l != 0 || this.f9198n != 0)) {
            int save = canvas.save();
            this.f9195k.mo1233a(canvas, this, view);
            C1882c.b bVar = (C1882c.b) this.f9200p;
            Activity activity = bVar.f2916b;
            if (activity != null) {
                activity.getWindow().getDecorView().requestLayout();
                bVar.f2916b.getWindow().getDecorView().draw(canvas);
            }
            canvas.restoreToCount(save);
        }
        boolean drawChild = super.drawChild(canvas, view, j2);
        if (this.f9191g && z && this.f9193i.f2918b != 0 && ((this.f9196l != 0 || this.f9198n != 0) && (drawable = this.f9201q) != null)) {
            int i2 = this.f9205u;
            if (i2 == 1) {
                drawable.setBounds(view.getLeft() - this.f9201q.getIntrinsicWidth(), view.getTop(), view.getLeft(), view.getBottom());
                this.f9201q.setAlpha(((getWidth() - view.getLeft()) * 255) / getWidth());
            } else if (i2 == 2) {
                drawable.setBounds(view.getRight(), view.getTop(), this.f9201q.getIntrinsicWidth() + view.getRight(), view.getBottom());
                this.f9201q.setAlpha((view.getRight() * 255) / getWidth());
            } else if (i2 == 8) {
                drawable.setBounds(view.getLeft(), view.getBottom(), view.getRight(), this.f9201q.getIntrinsicHeight() + view.getBottom());
                this.f9201q.setAlpha((view.getBottom() * 255) / getHeight());
            } else if (i2 == 4) {
                drawable.setBounds(view.getLeft(), getSystemTop() + (view.getTop() - this.f9201q.getIntrinsicHeight()), view.getRight(), getSystemTop() + view.getTop());
                this.f9201q.setAlpha(((getHeight() - view.getTop()) * 255) / getHeight());
            }
            this.f9201q.draw(canvas);
        }
        return drawChild;
    }

    public int getEdgeFlag() {
        return this.f9205u;
    }

    public int getLayoutType() {
        return this.f9199o;
    }

    public int getSystemLeft() {
        return this.f9190f.left;
    }

    public int getSystemTop() {
        return this.f9190f.top;
    }

    @Override // android.view.View
    @TargetApi(20)
    public WindowInsets onApplyWindowInsets(WindowInsets windowInsets) {
        int systemWindowInsetTop = windowInsets.getSystemWindowInsetTop();
        if (this.f9192h.getLayoutParams() instanceof ViewGroup.MarginLayoutParams) {
            ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) this.f9192h.getLayoutParams();
            this.f9190f.set(marginLayoutParams.leftMargin, marginLayoutParams.topMargin + systemWindowInsetTop, marginLayoutParams.rightMargin, marginLayoutParams.bottomMargin);
        }
        m4017a();
        return super.onApplyWindowInsets(windowInsets);
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        if (this.f9191g && ((C1882c.b) this.f9200p).m1214a()) {
            try {
                return this.f9193i.m1230p(motionEvent);
            } catch (ArrayIndexOutOfBoundsException unused) {
            }
        }
        return false;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    public void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        this.f9202r = true;
        m4017a();
        if (this.f9192h != null) {
            int i6 = this.f9196l;
            int i7 = this.f9198n;
            ViewGroup.LayoutParams layoutParams = this.f9192h.getLayoutParams();
            if (layoutParams instanceof ViewGroup.MarginLayoutParams) {
                ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
                i6 += marginLayoutParams.leftMargin;
                i7 += marginLayoutParams.topMargin;
            }
            View view = this.f9192h;
            view.layout(i6, i7, view.getMeasuredWidth() + i6, this.f9192h.getMeasuredHeight() + i7);
        }
        this.f9202r = false;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        int min;
        int min2;
        int i2;
        int i3 = 0;
        if (!this.f9191g || !((C1882c.b) this.f9200p).m1214a()) {
            return false;
        }
        C1883d c1883d = this.f9193i;
        Objects.requireNonNull(c1883d);
        int actionMasked = motionEvent.getActionMasked();
        int actionIndex = motionEvent.getActionIndex();
        if (actionMasked == 0) {
            c1883d.m1215a();
        }
        if (c1883d.f2929m == null) {
            c1883d.f2929m = VelocityTracker.obtain();
        }
        c1883d.f2929m.addMovement(motionEvent);
        if (actionMasked == 0) {
            float x = motionEvent.getX();
            float y = motionEvent.getY();
            int pointerId = motionEvent.getPointerId(0);
            View m1224j = c1883d.m1224j((int) x, (int) y);
            c1883d.m1227m(x, y, pointerId);
            c1883d.m1231q(m1224j, pointerId);
            if ((c1883d.f2925i[pointerId] & c1883d.f2934r) != 0) {
                Objects.requireNonNull(c1883d.f2936t);
            }
        } else if (actionMasked == 1) {
            if (c1883d.f2918b == 1) {
                c1883d.m1225k();
            }
            c1883d.m1215a();
        } else if (actionMasked != 2) {
            if (actionMasked == 3) {
                if (c1883d.f2918b == 1) {
                    c1883d.m1223i(0.0f, 0.0f);
                }
                c1883d.m1215a();
            } else if (actionMasked == 5) {
                int pointerId2 = motionEvent.getPointerId(actionIndex);
                float x2 = motionEvent.getX(actionIndex);
                float y2 = motionEvent.getY(actionIndex);
                c1883d.m1227m(x2, y2, pointerId2);
                if (c1883d.f2918b == 0) {
                    c1883d.m1231q(c1883d.m1224j((int) x2, (int) y2), pointerId2);
                    if ((c1883d.f2925i[pointerId2] & c1883d.f2934r) != 0) {
                        Objects.requireNonNull(c1883d.f2936t);
                    }
                } else {
                    int i4 = (int) x2;
                    int i5 = (int) y2;
                    View view = c1883d.f2937u;
                    if (view != null && i4 >= view.getLeft() && i4 < view.getRight() && i5 >= view.getTop() && i5 < view.getBottom()) {
                        i3 = 1;
                    }
                    if (i3 != 0) {
                        c1883d.m1231q(c1883d.f2937u, pointerId2);
                    }
                }
            } else if (actionMasked == 6) {
                int pointerId3 = motionEvent.getPointerId(actionIndex);
                if (c1883d.f2918b == 1 && pointerId3 == c1883d.f2920d) {
                    int pointerCount = motionEvent.getPointerCount();
                    while (true) {
                        if (i3 >= pointerCount) {
                            i2 = -1;
                            break;
                        }
                        int pointerId4 = motionEvent.getPointerId(i3);
                        if (pointerId4 != c1883d.f2920d) {
                            View m1224j2 = c1883d.m1224j((int) motionEvent.getX(i3), (int) motionEvent.getY(i3));
                            View view2 = c1883d.f2937u;
                            if (m1224j2 == view2 && c1883d.m1231q(view2, pointerId4)) {
                                i2 = c1883d.f2920d;
                                break;
                            }
                        }
                        i3++;
                    }
                    if (i2 == -1) {
                        c1883d.m1225k();
                    }
                }
                c1883d.m1221g(pointerId3);
            }
        } else if (c1883d.f2918b == 1) {
            int findPointerIndex = motionEvent.findPointerIndex(c1883d.f2920d);
            float x3 = motionEvent.getX(findPointerIndex);
            float y3 = motionEvent.getY(findPointerIndex);
            float[] fArr = c1883d.f2923g;
            int i6 = c1883d.f2920d;
            int i7 = (int) (x3 - fArr[i6]);
            int i8 = (int) (y3 - c1883d.f2924h[i6]);
            int left = c1883d.f2937u.getLeft() + i7;
            int top = c1883d.f2937u.getTop() + i8;
            int left2 = c1883d.f2937u.getLeft();
            int top2 = c1883d.f2937u.getTop();
            if (i7 != 0) {
                C1883d.c cVar = c1883d.f2936t;
                View view3 = c1883d.f2937u;
                ParallaxBackLayout parallaxBackLayout = ParallaxBackLayout.this;
                int i9 = parallaxBackLayout.f9190f.left;
                int i10 = parallaxBackLayout.f9203s;
                if ((i10 & 1) != 0) {
                    min2 = Math.min(view3.getWidth(), Math.max(left, 0));
                } else if ((2 & i10) != 0) {
                    min2 = Math.min(i9, Math.max(left, -view3.getWidth()));
                } else {
                    left = i9;
                    c1883d.f2937u.offsetLeftAndRight(left - left2);
                }
                left = min2;
                c1883d.f2937u.offsetLeftAndRight(left - left2);
            }
            int i11 = left;
            if (i8 != 0) {
                C1883d.c cVar2 = c1883d.f2936t;
                View view4 = c1883d.f2937u;
                C3256d c3256d = (C3256d) cVar2;
                int top3 = ParallaxBackLayout.this.f9192h.getTop();
                int i12 = ParallaxBackLayout.this.f9203s;
                if ((i12 & 8) != 0) {
                    min = Math.min(0, Math.max(top, -view4.getHeight()));
                } else if ((i12 & 4) != 0) {
                    min = Math.min(view4.getHeight(), Math.max(top, 0));
                } else {
                    top = top3;
                    c1883d.f2937u.offsetTopAndBottom(top - top2);
                }
                top = min;
                c1883d.f2937u.offsetTopAndBottom(top - top2);
            }
            int i13 = top;
            if (i7 != 0 || i8 != 0) {
                c1883d.f2936t.mo1232a(c1883d.f2937u, i11, i13, i11 - left2, i13 - top2);
            }
            c1883d.m1228n(motionEvent);
        } else {
            int pointerCount2 = motionEvent.getPointerCount();
            while (i3 < pointerCount2) {
                int pointerId5 = motionEvent.getPointerId(i3);
                float x4 = motionEvent.getX(i3);
                float y4 = motionEvent.getY(i3);
                float f2 = x4 - c1883d.f2921e[pointerId5];
                float f3 = y4 - c1883d.f2922f[pointerId5];
                c1883d.m1226l(f2, f3, pointerId5);
                if (c1883d.f2918b != 1) {
                    View m1224j3 = c1883d.m1224j((int) x4, (int) y4);
                    if (c1883d.m1218d(m1224j3, f2, f3) && c1883d.m1231q(m1224j3, pointerId5)) {
                        break;
                    }
                    i3++;
                } else {
                    break;
                }
            }
            c1883d.m1228n(motionEvent);
        }
        return true;
    }

    @Override // android.view.View, android.view.ViewParent
    public void requestLayout() {
        if (this.f9202r) {
            return;
        }
        super.requestLayout();
    }

    public void setBackgroundView(InterfaceC3254b interfaceC3254b) {
        this.f9200p = interfaceC3254b;
    }

    @TargetApi(16)
    public void setEdgeFlag(int i2) {
        if (this.f9205u == i2) {
            return;
        }
        this.f9205u = i2;
        this.f9193i.f2934r = i2;
        GradientDrawable.Orientation orientation = GradientDrawable.Orientation.LEFT_RIGHT;
        if (i2 == 1) {
            orientation = GradientDrawable.Orientation.RIGHT_LEFT;
        } else if (i2 == 4) {
            orientation = GradientDrawable.Orientation.BOTTOM_TOP;
        } else if (i2 != 2 && i2 == 8) {
            orientation = GradientDrawable.Orientation.TOP_BOTTOM;
        }
        Drawable drawable = this.f9201q;
        if (drawable == null) {
            C1888a c1888a = new C1888a(orientation, new int[]{1711276032, 285212672, 0});
            c1888a.setGradientRadius(90.0f);
            c1888a.setSize(50, 50);
            this.f9201q = c1888a;
        } else if (drawable instanceof C1888a) {
            ((C1888a) drawable).setOrientation(orientation);
        }
        m4017a();
    }

    public void setEdgeMode(int i2) {
        this.f9197m = i2;
        m4017a();
    }

    public void setEnableGesture(boolean z) {
        this.f9191g = z;
    }

    public void setScrollThresHold(float f2) {
        if (f2 >= 1.0f || f2 <= 0.0f) {
            throw new IllegalArgumentException("Threshold value should be between 0 and 1.0");
        }
        this.f9188c = f2;
    }

    public void setShadowDrawable(Drawable drawable) {
        this.f9201q = drawable;
    }

    public void setSlideCallback(InterfaceC3255c interfaceC3255c) {
        this.f9194j = interfaceC3255c;
    }

    public void setVelocity(int i2) {
        this.f9204t = i2;
    }
}
