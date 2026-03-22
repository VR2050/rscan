package p005b.p340x.p354b.p355a.p358d;

import android.animation.ValueAnimator;
import android.graphics.PointF;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.NestedScrollingChild;
import androidx.core.view.NestedScrollingParent;
import androidx.legacy.widget.Space;
import androidx.viewpager.widget.ViewPager;
import com.google.android.material.appbar.AppBarLayout;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import java.util.LinkedList;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2895d;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2899h;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2901j;
import p005b.p340x.p354b.p355a.p360f.InterfaceC2910a;
import p005b.p340x.p354b.p355a.p361g.C2916a;
import p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b;

/* renamed from: b.x.b.a.d.a */
/* loaded from: classes2.dex */
public class C2905a implements InterfaceC2895d, InterfaceC2910a, ValueAnimator.AnimatorUpdateListener {

    /* renamed from: c */
    public View f7962c;

    /* renamed from: e */
    public View f7963e;

    /* renamed from: f */
    public View f7964f;

    /* renamed from: g */
    public View f7965g;

    /* renamed from: h */
    public View f7966h;

    /* renamed from: i */
    public int f7967i = 0;

    /* renamed from: j */
    public boolean f7968j = true;

    /* renamed from: k */
    public boolean f7969k = true;

    /* renamed from: l */
    public C2906b f7970l = new C2906b();

    public C2905a(@NonNull View view) {
        this.f7964f = view;
        this.f7963e = view;
        this.f7962c = view;
    }

    /* renamed from: a */
    public boolean m3361a() {
        return this.f7969k && this.f7970l.m3368a(this.f7962c);
    }

    /* renamed from: b */
    public boolean m3362b() {
        return this.f7968j && this.f7970l.m3369b(this.f7962c);
    }

    /* renamed from: c */
    public View m3363c(View view, PointF pointF, View view2) {
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            int childCount = viewGroup.getChildCount();
            PointF pointF2 = new PointF();
            while (childCount > 0) {
                childCount--;
                View childAt = viewGroup.getChildAt(childCount);
                if (InterpolatorC2917b.m3385f(viewGroup, childAt, pointF.x, pointF.y, pointF2)) {
                    if (!(childAt instanceof ViewPager) && InterpolatorC2917b.m3383d(childAt)) {
                        return childAt;
                    }
                    pointF.offset(pointF2.x, pointF2.y);
                    View m3363c = m3363c(childAt, pointF, view2);
                    pointF.offset(-pointF2.x, -pointF2.y);
                    return m3363c;
                }
            }
        }
        return view2;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x002e  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0041  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:22:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0048  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0033  */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m3364d(int r6, int r7, int r8) {
        /*
            r5 = this;
            r0 = 1
            r1 = -1
            r2 = 0
            r3 = 0
            if (r7 == r1) goto L21
            android.view.View r4 = r5.f7963e
            android.view.View r7 = r4.findViewById(r7)
            if (r7 == 0) goto L21
            if (r6 <= 0) goto L16
            float r4 = (float) r6
            r7.setTranslationY(r4)
            r7 = 1
            goto L22
        L16:
            float r4 = r7.getTranslationY()
            int r4 = (r4 > r3 ? 1 : (r4 == r3 ? 0 : -1))
            if (r4 <= 0) goto L21
            r7.setTranslationY(r3)
        L21:
            r7 = 0
        L22:
            if (r8 == r1) goto L3e
            android.view.View r1 = r5.f7963e
            android.view.View r8 = r1.findViewById(r8)
            if (r8 == 0) goto L3e
            if (r6 >= 0) goto L33
            float r7 = (float) r6
            r8.setTranslationY(r7)
            goto L3f
        L33:
            float r0 = r8.getTranslationY()
            int r0 = (r0 > r3 ? 1 : (r0 == r3 ? 0 : -1))
            if (r0 >= 0) goto L3e
            r8.setTranslationY(r3)
        L3e:
            r0 = r7
        L3f:
            if (r0 != 0) goto L48
            android.view.View r7 = r5.f7963e
            float r8 = (float) r6
            r7.setTranslationY(r8)
            goto L4d
        L48:
            android.view.View r7 = r5.f7963e
            r7.setTranslationY(r3)
        L4d:
            android.view.View r7 = r5.f7965g
            if (r7 == 0) goto L59
            int r8 = java.lang.Math.max(r2, r6)
            float r8 = (float) r8
            r7.setTranslationY(r8)
        L59:
            android.view.View r7 = r5.f7966h
            if (r7 == 0) goto L65
            int r6 = java.lang.Math.min(r2, r6)
            float r6 = (float) r6
            r7.setTranslationY(r6)
        L65:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p340x.p354b.p355a.p358d.C2905a.m3364d(int, int, int):void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:6:0x000f, code lost:
    
        if (r0.canScrollVertically(1) == false) goto L8;
     */
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.animation.ValueAnimator.AnimatorUpdateListener m3365e(int r4) {
        /*
            r3 = this;
            android.view.View r0 = r3.f7964f
            if (r0 == 0) goto L21
            if (r4 == 0) goto L21
            if (r4 >= 0) goto L11
            r1 = 1
            float r2 = p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b.f7984a
            boolean r0 = r0.canScrollVertically(r1)
            if (r0 != 0) goto L1e
        L11:
            if (r4 <= 0) goto L21
            android.view.View r0 = r3.f7964f
            r1 = -1
            float r2 = p005b.p340x.p354b.p355a.p361g.InterpolatorC2917b.f7984a
            boolean r0 = r0.canScrollVertically(r1)
            if (r0 == 0) goto L21
        L1e:
            r3.f7967i = r4
            return r3
        L21:
            r4 = 0
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p340x.p354b.p355a.p358d.C2905a.m3365e(int):android.animation.ValueAnimator$AnimatorUpdateListener");
    }

    /* renamed from: f */
    public void m3366f(InterfaceC2901j interfaceC2901j) {
        if (interfaceC2901j instanceof C2906b) {
            this.f7970l = (C2906b) interfaceC2901j;
        } else {
            this.f7970l.f7972b = interfaceC2901j;
        }
    }

    /* renamed from: g */
    public void m3367g(InterfaceC2899h interfaceC2899h, View view, View view2) {
        View view3 = this.f7962c;
        boolean isInEditMode = view3.isInEditMode();
        View view4 = null;
        while (true) {
            if (view4 != null && (!(view4 instanceof NestedScrollingParent) || (view4 instanceof NestedScrollingChild))) {
                break;
            }
            boolean z = view4 == null;
            LinkedList linkedList = new LinkedList();
            linkedList.add(view3);
            View view5 = null;
            while (linkedList.size() > 0 && view5 == null) {
                View view6 = (View) linkedList.poll();
                if (view6 != null) {
                    if ((z || view6 != view3) && InterpolatorC2917b.m3383d(view6)) {
                        view5 = view6;
                    } else if (view6 instanceof ViewGroup) {
                        ViewGroup viewGroup = (ViewGroup) view6;
                        for (int i2 = 0; i2 < viewGroup.getChildCount(); i2++) {
                            linkedList.add(viewGroup.getChildAt(i2));
                        }
                    }
                }
            }
            if (view5 == null) {
                view5 = view3;
            }
            if (view5 == view4) {
                break;
            }
            if (!isInEditMode) {
                try {
                    if (view5 instanceof CoordinatorLayout) {
                        SmartRefreshLayout.this.setEnableNestedScroll(false);
                        ViewGroup viewGroup2 = (ViewGroup) view5;
                        int childCount = viewGroup2.getChildCount();
                        while (true) {
                            childCount--;
                            if (childCount >= 0) {
                                View childAt = viewGroup2.getChildAt(childCount);
                                if (childAt instanceof AppBarLayout) {
                                    ((AppBarLayout) childAt).addOnOffsetChangedListener((AppBarLayout.OnOffsetChangedListener) new C2916a(this));
                                }
                            }
                        }
                    }
                } catch (Throwable th) {
                    th.printStackTrace();
                }
            }
            view3 = view5;
            view4 = view3;
        }
        if (view4 != null) {
            this.f7964f = view4;
        }
        if (view == null && view2 == null) {
            return;
        }
        this.f7965g = view;
        this.f7966h = view2;
        FrameLayout frameLayout = new FrameLayout(this.f7962c.getContext());
        int indexOfChild = SmartRefreshLayout.this.getLayout().indexOfChild(this.f7962c);
        SmartRefreshLayout.C4087m c4087m = (SmartRefreshLayout.C4087m) interfaceC2899h;
        SmartRefreshLayout.this.getLayout().removeView(this.f7962c);
        frameLayout.addView(this.f7962c, 0, new ViewGroup.LayoutParams(-1, -1));
        SmartRefreshLayout.this.getLayout().addView(frameLayout, indexOfChild, this.f7962c.getLayoutParams());
        this.f7962c = frameLayout;
        if (view != null) {
            view.setTag("fixed-top");
            ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
            ViewGroup viewGroup3 = (ViewGroup) view.getParent();
            int indexOfChild2 = viewGroup3.indexOfChild(view);
            viewGroup3.removeView(view);
            layoutParams.height = InterpolatorC2917b.m3386g(view);
            viewGroup3.addView(new Space(this.f7962c.getContext()), indexOfChild2, layoutParams);
            frameLayout.addView(view, 1, layoutParams);
        }
        if (view2 != null) {
            view2.setTag("fixed-bottom");
            ViewGroup.LayoutParams layoutParams2 = view2.getLayoutParams();
            ViewGroup viewGroup4 = (ViewGroup) view2.getParent();
            int indexOfChild3 = viewGroup4.indexOfChild(view2);
            viewGroup4.removeView(view2);
            FrameLayout.LayoutParams layoutParams3 = new FrameLayout.LayoutParams(layoutParams2);
            layoutParams2.height = InterpolatorC2917b.m3386g(view2);
            viewGroup4.addView(new Space(this.f7962c.getContext()), indexOfChild3, layoutParams2);
            layoutParams3.gravity = 80;
            frameLayout.addView(view2, 1, layoutParams3);
        }
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator valueAnimator) {
        int intValue = ((Integer) valueAnimator.getAnimatedValue()).intValue();
        try {
            float scaleY = (intValue - this.f7967i) * this.f7964f.getScaleY();
            View view = this.f7964f;
            if (view instanceof AbsListView) {
                float f2 = InterpolatorC2917b.f7984a;
                ((AbsListView) view).scrollListBy((int) scaleY);
            } else {
                view.scrollBy(0, (int) scaleY);
            }
        } catch (Throwable th) {
            th.printStackTrace();
        }
        this.f7967i = intValue;
    }
}
