package p005b.p340x.p341a.p343b.p347c.p353f;

import android.animation.ValueAnimator;
import android.graphics.PointF;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.FrameLayout;
import android.widget.Space;
import androidx.annotation.NonNull;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.NestedScrollingChild;
import androidx.core.view.NestedScrollingParent;
import androidx.viewpager.widget.ViewPager;
import com.google.android.material.appbar.AppBarLayout;
import com.scwang.smart.refresh.layout.SmartRefreshLayout;
import com.scwang.smart.refresh.layout.kernel.R$id;
import java.util.LinkedList;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2872b;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2875e;
import p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2880a;
import p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2886g;
import p005b.p340x.p341a.p343b.p347c.p351d.C2887a;
import p005b.p340x.p341a.p343b.p347c.p352e.C2888a;
import p005b.p340x.p341a.p343b.p347c.p352e.InterpolatorC2889b;

/* renamed from: b.x.a.b.c.f.a */
/* loaded from: classes2.dex */
public class C2890a implements InterfaceC2872b, InterfaceC2880a, ValueAnimator.AnimatorUpdateListener {

    /* renamed from: c */
    public View f7903c;

    /* renamed from: e */
    public View f7904e;

    /* renamed from: f */
    public View f7905f;

    /* renamed from: g */
    public View f7906g;

    /* renamed from: h */
    public View f7907h;

    /* renamed from: i */
    public int f7908i = 0;

    /* renamed from: j */
    public boolean f7909j = true;

    /* renamed from: k */
    public boolean f7910k = true;

    /* renamed from: l */
    public C2887a f7911l = new C2887a();

    public C2890a(@NonNull View view) {
        this.f7905f = view;
        this.f7904e = view;
        this.f7903c = view;
    }

    /* renamed from: a */
    public boolean m3339a() {
        return this.f7910k && this.f7911l.mo3330b(this.f7903c);
    }

    /* renamed from: b */
    public boolean m3340b() {
        return this.f7909j && this.f7911l.mo3329a(this.f7903c);
    }

    /* renamed from: c */
    public View m3341c(View view, PointF pointF, View view2) {
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            int childCount = viewGroup.getChildCount();
            PointF pointF2 = new PointF();
            while (childCount > 0) {
                childCount--;
                View childAt = viewGroup.getChildAt(childCount);
                if (InterpolatorC2889b.m3336f(viewGroup, childAt, pointF.x, pointF.y, pointF2)) {
                    if (!(childAt instanceof ViewPager) && InterpolatorC2889b.m3334d(childAt)) {
                        return childAt;
                    }
                    pointF.offset(pointF2.x, pointF2.y);
                    View m3341c = m3341c(childAt, pointF, view2);
                    pointF.offset(-pointF2.x, -pointF2.y);
                    return m3341c;
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
    public void m3342d(int r6, int r7, int r8) {
        /*
            r5 = this;
            r0 = 1
            r1 = -1
            r2 = 0
            r3 = 0
            if (r7 == r1) goto L21
            android.view.View r4 = r5.f7904e
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
            android.view.View r1 = r5.f7904e
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
            android.view.View r7 = r5.f7904e
            float r8 = (float) r6
            r7.setTranslationY(r8)
            goto L4d
        L48:
            android.view.View r7 = r5.f7904e
            r7.setTranslationY(r3)
        L4d:
            android.view.View r7 = r5.f7906g
            if (r7 == 0) goto L59
            int r8 = java.lang.Math.max(r2, r6)
            float r8 = (float) r8
            r7.setTranslationY(r8)
        L59:
            android.view.View r7 = r5.f7907h
            if (r7 == 0) goto L65
            int r6 = java.lang.Math.min(r2, r6)
            float r6 = (float) r6
            r7.setTranslationY(r6)
        L65:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p340x.p341a.p343b.p347c.p353f.C2890a.m3342d(int, int, int):void");
    }

    /* renamed from: e */
    public ValueAnimator.AnimatorUpdateListener m3343e(int i2) {
        View view = this.f7905f;
        if (view == null || i2 == 0) {
            return null;
        }
        if ((i2 >= 0 || !view.canScrollVertically(1)) && (i2 <= 0 || !this.f7905f.canScrollVertically(-1))) {
            return null;
        }
        this.f7908i = i2;
        return this;
    }

    /* renamed from: f */
    public void m3344f(InterfaceC2886g interfaceC2886g) {
        if (interfaceC2886g instanceof C2887a) {
            this.f7911l = (C2887a) interfaceC2886g;
        } else {
            this.f7911l.f7897b = interfaceC2886g;
        }
    }

    /* renamed from: g */
    public void m3345g(InterfaceC2875e interfaceC2875e, View view, View view2) {
        View view3 = this.f7903c;
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
                    if ((z || view6 != view3) && InterpolatorC2889b.m3334d(view6)) {
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
                        SmartRefreshLayout.this.setNestedScrollingEnabled(false);
                        ViewGroup viewGroup2 = (ViewGroup) view5;
                        int childCount = viewGroup2.getChildCount();
                        while (true) {
                            childCount--;
                            if (childCount >= 0) {
                                View childAt = viewGroup2.getChildAt(childCount);
                                if (childAt instanceof AppBarLayout) {
                                    ((AppBarLayout) childAt).addOnOffsetChangedListener((AppBarLayout.OnOffsetChangedListener) new C2888a(this));
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
            this.f7905f = view4;
        }
        if (view == null && view2 == null) {
            return;
        }
        this.f7906g = view;
        this.f7907h = view2;
        FrameLayout frameLayout = new FrameLayout(this.f7903c.getContext());
        int indexOfChild = SmartRefreshLayout.this.getLayout().indexOfChild(this.f7903c);
        SmartRefreshLayout.C4074k c4074k = (SmartRefreshLayout.C4074k) interfaceC2875e;
        SmartRefreshLayout.this.getLayout().removeView(this.f7903c);
        frameLayout.addView(this.f7903c, 0, new ViewGroup.LayoutParams(-1, -1));
        SmartRefreshLayout.this.getLayout().addView(frameLayout, indexOfChild, this.f7903c.getLayoutParams());
        this.f7903c = frameLayout;
        if (view != null) {
            view.setTag(R$id.srl_tag, "fixed-top");
            ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
            ViewGroup viewGroup3 = (ViewGroup) view.getParent();
            int indexOfChild2 = viewGroup3.indexOfChild(view);
            viewGroup3.removeView(view);
            layoutParams.height = InterpolatorC2889b.m3337g(view);
            viewGroup3.addView(new Space(this.f7903c.getContext()), indexOfChild2, layoutParams);
            frameLayout.addView(view, 1, layoutParams);
        }
        if (view2 != null) {
            view2.setTag(R$id.srl_tag, "fixed-bottom");
            ViewGroup.LayoutParams layoutParams2 = view2.getLayoutParams();
            ViewGroup viewGroup4 = (ViewGroup) view2.getParent();
            int indexOfChild3 = viewGroup4.indexOfChild(view2);
            viewGroup4.removeView(view2);
            FrameLayout.LayoutParams layoutParams3 = new FrameLayout.LayoutParams(layoutParams2);
            layoutParams2.height = InterpolatorC2889b.m3337g(view2);
            viewGroup4.addView(new Space(this.f7903c.getContext()), indexOfChild3, layoutParams2);
            layoutParams3.gravity = 80;
            frameLayout.addView(view2, 1, layoutParams3);
        }
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator valueAnimator) {
        int intValue = ((Integer) valueAnimator.getAnimatedValue()).intValue();
        try {
            float scaleY = (intValue - this.f7908i) * this.f7905f.getScaleY();
            View view = this.f7905f;
            if (view instanceof AbsListView) {
                float f2 = InterpolatorC2889b.f7900a;
                ((AbsListView) view).scrollListBy((int) scaleY);
            } else {
                view.scrollBy(0, (int) scaleY);
            }
        } catch (Throwable th) {
            th.printStackTrace();
        }
        this.f7908i = intValue;
    }
}
