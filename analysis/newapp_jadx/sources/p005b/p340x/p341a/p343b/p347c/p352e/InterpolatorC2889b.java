package p005b.p340x.p341a.p343b.p347c.p352e;

import android.content.res.Resources;
import android.graphics.PointF;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Interpolator;
import android.webkit.WebView;
import android.widget.AbsListView;
import android.widget.ScrollView;
import androidx.annotation.NonNull;
import androidx.core.view.NestedScrollingChild;
import androidx.core.view.NestedScrollingParent;
import androidx.core.view.ScrollingView;
import androidx.viewpager.widget.ViewPager;
import com.scwang.smart.refresh.layout.kernel.R$id;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a;

/* renamed from: b.x.a.b.c.e.b */
/* loaded from: classes2.dex */
public class InterpolatorC2889b implements Interpolator {

    /* renamed from: a */
    public static float f7900a = Resources.getSystem().getDisplayMetrics().density;

    /* renamed from: b */
    public static final float f7901b;

    /* renamed from: c */
    public static final float f7902c;

    static {
        float m3338h = 1.0f / m3338h(1.0f);
        f7901b = m3338h;
        f7902c = 1.0f - (m3338h(1.0f) * m3338h);
    }

    public InterpolatorC2889b(int i2) {
    }

    /* renamed from: a */
    public static boolean m3331a(@NonNull View view, PointF pointF, boolean z) {
        if (view.canScrollVertically(1) && view.getVisibility() == 0) {
            return false;
        }
        if ((view instanceof ViewGroup) && pointF != null && !m3335e(view)) {
            ViewGroup viewGroup = (ViewGroup) view;
            PointF pointF2 = new PointF();
            for (int childCount = viewGroup.getChildCount(); childCount > 0; childCount--) {
                View childAt = viewGroup.getChildAt(childCount - 1);
                if (m3336f(viewGroup, childAt, pointF.x, pointF.y, pointF2)) {
                    Object tag = childAt.getTag(R$id.srl_tag);
                    if ("fixed".equals(tag) || "fixed-top".equals(tag)) {
                        return false;
                    }
                    pointF.offset(pointF2.x, pointF2.y);
                    boolean m3331a = m3331a(childAt, pointF, z);
                    pointF.offset(-pointF2.x, -pointF2.y);
                    return m3331a;
                }
            }
        }
        return z || view.canScrollVertically(-1);
    }

    /* renamed from: b */
    public static boolean m3332b(@NonNull View view, PointF pointF) {
        if (view.canScrollVertically(-1) && view.getVisibility() == 0) {
            return false;
        }
        if (!(view instanceof ViewGroup) || pointF == null) {
            return true;
        }
        ViewGroup viewGroup = (ViewGroup) view;
        PointF pointF2 = new PointF();
        for (int childCount = viewGroup.getChildCount(); childCount > 0; childCount--) {
            View childAt = viewGroup.getChildAt(childCount - 1);
            if (m3336f(viewGroup, childAt, pointF.x, pointF.y, pointF2)) {
                Object tag = childAt.getTag(R$id.srl_tag);
                if ("fixed".equals(tag) || "fixed-bottom".equals(tag)) {
                    return false;
                }
                pointF.offset(pointF2.x, pointF2.y);
                boolean m3332b = m3332b(childAt, pointF);
                pointF.offset(-pointF2.x, -pointF2.y);
                return m3332b;
            }
        }
        return true;
    }

    /* renamed from: c */
    public static int m3333c(float f2) {
        return (int) ((f2 * f7900a) + 0.5f);
    }

    /* renamed from: d */
    public static boolean m3334d(View view) {
        if (view instanceof InterfaceC2871a) {
            return false;
        }
        return m3335e(view) || (view instanceof ViewPager) || (view instanceof NestedScrollingParent);
    }

    /* renamed from: e */
    public static boolean m3335e(View view) {
        if (view instanceof InterfaceC2871a) {
            return false;
        }
        return (view instanceof AbsListView) || (view instanceof ScrollView) || (view instanceof ScrollingView) || (view instanceof WebView) || (view instanceof NestedScrollingChild);
    }

    /* renamed from: f */
    public static boolean m3336f(@NonNull View view, @NonNull View view2, float f2, float f3, PointF pointF) {
        if (view2.getVisibility() != 0) {
            return false;
        }
        float[] fArr = {f2, f3};
        fArr[0] = fArr[0] + (view.getScrollX() - view2.getLeft());
        fArr[1] = fArr[1] + (view.getScrollY() - view2.getTop());
        boolean z = fArr[0] >= 0.0f && fArr[1] >= 0.0f && fArr[0] < ((float) view2.getWidth()) && fArr[1] < ((float) view2.getHeight());
        if (z) {
            pointF.set(fArr[0] - f2, fArr[1] - f3);
        }
        return z;
    }

    /* renamed from: g */
    public static int m3337g(View view) {
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (layoutParams == null) {
            layoutParams = new ViewGroup.LayoutParams(-1, -2);
        }
        int childMeasureSpec = ViewGroup.getChildMeasureSpec(0, 0, layoutParams.width);
        int i2 = layoutParams.height;
        view.measure(childMeasureSpec, i2 > 0 ? View.MeasureSpec.makeMeasureSpec(i2, 1073741824) : View.MeasureSpec.makeMeasureSpec(0, 0));
        return view.getMeasuredHeight();
    }

    /* renamed from: h */
    public static float m3338h(float f2) {
        float f3 = f2 * 8.0f;
        return f3 < 1.0f ? f3 - (1.0f - ((float) Math.exp(-f3))) : C1499a.m627m(1.0f, (float) Math.exp(1.0f - f3), 0.63212055f, 0.36787945f);
    }

    @Override // android.animation.TimeInterpolator
    public float getInterpolation(float f2) {
        float m3338h = m3338h(f2) * f7901b;
        return m3338h > 0.0f ? m3338h + f7902c : m3338h;
    }
}
