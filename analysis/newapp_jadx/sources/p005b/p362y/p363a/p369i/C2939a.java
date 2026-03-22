package p005b.p362y.p363a.p369i;

import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import com.shuyu.gsyvideoplayer.utils.GSYVideoType;
import p005b.p362y.p363a.p369i.p372d.InterfaceC2944a;

/* renamed from: b.y.a.i.a */
/* loaded from: classes2.dex */
public class C2939a {

    /* renamed from: a */
    public InterfaceC2944a f8046a;

    /* renamed from: a */
    public static void m3404a(ViewGroup viewGroup, View view) {
        int i2 = GSYVideoType.getShowType() != 0 ? -2 : -1;
        if (viewGroup instanceof RelativeLayout) {
            RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(i2, i2);
            layoutParams.addRule(13);
            viewGroup.addView(view, layoutParams);
        } else if (viewGroup instanceof FrameLayout) {
            FrameLayout.LayoutParams layoutParams2 = new FrameLayout.LayoutParams(i2, i2);
            layoutParams2.gravity = 17;
            viewGroup.addView(view, layoutParams2);
        }
    }
}
