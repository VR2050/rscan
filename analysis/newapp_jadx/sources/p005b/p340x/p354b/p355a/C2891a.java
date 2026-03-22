package p005b.p340x.p354b.p355a;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import p005b.p340x.p354b.p355a.p357c.EnumC2903b;

/* renamed from: b.x.b.a.a */
/* loaded from: classes2.dex */
public class C2891a extends AnimatorListenerAdapter {

    /* renamed from: c */
    public final /* synthetic */ SmartRefreshLayout.C4087m f7912c;

    public C2891a(SmartRefreshLayout.C4087m c4087m) {
        this.f7912c = c4087m;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationEnd(Animator animator) {
        ((SmartRefreshLayout.C4087m) SmartRefreshLayout.this.mKernel).m4627d(EnumC2903b.TwoLevel);
    }
}
