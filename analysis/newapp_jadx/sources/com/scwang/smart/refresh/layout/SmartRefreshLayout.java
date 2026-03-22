package com.scwang.smart.refresh.layout;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Handler;
import android.os.Looper;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.animation.AnimationUtils;
import android.view.animation.Interpolator;
import android.webkit.WebView;
import android.widget.AbsListView;
import android.widget.ImageView;
import android.widget.ScrollView;
import android.widget.Scroller;
import android.widget.TextView;
import android.widget.Toast;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.view.NestedScrollingChildHelper;
import androidx.core.view.NestedScrollingParent;
import androidx.core.view.NestedScrollingParentHelper;
import androidx.core.view.ViewCompat;
import androidx.core.widget.NestedScrollView;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.MyApp;
import com.qnmd.adnnm.da0yzo.R;
import com.scwang.smart.refresh.footer.ClassicsFooter;
import com.scwang.smart.refresh.header.ClassicsHeader;
import com.scwang.smart.refresh.layout.kernel.R$id;
import com.scwang.smart.refresh.layout.kernel.R$string;
import com.scwang.smart.refresh.layout.kernel.R$styleable;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;
import p005b.p006a.p007a.p008a.C0881d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2872b;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2873c;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2874d;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2875e;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2876f;
import p005b.p340x.p341a.p343b.p347c.p349b.C2877a;
import p005b.p340x.p341a.p343b.p347c.p349b.C2879c;
import p005b.p340x.p341a.p343b.p347c.p349b.EnumC2878b;
import p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2881b;
import p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2882c;
import p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2883d;
import p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2884e;
import p005b.p340x.p341a.p343b.p347c.p350c.InterfaceC2886g;
import p005b.p340x.p341a.p343b.p347c.p352e.InterpolatorC2889b;
import p005b.p340x.p341a.p343b.p347c.p353f.C2890a;
import tv.danmaku.ijk.media.player.IjkMediaCodecInfo;

@SuppressLint({"RestrictedApi"})
/* loaded from: classes2.dex */
public class SmartRefreshLayout extends ViewGroup implements InterfaceC2876f, NestedScrollingParent {

    /* renamed from: c */
    public static InterfaceC2881b f10502c;

    /* renamed from: e */
    public static InterfaceC2882c f10503e;

    /* renamed from: f */
    public static InterfaceC2883d f10504f;

    /* renamed from: g */
    public static ViewGroup.MarginLayoutParams f10505g = new ViewGroup.MarginLayoutParams(-1, -1);

    /* renamed from: A */
    public int f10506A;

    /* renamed from: A0 */
    public float f10507A0;

    /* renamed from: B */
    public int f10508B;

    /* renamed from: B0 */
    public InterfaceC2871a f10509B0;

    /* renamed from: C */
    public int f10510C;

    /* renamed from: C0 */
    public InterfaceC2871a f10511C0;

    /* renamed from: D */
    public int f10512D;

    /* renamed from: D0 */
    public InterfaceC2872b f10513D0;

    /* renamed from: E */
    public Scroller f10514E;

    /* renamed from: E0 */
    public Paint f10515E0;

    /* renamed from: F */
    public VelocityTracker f10516F;

    /* renamed from: F0 */
    public Handler f10517F0;

    /* renamed from: G */
    public Interpolator f10518G;

    /* renamed from: G0 */
    public InterfaceC2875e f10519G0;

    /* renamed from: H */
    public int[] f10520H;

    /* renamed from: H0 */
    public EnumC2878b f10521H0;

    /* renamed from: I */
    public boolean f10522I;

    /* renamed from: I0 */
    public EnumC2878b f10523I0;

    /* renamed from: J */
    public boolean f10524J;

    /* renamed from: J0 */
    public long f10525J0;

    /* renamed from: K */
    public boolean f10526K;

    /* renamed from: K0 */
    public int f10527K0;

    /* renamed from: L */
    public boolean f10528L;

    /* renamed from: L0 */
    public int f10529L0;

    /* renamed from: M */
    public boolean f10530M;

    /* renamed from: M0 */
    public boolean f10531M0;

    /* renamed from: N */
    public boolean f10532N;

    /* renamed from: N0 */
    public boolean f10533N0;

    /* renamed from: O */
    public boolean f10534O;

    /* renamed from: O0 */
    public boolean f10535O0;

    /* renamed from: P */
    public boolean f10536P;

    /* renamed from: P0 */
    public MotionEvent f10537P0;

    /* renamed from: Q */
    public boolean f10538Q;

    /* renamed from: Q0 */
    public Runnable f10539Q0;

    /* renamed from: R */
    public boolean f10540R;

    /* renamed from: R0 */
    public ValueAnimator f10541R0;

    /* renamed from: S */
    public boolean f10542S;

    /* renamed from: T */
    public boolean f10543T;

    /* renamed from: U */
    public boolean f10544U;

    /* renamed from: V */
    public boolean f10545V;

    /* renamed from: W */
    public boolean f10546W;

    /* renamed from: a0 */
    public boolean f10547a0;

    /* renamed from: b0 */
    public boolean f10548b0;

    /* renamed from: c0 */
    public boolean f10549c0;

    /* renamed from: d0 */
    public boolean f10550d0;

    /* renamed from: e0 */
    public boolean f10551e0;

    /* renamed from: f0 */
    public boolean f10552f0;

    /* renamed from: g0 */
    public boolean f10553g0;

    /* renamed from: h */
    public int f10554h;

    /* renamed from: h0 */
    public boolean f10555h0;

    /* renamed from: i */
    public int f10556i;

    /* renamed from: i0 */
    public InterfaceC2884e f10557i0;

    /* renamed from: j */
    public int f10558j;

    /* renamed from: j0 */
    public InterfaceC2884e f10559j0;

    /* renamed from: k */
    public int f10560k;

    /* renamed from: k0 */
    public InterfaceC2886g f10561k0;

    /* renamed from: l */
    public int f10562l;

    /* renamed from: l0 */
    public int f10563l0;

    /* renamed from: m */
    public int f10564m;

    /* renamed from: m0 */
    public boolean f10565m0;

    /* renamed from: n */
    public int f10566n;

    /* renamed from: n0 */
    public int[] f10567n0;

    /* renamed from: o */
    public float f10568o;

    /* renamed from: o0 */
    public NestedScrollingChildHelper f10569o0;

    /* renamed from: p */
    public float f10570p;

    /* renamed from: p0 */
    public NestedScrollingParentHelper f10571p0;

    /* renamed from: q */
    public float f10572q;

    /* renamed from: q0 */
    public int f10573q0;

    /* renamed from: r */
    public float f10574r;

    /* renamed from: r0 */
    public C2877a f10575r0;

    /* renamed from: s */
    public float f10576s;

    /* renamed from: s0 */
    public int f10577s0;

    /* renamed from: t */
    public char f10578t;

    /* renamed from: t0 */
    public C2877a f10579t0;

    /* renamed from: u */
    public boolean f10580u;

    /* renamed from: u0 */
    public int f10581u0;

    /* renamed from: v */
    public boolean f10582v;

    /* renamed from: v0 */
    public int f10583v0;

    /* renamed from: w */
    public boolean f10584w;

    /* renamed from: w0 */
    public float f10585w0;

    /* renamed from: x */
    public int f10586x;

    /* renamed from: x0 */
    public float f10587x0;

    /* renamed from: y */
    public int f10588y;

    /* renamed from: y0 */
    public float f10589y0;

    /* renamed from: z */
    public int f10590z;

    /* renamed from: z0 */
    public float f10591z0;

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$a */
    public class C4064a extends AnimatorListenerAdapter {

        /* renamed from: c */
        public final /* synthetic */ boolean f10592c;

        public C4064a(boolean z) {
            this.f10592c = z;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            if (animator == null || animator.getDuration() != 0) {
                SmartRefreshLayout.this.setStateDirectLoading(this.f10592c);
            }
        }
    }

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$b */
    public class C4065b extends AnimatorListenerAdapter {

        /* renamed from: c */
        public final /* synthetic */ boolean f10594c;

        public C4065b(boolean z) {
            this.f10594c = z;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            if (animator == null || animator.getDuration() != 0) {
                SmartRefreshLayout.this.f10525J0 = System.currentTimeMillis();
                SmartRefreshLayout.this.m4614s(EnumC2878b.Refreshing);
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                InterfaceC2884e interfaceC2884e = smartRefreshLayout.f10557i0;
                if (interfaceC2884e == null) {
                    Objects.requireNonNull(smartRefreshLayout);
                    SmartRefreshLayout.this.mo3957m(3000, true, Boolean.FALSE);
                } else if (this.f10594c) {
                    interfaceC2884e.mo3326a(smartRefreshLayout);
                }
                SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                InterfaceC2871a interfaceC2871a = smartRefreshLayout2.f10509B0;
                if (interfaceC2871a != null) {
                    float f2 = smartRefreshLayout2.f10585w0;
                    if (f2 < 10.0f) {
                        f2 *= smartRefreshLayout2.f10573q0;
                    }
                    interfaceC2871a.mo3320i(smartRefreshLayout2, smartRefreshLayout2.f10573q0, (int) f2);
                }
                Objects.requireNonNull(SmartRefreshLayout.this);
            }
        }
    }

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$c */
    public class C4066c extends AnimatorListenerAdapter {
        public C4066c() {
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            EnumC2878b enumC2878b;
            EnumC2878b enumC2878b2;
            if (animator == null || animator.getDuration() != 0) {
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                smartRefreshLayout.f10541R0 = null;
                if (smartRefreshLayout.f10556i == 0 && (enumC2878b = smartRefreshLayout.f10521H0) != (enumC2878b2 = EnumC2878b.None) && !enumC2878b.f7886z && !enumC2878b.f7885y) {
                    smartRefreshLayout.m4614s(enumC2878b2);
                    return;
                }
                EnumC2878b enumC2878b3 = smartRefreshLayout.f10521H0;
                if (enumC2878b3 != smartRefreshLayout.f10523I0) {
                    smartRefreshLayout.setViceState(enumC2878b3);
                }
            }
        }
    }

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$d */
    public class C4067d implements ValueAnimator.AnimatorUpdateListener {
        public C4067d() {
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            ((C4074k) SmartRefreshLayout.this.f10519G0).m4621b(((Integer) valueAnimator.getAnimatedValue()).intValue(), false);
        }
    }

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$e */
    public class RunnableC4068e implements Runnable {
        public RunnableC4068e() {
        }

        @Override // java.lang.Runnable
        public void run() {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            InterfaceC2884e interfaceC2884e = smartRefreshLayout.f10559j0;
            if (interfaceC2884e != null) {
                interfaceC2884e.mo3327b(smartRefreshLayout);
            } else {
                smartRefreshLayout.mo3956k(2000, true, false);
            }
            Objects.requireNonNull(SmartRefreshLayout.this);
        }
    }

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$f */
    public class RunnableC4069f implements Runnable {

        /* renamed from: c */
        public int f10599c = 0;

        /* renamed from: e */
        public final /* synthetic */ int f10600e;

        /* renamed from: f */
        public final /* synthetic */ Boolean f10601f;

        /* renamed from: g */
        public final /* synthetic */ boolean f10602g;

        public RunnableC4069f(int i2, Boolean bool, boolean z) {
            this.f10600e = i2;
            this.f10601f = bool;
            this.f10602g = z;
        }

        @Override // java.lang.Runnable
        public void run() {
            int i2 = this.f10599c;
            ValueAnimator.AnimatorUpdateListener animatorUpdateListener = null;
            if (i2 == 0) {
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                EnumC2878b enumC2878b = smartRefreshLayout.f10521H0;
                EnumC2878b enumC2878b2 = EnumC2878b.None;
                if (enumC2878b == enumC2878b2 && smartRefreshLayout.f10523I0 == EnumC2878b.Refreshing) {
                    smartRefreshLayout.f10523I0 = enumC2878b2;
                } else {
                    ValueAnimator valueAnimator = smartRefreshLayout.f10541R0;
                    if (valueAnimator != null && enumC2878b.f7882v && (enumC2878b.f7885y || enumC2878b == EnumC2878b.RefreshReleased)) {
                        valueAnimator.setDuration(0L);
                        SmartRefreshLayout.this.f10541R0.cancel();
                        SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                        smartRefreshLayout2.f10541R0 = null;
                        if (((C4074k) smartRefreshLayout2.f10519G0).m4620a(0) == null) {
                            SmartRefreshLayout.this.m4614s(enumC2878b2);
                        } else {
                            SmartRefreshLayout.this.m4614s(EnumC2878b.PullDownCanceled);
                        }
                    } else if (enumC2878b == EnumC2878b.Refreshing && smartRefreshLayout.f10509B0 != null && smartRefreshLayout.f10513D0 != null) {
                        this.f10599c = i2 + 1;
                        smartRefreshLayout.f10517F0.postDelayed(this, this.f10600e);
                        SmartRefreshLayout.this.m4614s(EnumC2878b.RefreshFinish);
                        if (this.f10601f == Boolean.FALSE) {
                            SmartRefreshLayout.this.mo3958v(false);
                        }
                    }
                }
                if (this.f10601f == Boolean.TRUE) {
                    SmartRefreshLayout.this.mo3958v(true);
                    return;
                }
                return;
            }
            SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
            int mo3318f = smartRefreshLayout3.f10509B0.mo3318f(smartRefreshLayout3, this.f10602g);
            Objects.requireNonNull(SmartRefreshLayout.this);
            if (mo3318f < Integer.MAX_VALUE) {
                SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
                if (smartRefreshLayout4.f10580u || smartRefreshLayout4.f10565m0) {
                    long currentTimeMillis = System.currentTimeMillis();
                    SmartRefreshLayout smartRefreshLayout5 = SmartRefreshLayout.this;
                    if (smartRefreshLayout5.f10580u) {
                        float f2 = smartRefreshLayout5.f10574r;
                        smartRefreshLayout5.f10570p = f2;
                        smartRefreshLayout5.f10560k = 0;
                        smartRefreshLayout5.f10580u = false;
                        SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(currentTimeMillis, currentTimeMillis, 0, smartRefreshLayout5.f10572q, (f2 + smartRefreshLayout5.f10556i) - (smartRefreshLayout5.f10554h * 2), 0));
                        SmartRefreshLayout smartRefreshLayout6 = SmartRefreshLayout.this;
                        SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(currentTimeMillis, currentTimeMillis, 2, smartRefreshLayout6.f10572q, smartRefreshLayout6.f10574r + smartRefreshLayout6.f10556i, 0));
                    }
                    SmartRefreshLayout smartRefreshLayout7 = SmartRefreshLayout.this;
                    if (smartRefreshLayout7.f10565m0) {
                        smartRefreshLayout7.f10563l0 = 0;
                        SmartRefreshLayout.super.dispatchTouchEvent(MotionEvent.obtain(currentTimeMillis, currentTimeMillis, 1, smartRefreshLayout7.f10572q, smartRefreshLayout7.f10574r, 0));
                        SmartRefreshLayout smartRefreshLayout8 = SmartRefreshLayout.this;
                        smartRefreshLayout8.f10565m0 = false;
                        smartRefreshLayout8.f10560k = 0;
                    }
                }
                SmartRefreshLayout smartRefreshLayout9 = SmartRefreshLayout.this;
                int i3 = smartRefreshLayout9.f10556i;
                if (i3 <= 0) {
                    if (i3 < 0) {
                        smartRefreshLayout9.m4607j(0, mo3318f, smartRefreshLayout9.f10518G, smartRefreshLayout9.f10564m);
                        return;
                    }
                    ((C4074k) smartRefreshLayout9.f10519G0).m4621b(0, false);
                    ((C4074k) SmartRefreshLayout.this.f10519G0).m4623d(EnumC2878b.None);
                    return;
                }
                ValueAnimator m4607j = smartRefreshLayout9.m4607j(0, mo3318f, smartRefreshLayout9.f10518G, smartRefreshLayout9.f10564m);
                SmartRefreshLayout smartRefreshLayout10 = SmartRefreshLayout.this;
                if (smartRefreshLayout10.f10545V) {
                    animatorUpdateListener = ((C2890a) smartRefreshLayout10.f10513D0).m3343e(smartRefreshLayout10.f10556i);
                }
                if (m4607j == null || animatorUpdateListener == null) {
                    return;
                }
                m4607j.addUpdateListener(animatorUpdateListener);
            }
        }
    }

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$g */
    public class RunnableC4070g implements Runnable {

        /* renamed from: c */
        public int f10604c = 0;

        /* renamed from: e */
        public final /* synthetic */ int f10605e;

        /* renamed from: f */
        public final /* synthetic */ boolean f10606f;

        /* renamed from: g */
        public final /* synthetic */ boolean f10607g;

        /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$g$a */
        public class a implements Runnable {

            /* renamed from: c */
            public final /* synthetic */ int f10609c;

            /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$g$a$a, reason: collision with other inner class name */
            public class C5125a extends AnimatorListenerAdapter {
                public C5125a() {
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animator) {
                    if (animator == null || animator.getDuration() != 0) {
                        RunnableC4070g runnableC4070g = RunnableC4070g.this;
                        SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                        smartRefreshLayout.f10533N0 = false;
                        if (runnableC4070g.f10606f) {
                            smartRefreshLayout.mo3958v(true);
                        }
                        SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                        if (smartRefreshLayout2.f10521H0 == EnumC2878b.LoadFinish) {
                            smartRefreshLayout2.m4614s(EnumC2878b.None);
                        }
                    }
                }
            }

            public a(int i2) {
                this.f10609c = i2;
            }

            @Override // java.lang.Runnable
            public void run() {
                ValueAnimator.AnimatorUpdateListener animatorUpdateListener;
                ValueAnimator valueAnimator;
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                if (!smartRefreshLayout.f10544U || this.f10609c >= 0) {
                    animatorUpdateListener = null;
                } else {
                    animatorUpdateListener = ((C2890a) smartRefreshLayout.f10513D0).m3343e(smartRefreshLayout.f10556i);
                    if (animatorUpdateListener != null) {
                        ((C2890a) animatorUpdateListener).onAnimationUpdate(ValueAnimator.ofInt(0, 0));
                    }
                }
                C5125a c5125a = new C5125a();
                RunnableC4070g runnableC4070g = RunnableC4070g.this;
                SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                int i2 = smartRefreshLayout2.f10556i;
                if (i2 > 0) {
                    valueAnimator = ((C4074k) smartRefreshLayout2.f10519G0).m4620a(0);
                } else {
                    if (animatorUpdateListener != null || i2 == 0) {
                        ValueAnimator valueAnimator2 = smartRefreshLayout2.f10541R0;
                        if (valueAnimator2 != null) {
                            valueAnimator2.setDuration(0L);
                            SmartRefreshLayout.this.f10541R0.cancel();
                            SmartRefreshLayout.this.f10541R0 = null;
                        }
                        ((C4074k) SmartRefreshLayout.this.f10519G0).m4621b(0, false);
                        ((C4074k) SmartRefreshLayout.this.f10519G0).m4623d(EnumC2878b.None);
                    } else if (runnableC4070g.f10606f && smartRefreshLayout2.f10534O) {
                        int i3 = smartRefreshLayout2.f10577s0;
                        if (i2 >= (-i3)) {
                            smartRefreshLayout2.m4614s(EnumC2878b.None);
                        } else {
                            valueAnimator = ((C4074k) smartRefreshLayout2.f10519G0).m4620a(-i3);
                        }
                    } else {
                        valueAnimator = ((C4074k) smartRefreshLayout2.f10519G0).m4620a(0);
                    }
                    valueAnimator = null;
                }
                if (valueAnimator != null) {
                    valueAnimator.addListener(c5125a);
                } else {
                    c5125a.onAnimationEnd(null);
                }
            }
        }

        public RunnableC4070g(int i2, boolean z, boolean z2) {
            this.f10605e = i2;
            this.f10606f = z;
            this.f10607g = z2;
        }

        /* JADX WARN: Code restructure failed: missing block: B:43:0x00a6, code lost:
        
            if (((p005b.p340x.p341a.p343b.p347c.p353f.C2890a) r6.f10513D0).m3339a() != false) goto L44;
         */
        @Override // java.lang.Runnable
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void run() {
            /*
                Method dump skipped, instructions count: 317
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.scwang.smart.refresh.layout.SmartRefreshLayout.RunnableC4070g.run():void");
        }
    }

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$h */
    public class RunnableC4071h implements Runnable {

        /* renamed from: e */
        public int f10613e;

        /* renamed from: h */
        public float f10616h;

        /* renamed from: c */
        public int f10612c = 0;

        /* renamed from: g */
        public float f10615g = 0.0f;

        /* renamed from: f */
        public long f10614f = AnimationUtils.currentAnimationTimeMillis();

        public RunnableC4071h(float f2, int i2) {
            this.f10616h = f2;
            this.f10613e = i2;
            SmartRefreshLayout.this.f10517F0.postDelayed(this, 10);
            if (f2 > 0.0f) {
                ((C4074k) SmartRefreshLayout.this.f10519G0).m4623d(EnumC2878b.PullDownToRefresh);
            } else {
                ((C4074k) SmartRefreshLayout.this.f10519G0).m4623d(EnumC2878b.PullUpToLoad);
            }
        }

        @Override // java.lang.Runnable
        public void run() {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            if (smartRefreshLayout.f10539Q0 != this || smartRefreshLayout.f10521H0.f7880A) {
                return;
            }
            if (Math.abs(smartRefreshLayout.f10556i) < Math.abs(this.f10613e)) {
                double d2 = this.f10616h;
                this.f10612c = this.f10612c + 1;
                this.f10616h = (float) (Math.pow(0.949999988079071d, r4 * 2) * d2);
            } else if (this.f10613e != 0) {
                double d3 = this.f10616h;
                this.f10612c = this.f10612c + 1;
                this.f10616h = (float) (Math.pow(0.44999998807907104d, r4 * 2) * d3);
            } else {
                double d4 = this.f10616h;
                this.f10612c = this.f10612c + 1;
                this.f10616h = (float) (Math.pow(0.8500000238418579d, r4 * 2) * d4);
            }
            long currentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
            float f2 = this.f10616h * (((currentAnimationTimeMillis - this.f10614f) * 1.0f) / 1000.0f);
            if (Math.abs(f2) >= 1.0f) {
                this.f10614f = currentAnimationTimeMillis;
                float f3 = this.f10615g + f2;
                this.f10615g = f3;
                SmartRefreshLayout.this.m4613r(f3);
                SmartRefreshLayout.this.f10517F0.postDelayed(this, 10);
                return;
            }
            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
            EnumC2878b enumC2878b = smartRefreshLayout2.f10523I0;
            boolean z = enumC2878b.f7885y;
            if (z && enumC2878b.f7882v) {
                ((C4074k) smartRefreshLayout2.f10519G0).m4623d(EnumC2878b.PullDownCanceled);
            } else if (z && enumC2878b.f7883w) {
                ((C4074k) smartRefreshLayout2.f10519G0).m4623d(EnumC2878b.PullUpCanceled);
            }
            SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
            smartRefreshLayout3.f10539Q0 = null;
            if (Math.abs(smartRefreshLayout3.f10556i) >= Math.abs(this.f10613e)) {
                int min = Math.min(Math.max((int) (Math.abs(SmartRefreshLayout.this.f10556i - this.f10613e) / InterpolatorC2889b.f7900a), 30), 100) * 10;
                SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
                smartRefreshLayout4.m4607j(this.f10613e, 0, smartRefreshLayout4.f10518G, min);
            }
        }
    }

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$i */
    public class RunnableC4072i implements Runnable {

        /* renamed from: c */
        public int f10618c;

        /* renamed from: e */
        public float f10619e;

        /* renamed from: f */
        public long f10620f = 0;

        /* renamed from: g */
        public long f10621g = AnimationUtils.currentAnimationTimeMillis();

        public RunnableC4072i(float f2) {
            this.f10619e = f2;
            this.f10618c = SmartRefreshLayout.this.f10556i;
        }

        @Override // java.lang.Runnable
        public void run() {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            if (smartRefreshLayout.f10539Q0 != this || smartRefreshLayout.f10521H0.f7880A) {
                return;
            }
            long currentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
            long j2 = currentAnimationTimeMillis - this.f10621g;
            float pow = (float) (Math.pow(0.98f, (currentAnimationTimeMillis - this.f10620f) / (1000.0f / 10)) * this.f10619e);
            this.f10619e = pow;
            float f2 = ((j2 * 1.0f) / 1000.0f) * pow;
            if (Math.abs(f2) <= 1.0f) {
                SmartRefreshLayout.this.f10539Q0 = null;
                return;
            }
            this.f10621g = currentAnimationTimeMillis;
            int i2 = (int) (this.f10618c + f2);
            this.f10618c = i2;
            SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
            if (smartRefreshLayout2.f10556i * i2 > 0) {
                ((C4074k) smartRefreshLayout2.f10519G0).m4621b(i2, true);
                SmartRefreshLayout.this.f10517F0.postDelayed(this, 10);
                return;
            }
            smartRefreshLayout2.f10539Q0 = null;
            ((C4074k) smartRefreshLayout2.f10519G0).m4621b(0, true);
            View view = ((C2890a) SmartRefreshLayout.this.f10513D0).f7905f;
            int i3 = (int) (-this.f10619e);
            float f3 = InterpolatorC2889b.f7900a;
            if (view instanceof ScrollView) {
                ((ScrollView) view).fling(i3);
            } else if (view instanceof AbsListView) {
                ((AbsListView) view).fling(i3);
            } else if (view instanceof WebView) {
                ((WebView) view).flingScroll(0, i3);
            } else if (view instanceof NestedScrollView) {
                ((NestedScrollView) view).fling(i3);
            } else if (view instanceof RecyclerView) {
                ((RecyclerView) view).fling(0, i3);
            }
            SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
            if (!smartRefreshLayout3.f10533N0 || f2 <= 0.0f) {
                return;
            }
            smartRefreshLayout3.f10533N0 = false;
        }
    }

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$k */
    public class C4074k implements InterfaceC2875e {
        public C4074k() {
        }

        /* renamed from: a */
        public ValueAnimator m4620a(int i2) {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            return smartRefreshLayout.m4607j(i2, 0, smartRefreshLayout.f10518G, smartRefreshLayout.f10564m);
        }

        /* JADX WARN: Removed duplicated region for block: B:49:0x00ad  */
        /* JADX WARN: Removed duplicated region for block: B:56:0x00c2  */
        /* renamed from: b */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2875e m4621b(int r17, boolean r18) {
            /*
                Method dump skipped, instructions count: 867
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.scwang.smart.refresh.layout.SmartRefreshLayout.C4074k.m4621b(int, boolean):b.x.a.b.c.a.e");
        }

        /* renamed from: c */
        public InterfaceC2875e m4622c(@NonNull InterfaceC2871a interfaceC2871a, int i2) {
            SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
            if (smartRefreshLayout.f10515E0 == null && i2 != 0) {
                smartRefreshLayout.f10515E0 = new Paint();
            }
            if (interfaceC2871a.equals(SmartRefreshLayout.this.f10509B0)) {
                SmartRefreshLayout.this.f10527K0 = i2;
            } else if (interfaceC2871a.equals(SmartRefreshLayout.this.f10511C0)) {
                SmartRefreshLayout.this.f10529L0 = i2;
            }
            return this;
        }

        /* renamed from: d */
        public InterfaceC2875e m4623d(@NonNull EnumC2878b enumC2878b) {
            switch (enumC2878b) {
                case None:
                    SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                    EnumC2878b enumC2878b2 = smartRefreshLayout.f10521H0;
                    EnumC2878b enumC2878b3 = EnumC2878b.None;
                    if (enumC2878b2 != enumC2878b3 && smartRefreshLayout.f10556i == 0) {
                        smartRefreshLayout.m4614s(enumC2878b3);
                        break;
                    } else if (smartRefreshLayout.f10556i != 0) {
                        m4620a(0);
                        break;
                    }
                    break;
                case PullDownToRefresh:
                    SmartRefreshLayout smartRefreshLayout2 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout2.f10521H0.f7886z && smartRefreshLayout2.m4611p(smartRefreshLayout2.f10522I)) {
                        SmartRefreshLayout.this.m4614s(EnumC2878b.PullDownToRefresh);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2878b.PullDownToRefresh);
                        break;
                    }
                    break;
                case PullUpToLoad:
                    SmartRefreshLayout smartRefreshLayout3 = SmartRefreshLayout.this;
                    if (smartRefreshLayout3.m4611p(smartRefreshLayout3.f10524J)) {
                        SmartRefreshLayout smartRefreshLayout4 = SmartRefreshLayout.this;
                        EnumC2878b enumC2878b4 = smartRefreshLayout4.f10521H0;
                        if (!enumC2878b4.f7886z && !enumC2878b4.f7880A && (!smartRefreshLayout4.f10550d0 || !smartRefreshLayout4.f10534O || !smartRefreshLayout4.f10551e0)) {
                            smartRefreshLayout4.m4614s(EnumC2878b.PullUpToLoad);
                            break;
                        }
                    }
                    SmartRefreshLayout.this.setViceState(EnumC2878b.PullUpToLoad);
                    break;
                case PullDownCanceled:
                    SmartRefreshLayout smartRefreshLayout5 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout5.f10521H0.f7886z && smartRefreshLayout5.m4611p(smartRefreshLayout5.f10522I)) {
                        SmartRefreshLayout.this.m4614s(EnumC2878b.PullDownCanceled);
                        m4623d(EnumC2878b.None);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2878b.PullDownCanceled);
                        break;
                    }
                    break;
                case PullUpCanceled:
                    SmartRefreshLayout smartRefreshLayout6 = SmartRefreshLayout.this;
                    if (smartRefreshLayout6.m4611p(smartRefreshLayout6.f10524J)) {
                        SmartRefreshLayout smartRefreshLayout7 = SmartRefreshLayout.this;
                        if (!smartRefreshLayout7.f10521H0.f7886z && (!smartRefreshLayout7.f10550d0 || !smartRefreshLayout7.f10534O || !smartRefreshLayout7.f10551e0)) {
                            smartRefreshLayout7.m4614s(EnumC2878b.PullUpCanceled);
                            m4623d(EnumC2878b.None);
                            break;
                        }
                    }
                    SmartRefreshLayout.this.setViceState(EnumC2878b.PullUpCanceled);
                    break;
                case ReleaseToRefresh:
                    SmartRefreshLayout smartRefreshLayout8 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout8.f10521H0.f7886z && smartRefreshLayout8.m4611p(smartRefreshLayout8.f10522I)) {
                        SmartRefreshLayout.this.m4614s(EnumC2878b.ReleaseToRefresh);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2878b.ReleaseToRefresh);
                        break;
                    }
                    break;
                case ReleaseToLoad:
                    SmartRefreshLayout smartRefreshLayout9 = SmartRefreshLayout.this;
                    if (smartRefreshLayout9.m4611p(smartRefreshLayout9.f10524J)) {
                        SmartRefreshLayout smartRefreshLayout10 = SmartRefreshLayout.this;
                        EnumC2878b enumC2878b5 = smartRefreshLayout10.f10521H0;
                        if (!enumC2878b5.f7886z && !enumC2878b5.f7880A && (!smartRefreshLayout10.f10550d0 || !smartRefreshLayout10.f10534O || !smartRefreshLayout10.f10551e0)) {
                            smartRefreshLayout10.m4614s(EnumC2878b.ReleaseToLoad);
                            break;
                        }
                    }
                    SmartRefreshLayout.this.setViceState(EnumC2878b.ReleaseToLoad);
                    break;
                case ReleaseToTwoLevel:
                    SmartRefreshLayout smartRefreshLayout11 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout11.f10521H0.f7886z && smartRefreshLayout11.m4611p(smartRefreshLayout11.f10522I)) {
                        SmartRefreshLayout.this.m4614s(EnumC2878b.ReleaseToTwoLevel);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2878b.ReleaseToTwoLevel);
                        break;
                    }
                    break;
                case TwoLevelReleased:
                default:
                    SmartRefreshLayout.this.m4614s(enumC2878b);
                    break;
                case RefreshReleased:
                    SmartRefreshLayout smartRefreshLayout12 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout12.f10521H0.f7886z && smartRefreshLayout12.m4611p(smartRefreshLayout12.f10522I)) {
                        SmartRefreshLayout.this.m4614s(EnumC2878b.RefreshReleased);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2878b.RefreshReleased);
                        break;
                    }
                    break;
                case LoadReleased:
                    SmartRefreshLayout smartRefreshLayout13 = SmartRefreshLayout.this;
                    if (!smartRefreshLayout13.f10521H0.f7886z && smartRefreshLayout13.m4611p(smartRefreshLayout13.f10524J)) {
                        SmartRefreshLayout.this.m4614s(EnumC2878b.LoadReleased);
                        break;
                    } else {
                        SmartRefreshLayout.this.setViceState(EnumC2878b.LoadReleased);
                        break;
                    }
                    break;
                case Refreshing:
                    SmartRefreshLayout.this.setStateRefreshing(true);
                    break;
                case Loading:
                    SmartRefreshLayout.this.setStateLoading(true);
                    break;
            }
            return null;
        }
    }

    public SmartRefreshLayout(Context context) {
        this(context, null);
    }

    public static void setDefaultRefreshFooterCreator(@NonNull InterfaceC2881b interfaceC2881b) {
        f10502c = interfaceC2881b;
    }

    public static void setDefaultRefreshHeaderCreator(@NonNull InterfaceC2882c interfaceC2882c) {
        f10503e = interfaceC2882c;
    }

    public static void setDefaultRefreshInitializer(@NonNull InterfaceC2883d interfaceC2883d) {
        f10504f = interfaceC2883d;
    }

    /* renamed from: c */
    public InterfaceC2876f mo3322c(boolean z) {
        this.f10552f0 = true;
        this.f10524J = z;
        return this;
    }

    @Override // android.view.View
    public void computeScroll() {
        EnumC2878b enumC2878b;
        this.f10514E.getCurrY();
        if (this.f10514E.computeScrollOffset()) {
            int finalY = this.f10514E.getFinalY();
            if ((finalY >= 0 || !((this.f10522I || this.f10540R) && ((C2890a) this.f10513D0).m3340b())) && (finalY <= 0 || !((this.f10524J || this.f10540R) && ((C2890a) this.f10513D0).m3339a()))) {
                this.f10535O0 = true;
                invalidate();
                return;
            }
            if (this.f10535O0) {
                float currVelocity = finalY > 0 ? -this.f10514E.getCurrVelocity() : this.f10514E.getCurrVelocity();
                if (this.f10541R0 == null) {
                    if (currVelocity > 0.0f && ((enumC2878b = this.f10521H0) == EnumC2878b.Refreshing || enumC2878b == EnumC2878b.TwoLevel)) {
                        this.f10539Q0 = new RunnableC4071h(currVelocity, this.f10573q0);
                    } else if (currVelocity < 0.0f && (this.f10521H0 == EnumC2878b.Loading || ((this.f10534O && this.f10550d0 && this.f10551e0 && m4611p(this.f10524J)) || (this.f10542S && !this.f10550d0 && m4611p(this.f10524J) && this.f10521H0 != EnumC2878b.Refreshing)))) {
                        this.f10539Q0 = new RunnableC4071h(currVelocity, -this.f10577s0);
                    } else if (this.f10556i == 0 && this.f10538Q) {
                        this.f10539Q0 = new RunnableC4071h(currVelocity, 0);
                    }
                }
            }
            this.f10514E.forceFinished(true);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:74:0x00e2, code lost:
    
        if (r6 != 3) goto L215;
     */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean dispatchTouchEvent(android.view.MotionEvent r24) {
        /*
            Method dump skipped, instructions count: 905
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.scwang.smart.refresh.layout.SmartRefreshLayout.dispatchTouchEvent(android.view.MotionEvent):boolean");
    }

    @Override // android.view.ViewGroup
    public boolean drawChild(Canvas canvas, View view, long j2) {
        Paint paint;
        Paint paint2;
        InterfaceC2872b interfaceC2872b = this.f10513D0;
        View view2 = interfaceC2872b != null ? ((C2890a) interfaceC2872b).f7903c : null;
        InterfaceC2871a interfaceC2871a = this.f10509B0;
        if (interfaceC2871a != null && interfaceC2871a.getView() == view) {
            if (!m4611p(this.f10522I) || (!this.f10536P && isInEditMode())) {
                return true;
            }
            if (view2 != null) {
                int max = Math.max(view2.getPaddingTop() + view2.getTop() + this.f10556i, view.getTop());
                int i2 = this.f10527K0;
                if (i2 != 0 && (paint2 = this.f10515E0) != null) {
                    paint2.setColor(i2);
                    if (this.f10509B0.getSpinnerStyle().f7895i) {
                        max = view.getBottom();
                    } else if (this.f10509B0.getSpinnerStyle() == C2879c.f7887a) {
                        max = view.getBottom() + this.f10556i;
                    }
                    canvas.drawRect(0.0f, view.getTop(), getWidth(), max, this.f10515E0);
                }
                if ((this.f10526K && this.f10509B0.getSpinnerStyle() == C2879c.f7889c) || this.f10509B0.getSpinnerStyle().f7895i) {
                    canvas.save();
                    canvas.clipRect(view.getLeft(), view.getTop(), view.getRight(), max);
                    boolean drawChild = super.drawChild(canvas, view, j2);
                    canvas.restore();
                    return drawChild;
                }
            }
        }
        InterfaceC2871a interfaceC2871a2 = this.f10511C0;
        if (interfaceC2871a2 != null && interfaceC2871a2.getView() == view) {
            if (!m4611p(this.f10524J) || (!this.f10536P && isInEditMode())) {
                return true;
            }
            if (view2 != null) {
                int min = Math.min((view2.getBottom() - view2.getPaddingBottom()) + this.f10556i, view.getBottom());
                int i3 = this.f10529L0;
                if (i3 != 0 && (paint = this.f10515E0) != null) {
                    paint.setColor(i3);
                    if (this.f10511C0.getSpinnerStyle().f7895i) {
                        min = view.getTop();
                    } else if (this.f10511C0.getSpinnerStyle() == C2879c.f7887a) {
                        min = view.getTop() + this.f10556i;
                    }
                    canvas.drawRect(0.0f, min, getWidth(), view.getBottom(), this.f10515E0);
                }
                if ((this.f10528L && this.f10511C0.getSpinnerStyle() == C2879c.f7889c) || this.f10511C0.getSpinnerStyle().f7895i) {
                    canvas.save();
                    canvas.clipRect(view.getLeft(), min, view.getRight(), view.getBottom());
                    boolean drawChild2 = super.drawChild(canvas, view, j2);
                    canvas.restore();
                    return drawChild2;
                }
            }
        }
        return super.drawChild(canvas, view, j2);
    }

    @Override // android.view.ViewGroup
    public ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new C4073j(getContext(), attributeSet);
    }

    @Override // p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2876f
    @NonNull
    public ViewGroup getLayout() {
        return this;
    }

    @Override // android.view.ViewGroup, androidx.core.view.NestedScrollingParent
    public int getNestedScrollAxes() {
        return this.f10571p0.getNestedScrollAxes();
    }

    @Nullable
    public InterfaceC2873c getRefreshFooter() {
        InterfaceC2871a interfaceC2871a = this.f10511C0;
        if (interfaceC2871a instanceof InterfaceC2873c) {
            return (InterfaceC2873c) interfaceC2871a;
        }
        return null;
    }

    @Nullable
    public InterfaceC2874d getRefreshHeader() {
        InterfaceC2871a interfaceC2871a = this.f10509B0;
        if (interfaceC2871a instanceof InterfaceC2874d) {
            return (InterfaceC2874d) interfaceC2871a;
        }
        return null;
    }

    @NonNull
    public EnumC2878b getState() {
        return this.f10521H0;
    }

    @Override // android.view.View
    public boolean isNestedScrollingEnabled() {
        return this.f10547a0 && (this.f10540R || this.f10522I || this.f10524J);
    }

    /* renamed from: j */
    public ValueAnimator m4607j(int i2, int i3, Interpolator interpolator, int i4) {
        if (this.f10556i == i2) {
            return null;
        }
        ValueAnimator valueAnimator = this.f10541R0;
        if (valueAnimator != null) {
            valueAnimator.setDuration(0L);
            this.f10541R0.cancel();
            this.f10541R0 = null;
        }
        this.f10539Q0 = null;
        ValueAnimator ofInt = ValueAnimator.ofInt(this.f10556i, i2);
        this.f10541R0 = ofInt;
        ofInt.setDuration(i4);
        this.f10541R0.setInterpolator(interpolator);
        this.f10541R0.addListener(new C4066c());
        this.f10541R0.addUpdateListener(new C4067d());
        this.f10541R0.setStartDelay(i3);
        this.f10541R0.start();
        return this.f10541R0;
    }

    /* renamed from: k */
    public InterfaceC2876f mo3956k(int i2, boolean z, boolean z2) {
        int i3 = i2 >> 16;
        int i4 = (i2 << 16) >> 16;
        RunnableC4070g runnableC4070g = new RunnableC4070g(i3, z2, z);
        if (i4 > 0) {
            this.f10517F0.postDelayed(runnableC4070g, i4);
        } else {
            runnableC4070g.run();
        }
        return this;
    }

    /* renamed from: l */
    public InterfaceC2876f m4608l() {
        return mo3956k(Math.min(Math.max(0, 300 - ((int) (System.currentTimeMillis() - this.f10525J0))), IjkMediaCodecInfo.RANK_SECURE) << 16, true, true);
    }

    /* renamed from: m */
    public InterfaceC2876f mo3957m(int i2, boolean z, Boolean bool) {
        int i3 = i2 >> 16;
        int i4 = (i2 << 16) >> 16;
        RunnableC4069f runnableC4069f = new RunnableC4069f(i3, bool, z);
        if (i4 > 0) {
            this.f10517F0.postDelayed(runnableC4069f, i4);
        } else {
            runnableC4069f.run();
        }
        return this;
    }

    /* renamed from: n */
    public InterfaceC2876f m4609n() {
        return mo3957m(Math.min(Math.max(0, 300 - ((int) (System.currentTimeMillis() - this.f10525J0))), IjkMediaCodecInfo.RANK_SECURE) << 16, true, Boolean.TRUE);
    }

    /* renamed from: o */
    public boolean m4610o(int i2) {
        if (i2 == 0) {
            if (this.f10541R0 != null) {
                EnumC2878b enumC2878b = this.f10521H0;
                if (enumC2878b.f7880A || enumC2878b == EnumC2878b.TwoLevelReleased || enumC2878b == EnumC2878b.RefreshReleased || enumC2878b == EnumC2878b.LoadReleased) {
                    return true;
                }
                if (enumC2878b == EnumC2878b.PullDownCanceled) {
                    ((C4074k) this.f10519G0).m4623d(EnumC2878b.PullDownToRefresh);
                } else if (enumC2878b == EnumC2878b.PullUpCanceled) {
                    ((C4074k) this.f10519G0).m4623d(EnumC2878b.PullUpToLoad);
                }
                this.f10541R0.setDuration(0L);
                this.f10541R0.cancel();
                this.f10541R0 = null;
            }
            this.f10539Q0 = null;
        }
        return this.f10541R0 != null;
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        InterfaceC2871a interfaceC2871a;
        InterfaceC2871a interfaceC2871a2;
        InterfaceC2882c interfaceC2882c;
        InterfaceC2871a interfaceC2871a3;
        super.onAttachedToWindow();
        boolean z = true;
        this.f10531M0 = true;
        if (!isInEditMode()) {
            if (this.f10509B0 == null && (interfaceC2882c = f10503e) != null) {
                Context context = getContext();
                MyApp myApp = MyApp.f9891f;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(this, "layout");
                int[] iArr = new int[2];
                Resources resources = MyApp.f9895j;
                if (resources == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("resourses");
                    throw null;
                }
                iArr[0] = resources.getColor(R.color.transparent);
                Resources resources2 = MyApp.f9895j;
                if (resources2 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("resourses");
                    throw null;
                }
                iArr[1] = resources2.getColor(R.color.black26);
                m4617w(iArr);
                ClassicsHeader classicsHeader = new ClassicsHeader(context);
                InterfaceC2871a interfaceC2871a4 = this.f10509B0;
                if (interfaceC2871a4 != null) {
                    super.removeView(interfaceC2871a4.getView());
                }
                this.f10509B0 = classicsHeader;
                this.f10527K0 = 0;
                this.f10575r0 = C2877a.f7847a;
                ViewGroup.LayoutParams c4073j = new C4073j(-1, -2);
                ViewGroup.LayoutParams layoutParams = classicsHeader.getView().getLayoutParams();
                if (layoutParams instanceof C4073j) {
                    c4073j = (C4073j) layoutParams;
                }
                if (this.f10509B0.getSpinnerStyle().f7894h) {
                    super.addView(this.f10509B0.getView(), getChildCount(), c4073j);
                } else {
                    super.addView(this.f10509B0.getView(), 0, c4073j);
                }
                int[] iArr2 = this.f10520H;
                if (iArr2 != null && (interfaceC2871a3 = this.f10509B0) != null) {
                    interfaceC2871a3.setPrimaryColors(iArr2);
                }
            }
            if (this.f10511C0 == null) {
                InterfaceC2881b interfaceC2881b = f10502c;
                if (interfaceC2881b != null) {
                    Context context2 = getContext();
                    MyApp myApp2 = MyApp.f9891f;
                    Intrinsics.checkNotNullParameter(context2, "context");
                    Intrinsics.checkNotNullParameter(this, "layout");
                    ClassicsFooter classicsFooter = new ClassicsFooter(context2);
                    ImageView imageView = classicsFooter.f10456h;
                    ImageView imageView2 = classicsFooter.f10457i;
                    ViewGroup.LayoutParams layoutParams2 = imageView.getLayoutParams();
                    ViewGroup.LayoutParams layoutParams3 = imageView2.getLayoutParams();
                    int m3333c = InterpolatorC2889b.m3333c(20.0f);
                    layoutParams3.width = m3333c;
                    layoutParams2.width = m3333c;
                    int m3333c2 = InterpolatorC2889b.m3333c(20.0f);
                    layoutParams3.height = m3333c2;
                    layoutParams2.height = m3333c2;
                    imageView.setLayoutParams(layoutParams2);
                    imageView2.setLayoutParams(layoutParams3);
                    InterfaceC2871a interfaceC2871a5 = this.f10511C0;
                    if (interfaceC2871a5 != null) {
                        super.removeView(interfaceC2871a5.getView());
                    }
                    this.f10511C0 = classicsFooter;
                    this.f10533N0 = false;
                    this.f10529L0 = 0;
                    this.f10551e0 = false;
                    this.f10579t0 = C2877a.f7847a;
                    if (this.f10552f0 && !this.f10524J) {
                        z = false;
                    }
                    this.f10524J = z;
                    ViewGroup.LayoutParams c4073j2 = new C4073j(-1, -2);
                    ViewGroup.LayoutParams layoutParams4 = classicsFooter.getView().getLayoutParams();
                    if (layoutParams4 instanceof C4073j) {
                        c4073j2 = (C4073j) layoutParams4;
                    }
                    if (this.f10511C0.getSpinnerStyle().f7894h) {
                        super.addView(this.f10511C0.getView(), getChildCount(), c4073j2);
                    } else {
                        super.addView(this.f10511C0.getView(), 0, c4073j2);
                    }
                    int[] iArr3 = this.f10520H;
                    if (iArr3 != null && (interfaceC2871a2 = this.f10511C0) != null) {
                        interfaceC2871a2.setPrimaryColors(iArr3);
                    }
                }
            } else {
                if (!this.f10524J && this.f10552f0) {
                    z = false;
                }
                this.f10524J = z;
            }
            if (this.f10513D0 == null) {
                int childCount = getChildCount();
                for (int i2 = 0; i2 < childCount; i2++) {
                    View childAt = getChildAt(i2);
                    InterfaceC2871a interfaceC2871a6 = this.f10509B0;
                    if ((interfaceC2871a6 == null || childAt != interfaceC2871a6.getView()) && ((interfaceC2871a = this.f10511C0) == null || childAt != interfaceC2871a.getView())) {
                        this.f10513D0 = new C2890a(childAt);
                    }
                }
            }
            if (this.f10513D0 == null) {
                int m3333c3 = InterpolatorC2889b.m3333c(20.0f);
                TextView textView = new TextView(getContext());
                textView.setTextColor(-39424);
                textView.setGravity(17);
                textView.setTextSize(20.0f);
                textView.setText(R$string.srl_content_empty);
                super.addView(textView, 0, new C4073j(-1, -1));
                C2890a c2890a = new C2890a(textView);
                this.f10513D0 = c2890a;
                c2890a.f7903c.setPadding(m3333c3, m3333c3, m3333c3, m3333c3);
            }
            View findViewById = findViewById(this.f10586x);
            View findViewById2 = findViewById(this.f10588y);
            ((C2890a) this.f10513D0).m3344f(this.f10561k0);
            C2890a c2890a2 = (C2890a) this.f10513D0;
            c2890a2.f7911l.f7898c = this.f10546W;
            c2890a2.m3345g(this.f10519G0, findViewById, findViewById2);
            if (this.f10556i != 0) {
                m4614s(EnumC2878b.None);
                InterfaceC2872b interfaceC2872b = this.f10513D0;
                this.f10556i = 0;
                ((C2890a) interfaceC2872b).m3342d(0, this.f10590z, this.f10506A);
            }
        }
        int[] iArr4 = this.f10520H;
        if (iArr4 != null) {
            InterfaceC2871a interfaceC2871a7 = this.f10509B0;
            if (interfaceC2871a7 != null) {
                interfaceC2871a7.setPrimaryColors(iArr4);
            }
            InterfaceC2871a interfaceC2871a8 = this.f10511C0;
            if (interfaceC2871a8 != null) {
                interfaceC2871a8.setPrimaryColors(this.f10520H);
            }
        }
        InterfaceC2872b interfaceC2872b2 = this.f10513D0;
        if (interfaceC2872b2 != null) {
            super.bringChildToFront(((C2890a) interfaceC2872b2).f7903c);
        }
        InterfaceC2871a interfaceC2871a9 = this.f10509B0;
        if (interfaceC2871a9 != null && interfaceC2871a9.getSpinnerStyle().f7894h) {
            super.bringChildToFront(this.f10509B0.getView());
        }
        InterfaceC2871a interfaceC2871a10 = this.f10511C0;
        if (interfaceC2871a10 == null || !interfaceC2871a10.getSpinnerStyle().f7894h) {
            return;
        }
        super.bringChildToFront(this.f10511C0.getView());
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.f10531M0 = false;
        this.f10552f0 = true;
        this.f10539Q0 = null;
        ValueAnimator valueAnimator = this.f10541R0;
        if (valueAnimator != null) {
            valueAnimator.removeAllListeners();
            this.f10541R0.removeAllUpdateListeners();
            this.f10541R0.setDuration(0L);
            this.f10541R0.cancel();
            this.f10541R0 = null;
        }
        InterfaceC2871a interfaceC2871a = this.f10509B0;
        if (interfaceC2871a != null && this.f10521H0 == EnumC2878b.Refreshing) {
            interfaceC2871a.mo3318f(this, false);
        }
        InterfaceC2871a interfaceC2871a2 = this.f10511C0;
        if (interfaceC2871a2 != null && this.f10521H0 == EnumC2878b.Loading) {
            interfaceC2871a2.mo3318f(this, false);
        }
        if (this.f10556i != 0) {
            ((C4074k) this.f10519G0).m4621b(0, true);
        }
        EnumC2878b enumC2878b = this.f10521H0;
        EnumC2878b enumC2878b2 = EnumC2878b.None;
        if (enumC2878b != enumC2878b2) {
            m4614s(enumC2878b2);
        }
        Handler handler = this.f10517F0;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
        }
        this.f10533N0 = false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0052  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onFinishInflate() {
        /*
            r11 = this;
            super.onFinishInflate()
            int r0 = super.getChildCount()
            r1 = 3
            if (r0 > r1) goto L9e
            r2 = -1
            r3 = 0
            r4 = 0
            r5 = -1
            r6 = 0
        Lf:
            r7 = 2
            r8 = 1
            if (r4 >= r0) goto L33
            android.view.View r9 = super.getChildAt(r4)
            boolean r10 = p005b.p340x.p341a.p343b.p347c.p352e.InterpolatorC2889b.m3334d(r9)
            if (r10 == 0) goto L24
            if (r6 < r7) goto L21
            if (r4 != r8) goto L24
        L21:
            r5 = r4
            r6 = 2
            goto L30
        L24:
            boolean r7 = r9 instanceof p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
            if (r7 != 0) goto L30
            if (r6 >= r8) goto L30
            if (r4 <= 0) goto L2e
            r6 = 1
            goto L2f
        L2e:
            r6 = 0
        L2f:
            r5 = r4
        L30:
            int r4 = r4 + 1
            goto Lf
        L33:
            if (r5 < 0) goto L4d
            b.x.a.b.c.f.a r4 = new b.x.a.b.c.f.a
            android.view.View r6 = super.getChildAt(r5)
            r4.<init>(r6)
            r11.f10513D0 = r4
            if (r5 != r8) goto L48
            if (r0 != r1) goto L46
            r1 = 0
            goto L4f
        L46:
            r1 = 0
            goto L4e
        L48:
            if (r0 != r7) goto L4d
            r1 = -1
            r7 = 1
            goto L4f
        L4d:
            r1 = -1
        L4e:
            r7 = -1
        L4f:
            r4 = 0
        L50:
            if (r4 >= r0) goto L9d
            android.view.View r5 = super.getChildAt(r4)
            if (r4 == r1) goto L8b
            if (r4 == r7) goto L65
            if (r1 != r2) goto L65
            b.x.a.b.c.a.a r6 = r11.f10509B0
            if (r6 != 0) goto L65
            boolean r6 = r5 instanceof p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2874d
            if (r6 == 0) goto L65
            goto L8b
        L65:
            if (r4 == r7) goto L6d
            if (r7 != r2) goto L9a
            boolean r6 = r5 instanceof p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2873c
            if (r6 == 0) goto L9a
        L6d:
            boolean r6 = r11.f10524J
            if (r6 != 0) goto L78
            boolean r6 = r11.f10552f0
            if (r6 != 0) goto L76
            goto L78
        L76:
            r6 = 0
            goto L79
        L78:
            r6 = 1
        L79:
            r11.f10524J = r6
            boolean r6 = r5 instanceof p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2873c
            if (r6 == 0) goto L82
            b.x.a.b.c.a.c r5 = (p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2873c) r5
            goto L88
        L82:
            com.scwang.smart.refresh.layout.wrapper.RefreshFooterWrapper r6 = new com.scwang.smart.refresh.layout.wrapper.RefreshFooterWrapper
            r6.<init>(r5)
            r5 = r6
        L88:
            r11.f10511C0 = r5
            goto L9a
        L8b:
            boolean r6 = r5 instanceof p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2874d
            if (r6 == 0) goto L92
            b.x.a.b.c.a.d r5 = (p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2874d) r5
            goto L98
        L92:
            com.scwang.smart.refresh.layout.wrapper.RefreshHeaderWrapper r6 = new com.scwang.smart.refresh.layout.wrapper.RefreshHeaderWrapper
            r6.<init>(r5)
            r5 = r6
        L98:
            r11.f10509B0 = r5
        L9a:
            int r4 = r4 + 1
            goto L50
        L9d:
            return
        L9e:
            java.lang.RuntimeException r0 = new java.lang.RuntimeException
            java.lang.String r1 = "最多只支持3个子View，Most only support three sub view"
            r0.<init>(r1)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.scwang.smart.refresh.layout.SmartRefreshLayout.onFinishInflate():void");
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onLayout(boolean z, int i2, int i3, int i4, int i5) {
        int i6;
        int paddingLeft = getPaddingLeft();
        int paddingTop = getPaddingTop();
        getPaddingBottom();
        int childCount = super.getChildCount();
        for (int i7 = 0; i7 < childCount; i7++) {
            View childAt = super.getChildAt(i7);
            if (childAt.getVisibility() != 8 && !"GONE".equals(childAt.getTag(R$id.srl_tag))) {
                InterfaceC2872b interfaceC2872b = this.f10513D0;
                if (interfaceC2872b != null && ((C2890a) interfaceC2872b).f7903c == childAt) {
                    boolean z2 = isInEditMode() && this.f10536P && m4611p(this.f10522I) && this.f10509B0 != null;
                    View view = ((C2890a) this.f10513D0).f7903c;
                    ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
                    ViewGroup.MarginLayoutParams marginLayoutParams = layoutParams instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams : f10505g;
                    int i8 = marginLayoutParams.leftMargin + paddingLeft;
                    int i9 = marginLayoutParams.topMargin + paddingTop;
                    int measuredWidth = view.getMeasuredWidth() + i8;
                    int measuredHeight = view.getMeasuredHeight() + i9;
                    if (z2 && m4612q(this.f10530M, this.f10509B0)) {
                        int i10 = this.f10573q0;
                        i9 += i10;
                        measuredHeight += i10;
                    }
                    view.layout(i8, i9, measuredWidth, measuredHeight);
                }
                InterfaceC2871a interfaceC2871a = this.f10509B0;
                if (interfaceC2871a != null && interfaceC2871a.getView() == childAt) {
                    boolean z3 = isInEditMode() && this.f10536P && m4611p(this.f10522I);
                    View view2 = this.f10509B0.getView();
                    ViewGroup.LayoutParams layoutParams2 = view2.getLayoutParams();
                    ViewGroup.MarginLayoutParams marginLayoutParams2 = layoutParams2 instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams2 : f10505g;
                    int i11 = marginLayoutParams2.leftMargin;
                    int i12 = marginLayoutParams2.topMargin + this.f10581u0;
                    int measuredWidth2 = view2.getMeasuredWidth() + i11;
                    int measuredHeight2 = view2.getMeasuredHeight() + i12;
                    if (!z3 && this.f10509B0.getSpinnerStyle() == C2879c.f7887a) {
                        int i13 = this.f10573q0;
                        i12 -= i13;
                        measuredHeight2 -= i13;
                    }
                    view2.layout(i11, i12, measuredWidth2, measuredHeight2);
                }
                InterfaceC2871a interfaceC2871a2 = this.f10511C0;
                if (interfaceC2871a2 != null && interfaceC2871a2.getView() == childAt) {
                    boolean z4 = isInEditMode() && this.f10536P && m4611p(this.f10524J);
                    View view3 = this.f10511C0.getView();
                    ViewGroup.LayoutParams layoutParams3 = view3.getLayoutParams();
                    ViewGroup.MarginLayoutParams marginLayoutParams3 = layoutParams3 instanceof ViewGroup.MarginLayoutParams ? (ViewGroup.MarginLayoutParams) layoutParams3 : f10505g;
                    C2879c spinnerStyle = this.f10511C0.getSpinnerStyle();
                    int i14 = marginLayoutParams3.leftMargin;
                    int measuredHeight3 = (getMeasuredHeight() + marginLayoutParams3.topMargin) - this.f10583v0;
                    if (this.f10550d0 && this.f10551e0 && this.f10534O && this.f10513D0 != null && this.f10511C0.getSpinnerStyle() == C2879c.f7887a && m4611p(this.f10524J)) {
                        View view4 = ((C2890a) this.f10513D0).f7903c;
                        ViewGroup.LayoutParams layoutParams4 = view4.getLayoutParams();
                        measuredHeight3 = view4.getMeasuredHeight() + paddingTop + paddingTop + (layoutParams4 instanceof ViewGroup.MarginLayoutParams ? ((ViewGroup.MarginLayoutParams) layoutParams4).topMargin : 0);
                    }
                    if (spinnerStyle == C2879c.f7891e) {
                        measuredHeight3 = marginLayoutParams3.topMargin - this.f10583v0;
                    } else {
                        if (z4 || spinnerStyle == C2879c.f7890d || spinnerStyle == C2879c.f7889c) {
                            i6 = this.f10577s0;
                        } else if (spinnerStyle.f7895i && this.f10556i < 0) {
                            i6 = Math.max(m4611p(this.f10524J) ? -this.f10556i : 0, 0);
                        }
                        measuredHeight3 -= i6;
                    }
                    view3.layout(i14, measuredHeight3, view3.getMeasuredWidth() + i14, view3.getMeasuredHeight() + measuredHeight3);
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:145:0x0265  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0226  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x023f  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onMeasure(int r19, int r20) {
        /*
            Method dump skipped, instructions count: 872
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.scwang.smart.refresh.layout.SmartRefreshLayout.onMeasure(int, int):void");
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public boolean onNestedFling(@NonNull View view, float f2, float f3, boolean z) {
        return this.f10569o0.dispatchNestedFling(f2, f3, z);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public boolean onNestedPreFling(@NonNull View view, float f2, float f3) {
        return (this.f10533N0 && f3 > 0.0f) || m4619y(-f3) || this.f10569o0.dispatchNestedPreFling(f2, f3);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onNestedPreScroll(@NonNull View view, int i2, int i3, @NonNull int[] iArr) {
        int i4 = this.f10563l0;
        int i5 = 0;
        if (i3 * i4 > 0) {
            if (Math.abs(i3) > Math.abs(this.f10563l0)) {
                int i6 = this.f10563l0;
                this.f10563l0 = 0;
                i5 = i6;
            } else {
                this.f10563l0 -= i3;
                i5 = i3;
            }
            m4613r(this.f10563l0);
        } else if (i3 > 0 && this.f10533N0) {
            int i7 = i4 - i3;
            this.f10563l0 = i7;
            m4613r(i7);
            i5 = i3;
        }
        this.f10569o0.dispatchNestedPreScroll(i2, i3 - i5, iArr, null);
        iArr[1] = iArr[1] + i5;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onNestedScroll(@NonNull View view, int i2, int i3, int i4, int i5) {
        InterfaceC2886g interfaceC2886g;
        ViewParent parent;
        InterfaceC2886g interfaceC2886g2;
        boolean dispatchNestedScroll = this.f10569o0.dispatchNestedScroll(i2, i3, i4, i5, this.f10567n0);
        int i6 = i5 + this.f10567n0[1];
        if ((i6 < 0 && ((this.f10522I || this.f10540R) && (this.f10563l0 != 0 || (interfaceC2886g2 = this.f10561k0) == null || interfaceC2886g2.mo3329a(((C2890a) this.f10513D0).f7903c)))) || (i6 > 0 && ((this.f10524J || this.f10540R) && (this.f10563l0 != 0 || (interfaceC2886g = this.f10561k0) == null || interfaceC2886g.mo3330b(((C2890a) this.f10513D0).f7903c))))) {
            EnumC2878b enumC2878b = this.f10523I0;
            if (enumC2878b == EnumC2878b.None || enumC2878b.f7886z) {
                ((C4074k) this.f10519G0).m4623d(i6 > 0 ? EnumC2878b.PullUpToLoad : EnumC2878b.PullDownToRefresh);
                if (!dispatchNestedScroll && (parent = getParent()) != null) {
                    parent.requestDisallowInterceptTouchEvent(true);
                }
            }
            int i7 = this.f10563l0 - i6;
            this.f10563l0 = i7;
            m4613r(i7);
        }
        if (!this.f10533N0 || i3 >= 0) {
            return;
        }
        this.f10533N0 = false;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onNestedScrollAccepted(@NonNull View view, @NonNull View view2, int i2) {
        this.f10571p0.onNestedScrollAccepted(view, view2, i2);
        this.f10569o0.startNestedScroll(i2 & 2);
        this.f10563l0 = this.f10556i;
        this.f10565m0 = true;
        m4610o(0);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public boolean onStartNestedScroll(@NonNull View view, @NonNull View view2, int i2) {
        return (isEnabled() && isNestedScrollingEnabled() && (i2 & 2) != 0) && (this.f10540R || this.f10522I || this.f10524J);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent, androidx.core.view.NestedScrollingParent
    public void onStopNestedScroll(@NonNull View view) {
        this.f10571p0.onStopNestedScroll(view);
        this.f10565m0 = false;
        this.f10563l0 = 0;
        m4615t();
        this.f10569o0.stopNestedScroll();
    }

    /* renamed from: p */
    public boolean m4611p(boolean z) {
        return z && !this.f10543T;
    }

    /* renamed from: q */
    public boolean m4612q(boolean z, @Nullable InterfaceC2871a interfaceC2871a) {
        return z || this.f10543T || interfaceC2871a == null || interfaceC2871a.getSpinnerStyle() == C2879c.f7889c;
    }

    /* renamed from: r */
    public void m4613r(float f2) {
        EnumC2878b enumC2878b;
        float f3 = (!this.f10565m0 || this.f10546W || f2 >= 0.0f || ((C2890a) this.f10513D0).m3339a()) ? f2 : 0.0f;
        if (f3 > this.f10566n * 5 && getTag() == null) {
            int i2 = R$id.srl_tag;
            if (getTag(i2) == null) {
                float f4 = this.f10574r;
                int i3 = this.f10566n;
                if (f4 < i3 / 6.0f && this.f10572q < i3 / 16.0f) {
                    Toast.makeText(getContext(), "你这么死拉，臣妾做不到啊！", 0).show();
                    setTag(i2, "你这么死拉，臣妾做不到啊！");
                }
            }
        }
        EnumC2878b enumC2878b2 = this.f10521H0;
        if (enumC2878b2 == EnumC2878b.TwoLevel && f3 > 0.0f) {
            ((C4074k) this.f10519G0).m4621b(Math.min((int) f3, getMeasuredHeight()), true);
        } else if (enumC2878b2 == EnumC2878b.Refreshing && f3 >= 0.0f) {
            int i4 = this.f10573q0;
            if (f3 < i4) {
                ((C4074k) this.f10519G0).m4621b((int) f3, true);
            } else {
                float f5 = this.f10585w0;
                if (f5 < 10.0f) {
                    f5 *= i4;
                }
                double d2 = f5 - i4;
                int max = Math.max((this.f10566n * 4) / 3, getHeight());
                int i5 = this.f10573q0;
                double d3 = max - i5;
                double max2 = Math.max(0.0f, (f3 - i5) * this.f10576s);
                double d4 = -max2;
                if (d3 == ShadowDrawableWrapper.COS_45) {
                    d3 = 1.0d;
                }
                ((C4074k) this.f10519G0).m4621b(((int) Math.min((1.0d - Math.pow(100.0d, d4 / d3)) * d2, max2)) + this.f10573q0, true);
            }
        } else if (f3 < 0.0f && (enumC2878b2 == EnumC2878b.Loading || ((this.f10534O && this.f10550d0 && this.f10551e0 && m4611p(this.f10524J)) || (this.f10542S && !this.f10550d0 && m4611p(this.f10524J))))) {
            int i6 = this.f10577s0;
            if (f3 > (-i6)) {
                ((C4074k) this.f10519G0).m4621b((int) f3, true);
            } else {
                float f6 = this.f10587x0;
                if (f6 < 10.0f) {
                    f6 *= i6;
                }
                double d5 = f6 - i6;
                int max3 = Math.max((this.f10566n * 4) / 3, getHeight());
                int i7 = this.f10577s0;
                double d6 = max3 - i7;
                double d7 = -Math.min(0.0f, (i7 + f3) * this.f10576s);
                double d8 = -d7;
                if (d6 == ShadowDrawableWrapper.COS_45) {
                    d6 = 1.0d;
                }
                ((C4074k) this.f10519G0).m4621b(((int) (-Math.min((1.0d - Math.pow(100.0d, d8 / d6)) * d5, d7))) - this.f10577s0, true);
            }
        } else if (f3 >= 0.0f) {
            float f7 = this.f10585w0;
            double d9 = f7 < 10.0f ? this.f10573q0 * f7 : f7;
            double max4 = Math.max(this.f10566n / 2, getHeight());
            double max5 = Math.max(0.0f, this.f10576s * f3);
            double d10 = -max5;
            if (max4 == ShadowDrawableWrapper.COS_45) {
                max4 = 1.0d;
            }
            ((C4074k) this.f10519G0).m4621b((int) Math.min((1.0d - Math.pow(100.0d, d10 / max4)) * d9, max5), true);
        } else {
            float f8 = this.f10587x0;
            double d11 = f8 < 10.0f ? this.f10577s0 * f8 : f8;
            double max6 = Math.max(this.f10566n / 2, getHeight());
            double d12 = -Math.min(0.0f, this.f10576s * f3);
            ((C4074k) this.f10519G0).m4621b((int) (-Math.min((1.0d - Math.pow(100.0d, (-d12) / (max6 == ShadowDrawableWrapper.COS_45 ? 1.0d : max6))) * d11, d12)), true);
        }
        if (!this.f10542S || this.f10550d0 || !m4611p(this.f10524J) || f3 >= 0.0f || (enumC2878b = this.f10521H0) == EnumC2878b.Refreshing || enumC2878b == EnumC2878b.Loading || enumC2878b == EnumC2878b.LoadFinish) {
            return;
        }
        if (this.f10549c0) {
            this.f10539Q0 = null;
            ((C4074k) this.f10519G0).m4620a(-this.f10577s0);
        }
        setStateDirectLoading(false);
        this.f10517F0.postDelayed(new RunnableC4068e(), this.f10564m);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public void requestDisallowInterceptTouchEvent(boolean z) {
        if (ViewCompat.isNestedScrollingEnabled(((C2890a) this.f10513D0).f7905f)) {
            this.f10584w = z;
            super.requestDisallowInterceptTouchEvent(z);
        }
    }

    /* renamed from: s */
    public void m4614s(EnumC2878b enumC2878b) {
        EnumC2878b enumC2878b2 = this.f10521H0;
        if (enumC2878b2 == enumC2878b) {
            if (this.f10523I0 != enumC2878b2) {
                this.f10523I0 = enumC2878b2;
                return;
            }
            return;
        }
        this.f10521H0 = enumC2878b;
        this.f10523I0 = enumC2878b;
        InterfaceC2871a interfaceC2871a = this.f10509B0;
        InterfaceC2871a interfaceC2871a2 = this.f10511C0;
        if (interfaceC2871a != null) {
            interfaceC2871a.mo3328h(this, enumC2878b2, enumC2878b);
        }
        if (interfaceC2871a2 != null) {
            interfaceC2871a2.mo3328h(this, enumC2878b2, enumC2878b);
        }
        if (enumC2878b == EnumC2878b.LoadFinish) {
            this.f10533N0 = false;
        }
    }

    @Override // android.view.View
    public void setNestedScrollingEnabled(boolean z) {
        this.f10547a0 = z;
        this.f10569o0.setNestedScrollingEnabled(z);
    }

    public void setStateDirectLoading(boolean z) {
        EnumC2878b enumC2878b = this.f10521H0;
        EnumC2878b enumC2878b2 = EnumC2878b.Loading;
        if (enumC2878b != enumC2878b2) {
            this.f10525J0 = System.currentTimeMillis();
            this.f10533N0 = true;
            m4614s(enumC2878b2);
            InterfaceC2884e interfaceC2884e = this.f10559j0;
            if (interfaceC2884e == null) {
                mo3956k(2000, true, false);
            } else if (z) {
                interfaceC2884e.mo3327b(this);
            }
            InterfaceC2871a interfaceC2871a = this.f10511C0;
            if (interfaceC2871a != null) {
                float f2 = this.f10587x0;
                if (f2 < 10.0f) {
                    f2 *= this.f10577s0;
                }
                interfaceC2871a.mo3320i(this, this.f10577s0, (int) f2);
            }
        }
    }

    public void setStateLoading(boolean z) {
        C4064a c4064a = new C4064a(z);
        m4614s(EnumC2878b.LoadReleased);
        ValueAnimator m4620a = ((C4074k) this.f10519G0).m4620a(-this.f10577s0);
        if (m4620a != null) {
            m4620a.addListener(c4064a);
        }
        InterfaceC2871a interfaceC2871a = this.f10511C0;
        if (interfaceC2871a != null) {
            float f2 = this.f10587x0;
            if (f2 < 10.0f) {
                f2 *= this.f10577s0;
            }
            interfaceC2871a.mo3317e(this, this.f10577s0, (int) f2);
        }
        if (m4620a == null) {
            c4064a.onAnimationEnd(null);
        }
    }

    public void setStateRefreshing(boolean z) {
        C4065b c4065b = new C4065b(z);
        m4614s(EnumC2878b.RefreshReleased);
        ValueAnimator m4620a = ((C4074k) this.f10519G0).m4620a(this.f10573q0);
        if (m4620a != null) {
            m4620a.addListener(c4065b);
        }
        InterfaceC2871a interfaceC2871a = this.f10509B0;
        if (interfaceC2871a != null) {
            float f2 = this.f10585w0;
            if (f2 < 10.0f) {
                f2 *= this.f10573q0;
            }
            interfaceC2871a.mo3317e(this, this.f10573q0, (int) f2);
        }
        if (m4620a == null) {
            c4065b.onAnimationEnd(null);
        }
    }

    public void setViceState(EnumC2878b enumC2878b) {
        EnumC2878b enumC2878b2 = this.f10521H0;
        if (enumC2878b2.f7885y && enumC2878b2.f7882v != enumC2878b.f7882v) {
            m4614s(EnumC2878b.None);
        }
        if (this.f10523I0 != enumC2878b) {
            this.f10523I0 = enumC2878b;
        }
    }

    /* renamed from: t */
    public void m4615t() {
        EnumC2878b enumC2878b = this.f10521H0;
        EnumC2878b enumC2878b2 = EnumC2878b.TwoLevel;
        if (enumC2878b == enumC2878b2) {
            if (this.f10512D > -1000 && this.f10556i > getHeight() / 2) {
                ValueAnimator m4620a = ((C4074k) this.f10519G0).m4620a(getHeight());
                if (m4620a != null) {
                    m4620a.setDuration(this.f10562l);
                    return;
                }
                return;
            }
            if (this.f10580u) {
                C4074k c4074k = (C4074k) this.f10519G0;
                SmartRefreshLayout smartRefreshLayout = SmartRefreshLayout.this;
                if (smartRefreshLayout.f10521H0 == enumC2878b2) {
                    ((C4074k) smartRefreshLayout.f10519G0).m4623d(EnumC2878b.TwoLevelFinish);
                    if (SmartRefreshLayout.this.f10556i != 0) {
                        c4074k.m4620a(0).setDuration(SmartRefreshLayout.this.f10562l);
                        return;
                    } else {
                        c4074k.m4621b(0, false);
                        SmartRefreshLayout.this.m4614s(EnumC2878b.None);
                        return;
                    }
                }
                return;
            }
            return;
        }
        EnumC2878b enumC2878b3 = EnumC2878b.Loading;
        if (enumC2878b == enumC2878b3 || (this.f10534O && this.f10550d0 && this.f10551e0 && this.f10556i < 0 && m4611p(this.f10524J))) {
            int i2 = this.f10556i;
            int i3 = this.f10577s0;
            if (i2 < (-i3)) {
                ((C4074k) this.f10519G0).m4620a(-i3);
                return;
            } else {
                if (i2 > 0) {
                    ((C4074k) this.f10519G0).m4620a(0);
                    return;
                }
                return;
            }
        }
        EnumC2878b enumC2878b4 = this.f10521H0;
        EnumC2878b enumC2878b5 = EnumC2878b.Refreshing;
        if (enumC2878b4 == enumC2878b5) {
            int i4 = this.f10556i;
            int i5 = this.f10573q0;
            if (i4 > i5) {
                ((C4074k) this.f10519G0).m4620a(i5);
                return;
            } else {
                if (i4 < 0) {
                    ((C4074k) this.f10519G0).m4620a(0);
                    return;
                }
                return;
            }
        }
        if (enumC2878b4 == EnumC2878b.PullDownToRefresh) {
            ((C4074k) this.f10519G0).m4623d(EnumC2878b.PullDownCanceled);
            return;
        }
        if (enumC2878b4 == EnumC2878b.PullUpToLoad) {
            ((C4074k) this.f10519G0).m4623d(EnumC2878b.PullUpCanceled);
            return;
        }
        if (enumC2878b4 == EnumC2878b.ReleaseToRefresh) {
            ((C4074k) this.f10519G0).m4623d(enumC2878b5);
            return;
        }
        if (enumC2878b4 == EnumC2878b.ReleaseToLoad) {
            ((C4074k) this.f10519G0).m4623d(enumC2878b3);
            return;
        }
        if (enumC2878b4 == EnumC2878b.ReleaseToTwoLevel) {
            ((C4074k) this.f10519G0).m4623d(EnumC2878b.TwoLevelReleased);
            return;
        }
        if (enumC2878b4 == EnumC2878b.RefreshReleased) {
            if (this.f10541R0 == null) {
                ((C4074k) this.f10519G0).m4620a(this.f10573q0);
                return;
            }
            return;
        }
        if (enumC2878b4 != EnumC2878b.LoadReleased) {
            if (enumC2878b4 == EnumC2878b.LoadFinish || this.f10556i == 0) {
                return;
            }
            ((C4074k) this.f10519G0).m4620a(0);
            return;
        }
        if (this.f10541R0 == null) {
            ((C4074k) this.f10519G0).m4620a(-this.f10577s0);
        }
    }

    /* renamed from: u */
    public InterfaceC2876f m4616u(boolean z) {
        this.f10546W = z;
        InterfaceC2872b interfaceC2872b = this.f10513D0;
        if (interfaceC2872b != null) {
            ((C2890a) interfaceC2872b).f7911l.f7898c = z;
        }
        return this;
    }

    /* renamed from: v */
    public InterfaceC2876f mo3958v(boolean z) {
        EnumC2878b enumC2878b = this.f10521H0;
        if (enumC2878b == EnumC2878b.Refreshing && z) {
            m4609n();
        } else if (enumC2878b == EnumC2878b.Loading && z) {
            m4608l();
        } else if (this.f10550d0 != z) {
            this.f10550d0 = z;
            InterfaceC2871a interfaceC2871a = this.f10511C0;
            if (interfaceC2871a instanceof InterfaceC2873c) {
                if (((InterfaceC2873c) interfaceC2871a).mo3321a(z)) {
                    this.f10551e0 = true;
                    if (this.f10550d0 && this.f10534O && this.f10556i > 0 && this.f10511C0.getSpinnerStyle() == C2879c.f7887a && m4611p(this.f10524J) && m4612q(this.f10522I, this.f10509B0)) {
                        this.f10511C0.getView().setTranslationY(this.f10556i);
                    }
                } else {
                    this.f10551e0 = false;
                    StringBuilder m586H = C1499a.m586H("Footer:");
                    m586H.append(this.f10511C0);
                    m586H.append(" NoMoreData is not supported.(不支持NoMoreData，请使用[ClassicsFooter]或者[自定义Footer并实现setNoMoreData方法且返回true])");
                    new RuntimeException(m586H.toString()).printStackTrace();
                }
            }
        }
        return this;
    }

    /* renamed from: w */
    public InterfaceC2876f m4617w(@ColorInt int... iArr) {
        InterfaceC2871a interfaceC2871a = this.f10509B0;
        if (interfaceC2871a != null) {
            interfaceC2871a.setPrimaryColors(iArr);
        }
        InterfaceC2871a interfaceC2871a2 = this.f10511C0;
        if (interfaceC2871a2 != null) {
            interfaceC2871a2.setPrimaryColors(iArr);
        }
        this.f10520H = iArr;
        return this;
    }

    /* renamed from: x */
    public InterfaceC2876f m4618x(@NonNull View view) {
        InterfaceC2872b interfaceC2872b = this.f10513D0;
        if (interfaceC2872b != null) {
            super.removeView(((C2890a) interfaceC2872b).f7903c);
        }
        C4073j c4073j = new C4073j(-1, -1);
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (layoutParams instanceof C4073j) {
            c4073j = (C4073j) layoutParams;
        }
        super.addView(view, getChildCount(), c4073j);
        this.f10513D0 = new C2890a(view);
        if (this.f10531M0) {
            View findViewById = findViewById(this.f10586x);
            View findViewById2 = findViewById(this.f10588y);
            ((C2890a) this.f10513D0).m3344f(this.f10561k0);
            C2890a c2890a = (C2890a) this.f10513D0;
            c2890a.f7911l.f7898c = this.f10546W;
            c2890a.m3345g(this.f10519G0, findViewById, findViewById2);
        }
        InterfaceC2871a interfaceC2871a = this.f10509B0;
        if (interfaceC2871a != null && interfaceC2871a.getSpinnerStyle().f7894h) {
            super.bringChildToFront(this.f10509B0.getView());
        }
        InterfaceC2871a interfaceC2871a2 = this.f10511C0;
        if (interfaceC2871a2 != null && interfaceC2871a2.getSpinnerStyle().f7894h) {
            super.bringChildToFront(this.f10511C0.getView());
        }
        return this;
    }

    /* JADX WARN: Code restructure failed: missing block: B:48:0x00c9, code lost:
    
        if (r4 <= r14.f10573q0) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x00d0, code lost:
    
        if (r4 >= (-r14.f10577s0)) goto L67;
     */
    /* renamed from: y */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean m4619y(float r14) {
        /*
            Method dump skipped, instructions count: 324
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.scwang.smart.refresh.layout.SmartRefreshLayout.m4619y(float):boolean");
    }

    public SmartRefreshLayout(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f10562l = IjkMediaCodecInfo.RANK_SECURE;
        this.f10564m = IjkMediaCodecInfo.RANK_SECURE;
        this.f10576s = 0.5f;
        this.f10578t = 'n';
        this.f10586x = -1;
        this.f10588y = -1;
        this.f10590z = -1;
        this.f10506A = -1;
        this.f10522I = true;
        this.f10524J = false;
        this.f10526K = true;
        this.f10528L = true;
        this.f10530M = true;
        this.f10532N = true;
        this.f10534O = false;
        this.f10536P = true;
        this.f10538Q = true;
        this.f10540R = false;
        this.f10542S = true;
        this.f10543T = false;
        this.f10544U = true;
        this.f10545V = true;
        this.f10546W = true;
        this.f10547a0 = true;
        this.f10548b0 = false;
        this.f10549c0 = false;
        this.f10550d0 = false;
        this.f10551e0 = false;
        this.f10552f0 = false;
        this.f10553g0 = false;
        this.f10555h0 = false;
        this.f10567n0 = new int[2];
        this.f10569o0 = new NestedScrollingChildHelper(this);
        this.f10571p0 = new NestedScrollingParentHelper(this);
        C2877a c2877a = C2877a.f7847a;
        this.f10575r0 = c2877a;
        this.f10579t0 = c2877a;
        this.f10585w0 = 2.5f;
        this.f10587x0 = 2.5f;
        this.f10589y0 = 1.0f;
        this.f10591z0 = 1.0f;
        this.f10507A0 = 0.16666667f;
        this.f10519G0 = new C4074k();
        EnumC2878b enumC2878b = EnumC2878b.None;
        this.f10521H0 = enumC2878b;
        this.f10523I0 = enumC2878b;
        this.f10525J0 = 0L;
        this.f10527K0 = 0;
        this.f10529L0 = 0;
        this.f10533N0 = false;
        this.f10535O0 = false;
        this.f10537P0 = null;
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        this.f10517F0 = new Handler(Looper.getMainLooper());
        this.f10514E = new Scroller(context);
        this.f10516F = VelocityTracker.obtain();
        this.f10566n = context.getResources().getDisplayMetrics().heightPixels;
        float f2 = InterpolatorC2889b.f7900a;
        this.f10518G = new InterpolatorC2889b(0);
        this.f10554h = viewConfiguration.getScaledTouchSlop();
        this.f10508B = viewConfiguration.getScaledMinimumFlingVelocity();
        this.f10510C = viewConfiguration.getScaledMaximumFlingVelocity();
        this.f10577s0 = InterpolatorC2889b.m3333c(60.0f);
        this.f10573q0 = InterpolatorC2889b.m3333c(100.0f);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.SmartRefreshLayout);
        if (!obtainStyledAttributes.hasValue(R$styleable.SmartRefreshLayout_android_clipToPadding)) {
            super.setClipToPadding(false);
        }
        if (!obtainStyledAttributes.hasValue(R$styleable.SmartRefreshLayout_android_clipChildren)) {
            super.setClipChildren(false);
        }
        InterfaceC2883d interfaceC2883d = f10504f;
        if (interfaceC2883d != null) {
            Objects.requireNonNull((C0881d) interfaceC2883d);
            MyApp myApp = MyApp.f9891f;
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(this, "layout");
            m4616u(false);
            mo3322c(false);
            int[] iArr = new int[2];
            Resources resources = MyApp.f9895j;
            if (resources == null) {
                Intrinsics.throwUninitializedPropertyAccessException("resourses");
                throw null;
            }
            iArr[0] = resources.getColor(R.color.transparent);
            Resources resources2 = MyApp.f9895j;
            if (resources2 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("resourses");
                throw null;
            }
            iArr[1] = resources2.getColor(R.color.black26);
            m4617w(iArr);
        }
        this.f10576s = obtainStyledAttributes.getFloat(R$styleable.SmartRefreshLayout_srlDragRate, this.f10576s);
        this.f10585w0 = obtainStyledAttributes.getFloat(R$styleable.SmartRefreshLayout_srlHeaderMaxDragRate, this.f10585w0);
        this.f10587x0 = obtainStyledAttributes.getFloat(R$styleable.SmartRefreshLayout_srlFooterMaxDragRate, this.f10587x0);
        this.f10589y0 = obtainStyledAttributes.getFloat(R$styleable.SmartRefreshLayout_srlHeaderTriggerRate, this.f10589y0);
        this.f10591z0 = obtainStyledAttributes.getFloat(R$styleable.SmartRefreshLayout_srlFooterTriggerRate, this.f10591z0);
        this.f10522I = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableRefresh, this.f10522I);
        this.f10564m = obtainStyledAttributes.getInt(R$styleable.SmartRefreshLayout_srlReboundDuration, this.f10564m);
        int i2 = R$styleable.SmartRefreshLayout_srlEnableLoadMore;
        this.f10524J = obtainStyledAttributes.getBoolean(i2, this.f10524J);
        int i3 = R$styleable.SmartRefreshLayout_srlHeaderHeight;
        this.f10573q0 = obtainStyledAttributes.getDimensionPixelOffset(i3, this.f10573q0);
        int i4 = R$styleable.SmartRefreshLayout_srlFooterHeight;
        this.f10577s0 = obtainStyledAttributes.getDimensionPixelOffset(i4, this.f10577s0);
        this.f10581u0 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.SmartRefreshLayout_srlHeaderInsetStart, this.f10581u0);
        this.f10583v0 = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.SmartRefreshLayout_srlFooterInsetStart, this.f10583v0);
        this.f10548b0 = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlDisableContentWhenRefresh, this.f10548b0);
        this.f10549c0 = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlDisableContentWhenLoading, this.f10549c0);
        int i5 = R$styleable.SmartRefreshLayout_srlEnableHeaderTranslationContent;
        this.f10530M = obtainStyledAttributes.getBoolean(i5, this.f10530M);
        int i6 = R$styleable.SmartRefreshLayout_srlEnableFooterTranslationContent;
        this.f10532N = obtainStyledAttributes.getBoolean(i6, this.f10532N);
        this.f10536P = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnablePreviewInEditMode, this.f10536P);
        this.f10542S = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableAutoLoadMore, this.f10542S);
        this.f10538Q = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableOverScrollBounce, this.f10538Q);
        this.f10543T = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnablePureScrollMode, this.f10543T);
        this.f10544U = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableScrollContentWhenLoaded, this.f10544U);
        this.f10545V = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableScrollContentWhenRefreshed, this.f10545V);
        this.f10546W = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableLoadMoreWhenContentNotFull, this.f10546W);
        boolean z = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableFooterFollowWhenLoadFinished, this.f10534O);
        this.f10534O = z;
        this.f10534O = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableFooterFollowWhenNoMoreData, z);
        this.f10526K = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableClipHeaderWhenFixedBehind, this.f10526K);
        this.f10528L = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableClipFooterWhenFixedBehind, this.f10528L);
        this.f10540R = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableOverScrollDrag, this.f10540R);
        this.f10586x = obtainStyledAttributes.getResourceId(R$styleable.SmartRefreshLayout_srlFixedHeaderViewId, this.f10586x);
        this.f10588y = obtainStyledAttributes.getResourceId(R$styleable.SmartRefreshLayout_srlFixedFooterViewId, this.f10588y);
        this.f10590z = obtainStyledAttributes.getResourceId(R$styleable.SmartRefreshLayout_srlHeaderTranslationViewId, this.f10590z);
        this.f10506A = obtainStyledAttributes.getResourceId(R$styleable.SmartRefreshLayout_srlFooterTranslationViewId, this.f10506A);
        boolean z2 = obtainStyledAttributes.getBoolean(R$styleable.SmartRefreshLayout_srlEnableNestedScrolling, this.f10547a0);
        this.f10547a0 = z2;
        this.f10569o0.setNestedScrollingEnabled(z2);
        this.f10552f0 = this.f10552f0 || obtainStyledAttributes.hasValue(i2);
        this.f10553g0 = this.f10553g0 || obtainStyledAttributes.hasValue(i5);
        this.f10555h0 = this.f10555h0 || obtainStyledAttributes.hasValue(i6);
        this.f10575r0 = obtainStyledAttributes.hasValue(i3) ? C2877a.f7853g : this.f10575r0;
        this.f10579t0 = obtainStyledAttributes.hasValue(i4) ? C2877a.f7853g : this.f10579t0;
        int color = obtainStyledAttributes.getColor(R$styleable.SmartRefreshLayout_srlAccentColor, 0);
        int color2 = obtainStyledAttributes.getColor(R$styleable.SmartRefreshLayout_srlPrimaryColor, 0);
        if (color2 != 0) {
            if (color != 0) {
                this.f10520H = new int[]{color2, color};
            } else {
                this.f10520H = new int[]{color2};
            }
        } else if (color != 0) {
            this.f10520H = new int[]{0, color};
        }
        if (this.f10543T && !this.f10552f0 && !this.f10524J) {
            this.f10524J = true;
        }
        obtainStyledAttributes.recycle();
    }

    /* renamed from: com.scwang.smart.refresh.layout.SmartRefreshLayout$j */
    public static class C4073j extends ViewGroup.MarginLayoutParams {

        /* renamed from: a */
        public int f10623a;

        /* renamed from: b */
        public C2879c f10624b;

        public C4073j(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
            this.f10623a = 0;
            this.f10624b = null;
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.SmartRefreshLayout_Layout);
            this.f10623a = obtainStyledAttributes.getColor(R$styleable.SmartRefreshLayout_Layout_layout_srlBackgroundColor, this.f10623a);
            int i2 = R$styleable.SmartRefreshLayout_Layout_layout_srlSpinnerStyle;
            if (obtainStyledAttributes.hasValue(i2)) {
                this.f10624b = C2879c.f7892f[obtainStyledAttributes.getInt(i2, 0)];
            }
            obtainStyledAttributes.recycle();
        }

        public C4073j(int i2, int i3) {
            super(i2, i3);
            this.f10623a = 0;
            this.f10624b = null;
        }
    }
}
