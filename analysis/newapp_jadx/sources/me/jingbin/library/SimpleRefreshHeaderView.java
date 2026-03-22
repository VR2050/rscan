package me.jingbin.library;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.RotateAnimation;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import p448i.p452b.p453a.InterfaceC4355c;

/* loaded from: classes3.dex */
public class SimpleRefreshHeaderView extends LinearLayout implements InterfaceC4355c {

    /* renamed from: c */
    public TextView f12706c;

    /* renamed from: e */
    public ImageView f12707e;

    /* renamed from: f */
    public ProgressBar f12708f;

    /* renamed from: g */
    public LinearLayout f12709g;

    /* renamed from: h */
    public Animation f12710h;

    /* renamed from: i */
    public Animation f12711i;

    /* renamed from: j */
    public int f12712j;

    /* renamed from: k */
    public int f12713k;

    /* renamed from: me.jingbin.library.SimpleRefreshHeaderView$a */
    public class C4967a implements ValueAnimator.AnimatorUpdateListener {
        public C4967a() {
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            SimpleRefreshHeaderView.this.setVisibleHeight(((Integer) valueAnimator.getAnimatedValue()).intValue());
        }
    }

    /* renamed from: me.jingbin.library.SimpleRefreshHeaderView$b */
    public class C4968b extends AnimatorListenerAdapter {

        /* renamed from: c */
        public final /* synthetic */ int f12715c;

        public C4968b(int i2) {
            this.f12715c = i2;
        }

        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
            super.onAnimationEnd(animator);
            if (this.f12715c == 0) {
                SimpleRefreshHeaderView.this.setState(0);
            }
        }
    }

    public SimpleRefreshHeaderView(Context context) {
        super(context);
        this.f12712j = 0;
        ViewGroup.LayoutParams layoutParams = new LinearLayout.LayoutParams(-1, 0);
        LinearLayout linearLayout = (LinearLayout) LayoutInflater.from(context).inflate(R$layout.simple_by_refresh_view, (ViewGroup) null);
        this.f12709g = linearLayout;
        addView(linearLayout, layoutParams);
        setGravity(80);
        this.f12707e = (ImageView) findViewById(R$id.iv_arrow);
        this.f12708f = (ProgressBar) findViewById(R$id.pb_progress);
        this.f12706c = (TextView) findViewById(R$id.tv_refresh_tip);
        measure(-1, -2);
        this.f12713k = getMeasuredHeight();
        RotateAnimation rotateAnimation = new RotateAnimation(0.0f, -180.0f, 1, 0.5f, 1, 0.5f);
        this.f12710h = rotateAnimation;
        rotateAnimation.setDuration(180L);
        this.f12710h.setFillAfter(true);
        RotateAnimation rotateAnimation2 = new RotateAnimation(-180.0f, 0.0f, 1, 0.5f, 1, 0.5f);
        this.f12711i = rotateAnimation2;
        rotateAnimation2.setDuration(180L);
        this.f12711i.setFillAfter(true);
        setLayoutParams(new LinearLayout.LayoutParams(-1, -2));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setVisibleHeight(int i2) {
        if (i2 < 0) {
            i2 = 0;
        }
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) this.f12709g.getLayoutParams();
        layoutParams.height = i2;
        this.f12709g.setLayoutParams(layoutParams);
    }

    /* renamed from: b */
    public void m5631b(float f2) {
        if (getVisibleHeight() > 0 || f2 > 0.0f) {
            setVisibleHeight(getVisibleHeight() + ((int) f2));
            if (this.f12712j <= 1) {
                if (getVisibleHeight() > this.f12713k) {
                    setState(1);
                } else {
                    setState(0);
                }
            }
        }
    }

    /* renamed from: c */
    public final void m5632c(int i2) {
        ValueAnimator ofInt = ValueAnimator.ofInt(getVisibleHeight(), i2);
        ofInt.setDuration(300L).start();
        ofInt.addUpdateListener(new C4967a());
        ofInt.addListener(new C4968b(i2));
        ofInt.start();
    }

    @Override // p448i.p452b.p453a.InterfaceC4355c
    public int getState() {
        return this.f12712j;
    }

    @Override // p448i.p452b.p453a.InterfaceC4355c
    public int getVisibleHeight() {
        return this.f12709g.getHeight();
    }

    @Override // p448i.p452b.p453a.InterfaceC4355c
    public void setState(int i2) {
        if (i2 == this.f12712j) {
            return;
        }
        this.f12706c.setVisibility(0);
        if (i2 == 2) {
            this.f12707e.setVisibility(4);
            this.f12708f.setVisibility(0);
        } else {
            this.f12707e.setVisibility(0);
            this.f12708f.setVisibility(4);
        }
        if (i2 == 0) {
            int i3 = this.f12712j;
            if (i3 == 1) {
                this.f12707e.startAnimation(this.f12711i);
            } else if (i3 == 2) {
                this.f12707e.clearAnimation();
            }
            this.f12706c.setText(R$string.by_header_hint_normal);
        } else if (i2 == 1) {
            this.f12707e.clearAnimation();
            this.f12707e.startAnimation(this.f12710h);
            this.f12706c.setText(R$string.by_header_hint_release);
        } else if (i2 == 2) {
            this.f12707e.clearAnimation();
            m5632c(this.f12713k);
            this.f12706c.setText(R$string.by_refreshing);
        } else if (i2 == 3) {
            this.f12707e.clearAnimation();
            this.f12706c.setText(R$string.by_header_hint_normal);
        }
        this.f12712j = i2;
    }
}
