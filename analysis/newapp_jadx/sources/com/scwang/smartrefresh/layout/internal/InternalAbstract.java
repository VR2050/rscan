package com.scwang.smartrefresh.layout.internal;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.impl.RefreshFooterWrapper;
import com.scwang.smartrefresh.layout.impl.RefreshHeaderWrapper;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2896e;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2897f;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2898g;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2899h;
import p005b.p340x.p354b.p355a.p356b.InterfaceC2900i;
import p005b.p340x.p354b.p355a.p357c.C2904c;
import p005b.p340x.p354b.p355a.p357c.EnumC2903b;

/* loaded from: classes2.dex */
public abstract class InternalAbstract extends RelativeLayout implements InterfaceC2898g {

    /* renamed from: c */
    public View f10743c;

    /* renamed from: e */
    public C2904c f10744e;

    /* renamed from: f */
    public InterfaceC2898g f10745f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public InternalAbstract(@NonNull View view) {
        super(view.getContext(), null, 0);
        InterfaceC2898g interfaceC2898g = view instanceof InterfaceC2898g ? (InterfaceC2898g) view : null;
        this.f10743c = view;
        this.f10745f = interfaceC2898g;
        if ((this instanceof RefreshFooterWrapper) && (interfaceC2898g instanceof InterfaceC2897f) && interfaceC2898g.getSpinnerStyle() == C2904c.f7957e) {
            interfaceC2898g.getView().setScaleY(-1.0f);
            return;
        }
        if (this instanceof RefreshHeaderWrapper) {
            InterfaceC2898g interfaceC2898g2 = this.f10745f;
            if ((interfaceC2898g2 instanceof InterfaceC2896e) && interfaceC2898g2.getSpinnerStyle() == C2904c.f7957e) {
                interfaceC2898g.getView().setScaleY(-1.0f);
            }
        }
    }

    @SuppressLint({"RestrictedApi"})
    /* renamed from: a */
    public boolean mo3349a(boolean z) {
        InterfaceC2898g interfaceC2898g = this.f10745f;
        return (interfaceC2898g instanceof InterfaceC2896e) && ((InterfaceC2896e) interfaceC2898g).mo3349a(z);
    }

    /* renamed from: b */
    public void mo3350b(float f2, int i2, int i3) {
        InterfaceC2898g interfaceC2898g = this.f10745f;
        if (interfaceC2898g == null || interfaceC2898g == this) {
            return;
        }
        interfaceC2898g.mo3350b(f2, i2, i3);
    }

    /* renamed from: c */
    public boolean mo3351c() {
        InterfaceC2898g interfaceC2898g = this.f10745f;
        return (interfaceC2898g == null || interfaceC2898g == this || !interfaceC2898g.mo3351c()) ? false : true;
    }

    /* renamed from: d */
    public void mo3352d(boolean z, float f2, int i2, int i3, int i4) {
        InterfaceC2898g interfaceC2898g = this.f10745f;
        if (interfaceC2898g == null || interfaceC2898g == this) {
            return;
        }
        interfaceC2898g.mo3352d(z, f2, i2, i3, i4);
    }

    /* renamed from: e */
    public void mo3379e(@NonNull InterfaceC2900i interfaceC2900i, @NonNull EnumC2903b enumC2903b, @NonNull EnumC2903b enumC2903b2) {
        InterfaceC2898g interfaceC2898g = this.f10745f;
        if (interfaceC2898g == null || interfaceC2898g == this) {
            return;
        }
        if ((this instanceof RefreshFooterWrapper) && (interfaceC2898g instanceof InterfaceC2897f)) {
            if (enumC2903b.f7949w) {
                enumC2903b = enumC2903b.m3360b();
            }
            if (enumC2903b2.f7949w) {
                enumC2903b2 = enumC2903b2.m3360b();
            }
        } else if ((this instanceof RefreshHeaderWrapper) && (interfaceC2898g instanceof InterfaceC2896e)) {
            if (enumC2903b.f7948v) {
                enumC2903b = enumC2903b.m3359a();
            }
            if (enumC2903b2.f7948v) {
                enumC2903b2 = enumC2903b2.m3359a();
            }
        }
        InterfaceC2898g interfaceC2898g2 = this.f10745f;
        if (interfaceC2898g2 != null) {
            interfaceC2898g2.mo3379e(interfaceC2900i, enumC2903b, enumC2903b2);
        }
    }

    public boolean equals(Object obj) {
        if (super.equals(obj)) {
            return true;
        }
        return (obj instanceof InterfaceC2898g) && getView() == ((InterfaceC2898g) obj).getView();
    }

    /* renamed from: f */
    public void mo3353f(@NonNull InterfaceC2900i interfaceC2900i, int i2, int i3) {
        InterfaceC2898g interfaceC2898g = this.f10745f;
        if (interfaceC2898g == null || interfaceC2898g == this) {
            return;
        }
        interfaceC2898g.mo3353f(interfaceC2900i, i2, i3);
    }

    @Override // p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    @NonNull
    public C2904c getSpinnerStyle() {
        int i2;
        C2904c c2904c = this.f10744e;
        if (c2904c != null) {
            return c2904c;
        }
        InterfaceC2898g interfaceC2898g = this.f10745f;
        if (interfaceC2898g != null && interfaceC2898g != this) {
            return interfaceC2898g.getSpinnerStyle();
        }
        View view = this.f10743c;
        if (view != null) {
            ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
            if (layoutParams instanceof SmartRefreshLayout.C4086l) {
                C2904c c2904c2 = ((SmartRefreshLayout.C4086l) layoutParams).f10673b;
                this.f10744e = c2904c2;
                if (c2904c2 != null) {
                    return c2904c2;
                }
            }
            if (layoutParams != null && ((i2 = layoutParams.height) == 0 || i2 == -1)) {
                for (C2904c c2904c3 : C2904c.f7958f) {
                    if (c2904c3.f7961i) {
                        this.f10744e = c2904c3;
                        return c2904c3;
                    }
                }
            }
        }
        C2904c c2904c4 = C2904c.f7953a;
        this.f10744e = c2904c4;
        return c2904c4;
    }

    @Override // p005b.p340x.p354b.p355a.p356b.InterfaceC2898g
    @NonNull
    public View getView() {
        View view = this.f10743c;
        return view == null ? this : view;
    }

    /* renamed from: j */
    public int mo3354j(@NonNull InterfaceC2900i interfaceC2900i, boolean z) {
        InterfaceC2898g interfaceC2898g = this.f10745f;
        if (interfaceC2898g == null || interfaceC2898g == this) {
            return 0;
        }
        return interfaceC2898g.mo3354j(interfaceC2900i, z);
    }

    /* renamed from: k */
    public void mo3355k(@NonNull InterfaceC2900i interfaceC2900i, int i2, int i3) {
        InterfaceC2898g interfaceC2898g = this.f10745f;
        if (interfaceC2898g == null || interfaceC2898g == this) {
            return;
        }
        interfaceC2898g.mo3355k(interfaceC2900i, i2, i3);
    }

    /* renamed from: o */
    public void mo3356o(@NonNull InterfaceC2899h interfaceC2899h, int i2, int i3) {
        InterfaceC2898g interfaceC2898g = this.f10745f;
        if (interfaceC2898g != null && interfaceC2898g != this) {
            interfaceC2898g.mo3356o(interfaceC2899h, i2, i3);
            return;
        }
        View view = this.f10743c;
        if (view != null) {
            ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
            if (layoutParams instanceof SmartRefreshLayout.C4086l) {
                ((SmartRefreshLayout.C4087m) interfaceC2899h).m4626c(this, ((SmartRefreshLayout.C4086l) layoutParams).f10672a);
            }
        }
    }

    public void setPrimaryColors(@ColorInt int... iArr) {
        InterfaceC2898g interfaceC2898g = this.f10745f;
        if (interfaceC2898g == null || interfaceC2898g == this) {
            return;
        }
        interfaceC2898g.setPrimaryColors(iArr);
    }

    public InternalAbstract(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
    }
}
