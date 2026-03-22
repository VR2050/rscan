package com.scwang.smart.refresh.layout.simple;

import android.annotation.SuppressLint;
import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import com.scwang.smart.refresh.layout.SmartRefreshLayout;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2873c;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2874d;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2875e;
import p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2876f;
import p005b.p340x.p341a.p343b.p347c.p349b.C2879c;
import p005b.p340x.p341a.p343b.p347c.p349b.EnumC2878b;

/* loaded from: classes2.dex */
public abstract class SimpleComponent extends RelativeLayout implements InterfaceC2871a {

    /* renamed from: c */
    public View f10626c;

    /* renamed from: e */
    public C2879c f10627e;

    /* renamed from: f */
    public InterfaceC2871a f10628f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public SimpleComponent(@NonNull View view) {
        super(view.getContext(), null, 0);
        InterfaceC2871a interfaceC2871a = view instanceof InterfaceC2871a ? (InterfaceC2871a) view : null;
        this.f10626c = view;
        this.f10628f = interfaceC2871a;
        if ((this instanceof InterfaceC2873c) && (interfaceC2871a instanceof InterfaceC2874d) && interfaceC2871a.getSpinnerStyle() == C2879c.f7891e) {
            interfaceC2871a.getView().setScaleY(-1.0f);
            return;
        }
        if (this instanceof InterfaceC2874d) {
            InterfaceC2871a interfaceC2871a2 = this.f10628f;
            if ((interfaceC2871a2 instanceof InterfaceC2873c) && interfaceC2871a2.getSpinnerStyle() == C2879c.f7891e) {
                interfaceC2871a.getView().setScaleY(-1.0f);
            }
        }
    }

    @SuppressLint({"RestrictedApi"})
    /* renamed from: a */
    public boolean mo3321a(boolean z) {
        InterfaceC2871a interfaceC2871a = this.f10628f;
        return (interfaceC2871a instanceof InterfaceC2873c) && ((InterfaceC2873c) interfaceC2871a).mo3321a(z);
    }

    @Override // p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: b */
    public void mo3314b(float f2, int i2, int i3) {
        InterfaceC2871a interfaceC2871a = this.f10628f;
        if (interfaceC2871a == null || interfaceC2871a == this) {
            return;
        }
        interfaceC2871a.mo3314b(f2, i2, i3);
    }

    @Override // p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    /* renamed from: c */
    public boolean mo3315c() {
        InterfaceC2871a interfaceC2871a = this.f10628f;
        return (interfaceC2871a == null || interfaceC2871a == this || !interfaceC2871a.mo3315c()) ? false : true;
    }

    /* renamed from: d */
    public void mo3316d(boolean z, float f2, int i2, int i3, int i4) {
        InterfaceC2871a interfaceC2871a = this.f10628f;
        if (interfaceC2871a == null || interfaceC2871a == this) {
            return;
        }
        interfaceC2871a.mo3316d(z, f2, i2, i3, i4);
    }

    /* renamed from: e */
    public void mo3317e(@NonNull InterfaceC2876f interfaceC2876f, int i2, int i3) {
        InterfaceC2871a interfaceC2871a = this.f10628f;
        if (interfaceC2871a == null || interfaceC2871a == this) {
            return;
        }
        interfaceC2871a.mo3317e(interfaceC2876f, i2, i3);
    }

    public boolean equals(Object obj) {
        if (super.equals(obj)) {
            return true;
        }
        return (obj instanceof InterfaceC2871a) && getView() == ((InterfaceC2871a) obj).getView();
    }

    /* renamed from: f */
    public int mo3318f(@NonNull InterfaceC2876f interfaceC2876f, boolean z) {
        InterfaceC2871a interfaceC2871a = this.f10628f;
        if (interfaceC2871a == null || interfaceC2871a == this) {
            return 0;
        }
        return interfaceC2871a.mo3318f(interfaceC2876f, z);
    }

    /* renamed from: g */
    public void mo3319g(@NonNull InterfaceC2875e interfaceC2875e, int i2, int i3) {
        InterfaceC2871a interfaceC2871a = this.f10628f;
        if (interfaceC2871a != null && interfaceC2871a != this) {
            interfaceC2871a.mo3319g(interfaceC2875e, i2, i3);
            return;
        }
        View view = this.f10626c;
        if (view != null) {
            ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
            if (layoutParams instanceof SmartRefreshLayout.C4073j) {
                ((SmartRefreshLayout.C4074k) interfaceC2875e).m4622c(this, ((SmartRefreshLayout.C4073j) layoutParams).f10623a);
            }
        }
    }

    @Override // p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    @NonNull
    public C2879c getSpinnerStyle() {
        int i2;
        C2879c c2879c = this.f10627e;
        if (c2879c != null) {
            return c2879c;
        }
        InterfaceC2871a interfaceC2871a = this.f10628f;
        if (interfaceC2871a != null && interfaceC2871a != this) {
            return interfaceC2871a.getSpinnerStyle();
        }
        View view = this.f10626c;
        if (view != null) {
            ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
            if (layoutParams instanceof SmartRefreshLayout.C4073j) {
                C2879c c2879c2 = ((SmartRefreshLayout.C4073j) layoutParams).f10624b;
                this.f10627e = c2879c2;
                if (c2879c2 != null) {
                    return c2879c2;
                }
            }
            if (layoutParams != null && ((i2 = layoutParams.height) == 0 || i2 == -1)) {
                for (C2879c c2879c3 : C2879c.f7892f) {
                    if (c2879c3.f7895i) {
                        this.f10627e = c2879c3;
                        return c2879c3;
                    }
                }
            }
        }
        C2879c c2879c4 = C2879c.f7887a;
        this.f10627e = c2879c4;
        return c2879c4;
    }

    @Override // p005b.p340x.p341a.p343b.p347c.p348a.InterfaceC2871a
    @NonNull
    public View getView() {
        View view = this.f10626c;
        return view == null ? this : view;
    }

    /* renamed from: h */
    public void mo3328h(@NonNull InterfaceC2876f interfaceC2876f, @NonNull EnumC2878b enumC2878b, @NonNull EnumC2878b enumC2878b2) {
        InterfaceC2871a interfaceC2871a = this.f10628f;
        if (interfaceC2871a == null || interfaceC2871a == this) {
            return;
        }
        if ((this instanceof InterfaceC2873c) && (interfaceC2871a instanceof InterfaceC2874d)) {
            if (enumC2878b.f7883w) {
                enumC2878b = enumC2878b.m3325b();
            }
            if (enumC2878b2.f7883w) {
                enumC2878b2 = enumC2878b2.m3325b();
            }
        } else if ((this instanceof InterfaceC2874d) && (interfaceC2871a instanceof InterfaceC2873c)) {
            if (enumC2878b.f7882v) {
                enumC2878b = enumC2878b.m3324a();
            }
            if (enumC2878b2.f7882v) {
                enumC2878b2 = enumC2878b2.m3324a();
            }
        }
        InterfaceC2871a interfaceC2871a2 = this.f10628f;
        if (interfaceC2871a2 != null) {
            interfaceC2871a2.mo3328h(interfaceC2876f, enumC2878b, enumC2878b2);
        }
    }

    /* renamed from: i */
    public void mo3320i(@NonNull InterfaceC2876f interfaceC2876f, int i2, int i3) {
        InterfaceC2871a interfaceC2871a = this.f10628f;
        if (interfaceC2871a == null || interfaceC2871a == this) {
            return;
        }
        interfaceC2871a.mo3320i(interfaceC2876f, i2, i3);
    }

    public void setPrimaryColors(@ColorInt int... iArr) {
        InterfaceC2871a interfaceC2871a = this.f10628f;
        if (interfaceC2871a == null || interfaceC2871a == this) {
            return;
        }
        interfaceC2871a.setPrimaryColors(iArr);
    }

    public SimpleComponent(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
    }
}
