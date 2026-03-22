package com.gyf.immersionbar.components;

import android.content.res.Configuration;
import android.os.Bundle;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import p005b.p290m.p291a.p292a.C2633b;
import p005b.p290m.p291a.p292a.InterfaceC2632a;

/* loaded from: classes2.dex */
public abstract class ImmersionFragment extends Fragment implements InterfaceC2632a {

    /* renamed from: c */
    public C2633b f9873c = new C2633b(this);

    @Override // p005b.p290m.p291a.p292a.InterfaceC2632a
    /* renamed from: b */
    public boolean mo3100b() {
        return true;
    }

    @Override // p005b.p290m.p291a.p292a.InterfaceC2632a
    /* renamed from: c */
    public void mo3101c() {
    }

    @Override // p005b.p290m.p291a.p292a.InterfaceC2632a
    /* renamed from: d */
    public void mo3102d() {
    }

    @Override // p005b.p290m.p291a.p292a.InterfaceC2632a
    /* renamed from: e */
    public void mo3103e() {
    }

    @Override // p005b.p290m.p291a.p292a.InterfaceC2632a
    /* renamed from: f */
    public void mo3104f() {
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityCreated(@Nullable Bundle bundle) {
        super.onActivityCreated(bundle);
        C2633b c2633b = this.f9873c;
        c2633b.f7178c = true;
        Fragment fragment = c2633b.f7176a;
        if (fragment == null || !fragment.getUserVisibleHint()) {
            return;
        }
        if (c2633b.f7177b.mo3100b()) {
            c2633b.f7177b.m3099a();
        }
        if (c2633b.f7179d) {
            return;
        }
        c2633b.f7177b.mo3101c();
        c2633b.f7179d = true;
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        C2633b c2633b = this.f9873c;
        Fragment fragment = c2633b.f7176a;
        if (fragment == null || !fragment.getUserVisibleHint()) {
            return;
        }
        if (c2633b.f7177b.mo3100b()) {
            c2633b.f7177b.m3099a();
        }
        c2633b.f7177b.mo3102d();
    }

    @Override // androidx.fragment.app.Fragment
    public void onCreate(@Nullable Bundle bundle) {
        super.onCreate(bundle);
        C2633b c2633b = this.f9873c;
        Fragment fragment = c2633b.f7176a;
        if (fragment == null || !fragment.getUserVisibleHint() || c2633b.f7180e) {
            return;
        }
        c2633b.f7177b.mo3104f();
        c2633b.f7180e = true;
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        C2633b c2633b = this.f9873c;
        c2633b.f7176a = null;
        c2633b.f7177b = null;
    }

    @Override // androidx.fragment.app.Fragment
    public void onHiddenChanged(boolean z) {
        super.onHiddenChanged(z);
        Fragment fragment = this.f9873c.f7176a;
        if (fragment != null) {
            fragment.setUserVisibleHint(!z);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        C2633b c2633b = this.f9873c;
        if (c2633b.f7176a != null) {
            c2633b.f7177b.mo3103e();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        C2633b c2633b = this.f9873c;
        Fragment fragment = c2633b.f7176a;
        if (fragment == null || !fragment.getUserVisibleHint()) {
            return;
        }
        c2633b.f7177b.mo3102d();
    }

    @Override // androidx.fragment.app.Fragment
    public void setUserVisibleHint(boolean z) {
        super.setUserVisibleHint(z);
        C2633b c2633b = this.f9873c;
        Fragment fragment = c2633b.f7176a;
        if (fragment != null) {
            if (!fragment.getUserVisibleHint()) {
                if (c2633b.f7178c) {
                    c2633b.f7177b.mo3103e();
                    return;
                }
                return;
            }
            if (!c2633b.f7180e) {
                c2633b.f7177b.mo3104f();
                c2633b.f7180e = true;
            }
            if (c2633b.f7178c && c2633b.f7176a.getUserVisibleHint()) {
                if (c2633b.f7177b.mo3100b()) {
                    c2633b.f7177b.m3099a();
                }
                if (!c2633b.f7179d) {
                    c2633b.f7177b.mo3101c();
                    c2633b.f7179d = true;
                }
                c2633b.f7177b.mo3102d();
            }
        }
    }
}
