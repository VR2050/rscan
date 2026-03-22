package com.gyf.immersionbar.components;

import android.content.res.Configuration;
import android.os.Bundle;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import p005b.p290m.p291a.p292a.C2635d;
import p005b.p290m.p291a.p292a.InterfaceC2634c;

/* loaded from: classes2.dex */
public abstract class SimpleImmersionFragment extends Fragment implements InterfaceC2634c {

    /* renamed from: c */
    public C2635d f9874c = new C2635d(this);

    @Override // p005b.p290m.p291a.p292a.InterfaceC2634c
    /* renamed from: b */
    public boolean mo3106b() {
        return true;
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityCreated(@Nullable Bundle bundle) {
        super.onActivityCreated(bundle);
        C2635d c2635d = this.f9874c;
        c2635d.f7183c = true;
        c2635d.m3107a();
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        this.f9874c.m3107a();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        C2635d c2635d = this.f9874c;
        c2635d.f7181a = null;
        c2635d.f7182b = null;
    }

    @Override // androidx.fragment.app.Fragment
    public void onHiddenChanged(boolean z) {
        super.onHiddenChanged(z);
        Fragment fragment = this.f9874c.f7181a;
        if (fragment != null) {
            fragment.setUserVisibleHint(!z);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void setUserVisibleHint(boolean z) {
        super.setUserVisibleHint(z);
        this.f9874c.m3107a();
    }
}
