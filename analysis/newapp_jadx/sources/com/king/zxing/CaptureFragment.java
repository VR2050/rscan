package com.king.zxing;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.SurfaceView;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import p005b.p310s.p311a.InterfaceC2744n;
import p005b.p310s.p311a.SurfaceHolderCallbackC2739i;

/* loaded from: classes2.dex */
public class CaptureFragment extends Fragment implements InterfaceC2744n {

    /* renamed from: c */
    public View f10151c;

    /* renamed from: e */
    public SurfaceView f10152e;

    /* renamed from: f */
    public ViewfinderView f10153f;

    /* renamed from: g */
    public View f10154g;

    /* renamed from: h */
    public SurfaceHolderCallbackC2739i f10155h;

    /* renamed from: g */
    public boolean m4520g() {
        return true;
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityCreated(@Nullable Bundle bundle) {
        super.onActivityCreated(bundle);
        this.f10155h.m3248d();
    }

    @Override // androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        int i2 = R$layout.zxl_capture;
        if (m4520g()) {
            this.f10151c = layoutInflater.inflate(i2, viewGroup, false);
        }
        this.f10152e = (SurfaceView) this.f10151c.findViewById(R$id.surfaceView);
        this.f10153f = (ViewfinderView) this.f10151c.findViewById(R$id.viewfinderView);
        int i3 = R$id.ivTorch;
        if (i3 != 0) {
            View findViewById = this.f10151c.findViewById(i3);
            this.f10154g = findViewById;
            findViewById.setVisibility(4);
        }
        SurfaceHolderCallbackC2739i surfaceHolderCallbackC2739i = new SurfaceHolderCallbackC2739i(getActivity(), this.f10152e, this.f10153f, this.f10154g);
        this.f10155h = surfaceHolderCallbackC2739i;
        surfaceHolderCallbackC2739i.f7461B = this;
        return this.f10151c;
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        this.f10155h.f7467i.m3254a();
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        this.f10155h.m3249e();
    }

    @Override // p005b.p310s.p311a.InterfaceC2744n
    public boolean onResultCallback(String str) {
        return false;
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        this.f10155h.m3250f();
    }
}
