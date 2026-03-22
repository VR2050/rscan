package com.king.zxing;

import android.hardware.Camera;
import android.os.Bundle;
import android.view.MotionEvent;
import android.view.SurfaceView;
import android.view.View;
import androidx.annotation.LayoutRes;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import p005b.p310s.p311a.InterfaceC2744n;
import p005b.p310s.p311a.SurfaceHolderCallbackC2739i;
import p005b.p310s.p311a.p312o.C2748d;

/* loaded from: classes2.dex */
public class CaptureActivity extends AppCompatActivity implements InterfaceC2744n {
    public static final String KEY_RESULT = "SCAN_RESULT";
    private View ivTorch;
    private SurfaceHolderCallbackC2739i mCaptureHelper;
    private SurfaceView surfaceView;
    private ViewfinderView viewfinderView;

    @Deprecated
    public C2748d getCameraManager() {
        return this.mCaptureHelper.f7466h;
    }

    public SurfaceHolderCallbackC2739i getCaptureHelper() {
        return this.mCaptureHelper;
    }

    public int getIvTorchId() {
        return R$id.ivTorch;
    }

    public int getLayoutId() {
        return R$layout.zxl_capture;
    }

    public int getSurfaceViewId() {
        return R$id.surfaceView;
    }

    public int getViewfinderViewId() {
        return R$id.viewfinderView;
    }

    public void initUI() {
        this.surfaceView = (SurfaceView) findViewById(getSurfaceViewId());
        this.viewfinderView = (ViewfinderView) findViewById(getViewfinderViewId());
        int ivTorchId = getIvTorchId();
        if (ivTorchId != 0) {
            View findViewById = findViewById(ivTorchId);
            this.ivTorch = findViewById;
            findViewById.setVisibility(4);
        }
        SurfaceHolderCallbackC2739i surfaceHolderCallbackC2739i = new SurfaceHolderCallbackC2739i(this, this.surfaceView, this.viewfinderView, this.ivTorch);
        this.mCaptureHelper = surfaceHolderCallbackC2739i;
        surfaceHolderCallbackC2739i.f7461B = this;
        surfaceHolderCallbackC2739i.m3248d();
    }

    public boolean isContentView(@LayoutRes int i2) {
        return true;
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle bundle) {
        super.onCreate(bundle);
        int layoutId = getLayoutId();
        if (isContentView(layoutId)) {
            setContentView(layoutId);
        }
        initUI();
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        this.mCaptureHelper.f7467i.m3254a();
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onPause() {
        super.onPause();
        this.mCaptureHelper.m3249e();
    }

    @Override // p005b.p310s.p311a.InterfaceC2744n
    public boolean onResultCallback(String str) {
        return false;
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        this.mCaptureHelper.m3250f();
    }

    @Override // android.app.Activity
    public boolean onTouchEvent(MotionEvent motionEvent) {
        Camera camera;
        SurfaceHolderCallbackC2739i surfaceHolderCallbackC2739i = this.mCaptureHelper;
        if (surfaceHolderCallbackC2739i.f7475q && surfaceHolderCallbackC2739i.f7466h.m3266c() && (camera = surfaceHolderCallbackC2739i.f7466h.f7531c.f7555b) != null && motionEvent.getPointerCount() > 1) {
            int action = motionEvent.getAction() & 255;
            if (action == 2) {
                float m3245a = surfaceHolderCallbackC2739i.m3245a(motionEvent);
                float f2 = surfaceHolderCallbackC2739i.f7476r;
                if (m3245a > f2 + 6.0f) {
                    surfaceHolderCallbackC2739i.m3246b(true, camera);
                } else if (m3245a < f2 - 6.0f) {
                    surfaceHolderCallbackC2739i.m3246b(false, camera);
                }
                surfaceHolderCallbackC2739i.f7476r = m3245a;
            } else if (action == 5) {
                surfaceHolderCallbackC2739i.f7476r = surfaceHolderCallbackC2739i.m3245a(motionEvent);
            }
        }
        return super.onTouchEvent(motionEvent);
    }
}
