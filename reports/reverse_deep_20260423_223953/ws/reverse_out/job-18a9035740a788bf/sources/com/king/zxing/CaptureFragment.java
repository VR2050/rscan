package com.king.zxing;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.SurfaceView;
import android.view.View;
import android.view.ViewGroup;
import androidx.fragment.app.Fragment;
import com.king.zxing.camera.CameraManager;

/* JADX INFO: loaded from: classes3.dex */
public class CaptureFragment extends Fragment implements OnCaptureCallback {
    public static final String KEY_RESULT = "SCAN_RESULT";
    private View ivTorch;
    private CaptureHelper mCaptureHelper;
    private View mRootView;
    private SurfaceView surfaceView;
    private ViewfinderView viewfinderView;

    public static CaptureFragment newInstance() {
        Bundle args = new Bundle();
        CaptureFragment fragment = new CaptureFragment();
        fragment.setArguments(args);
        return fragment;
    }

    @Override // androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        int layoutId = getLayoutId();
        if (isContentView(layoutId)) {
            this.mRootView = inflater.inflate(getLayoutId(), container, false);
        }
        initUI();
        return this.mRootView;
    }

    public void initUI() {
        this.surfaceView = (SurfaceView) this.mRootView.findViewById(getSurfaceViewId());
        int viewfinderViewId = getViewfinderViewId();
        if (viewfinderViewId != 0) {
            this.viewfinderView = (ViewfinderView) this.mRootView.findViewById(viewfinderViewId);
        }
        int ivTorchId = getIvTorchId();
        if (ivTorchId != 0) {
            View viewFindViewById = this.mRootView.findViewById(ivTorchId);
            this.ivTorch = viewFindViewById;
            viewFindViewById.setVisibility(4);
        }
        initCaptureHelper();
    }

    public void initCaptureHelper() {
        CaptureHelper captureHelper = new CaptureHelper(this, this.surfaceView, this.viewfinderView, this.ivTorch);
        this.mCaptureHelper = captureHelper;
        captureHelper.setOnCaptureCallback(this);
    }

    public boolean isContentView(int layoutId) {
        return true;
    }

    public int getLayoutId() {
        return R.layout.zxl_capture;
    }

    public int getViewfinderViewId() {
        return R.id.viewfinderView;
    }

    public int getSurfaceViewId() {
        return R.id.surfaceView;
    }

    public int getIvTorchId() {
        return R.id.ivTorch;
    }

    public CaptureHelper getCaptureHelper() {
        return this.mCaptureHelper;
    }

    @Deprecated
    public CameraManager getCameraManager() {
        return this.mCaptureHelper.getCameraManager();
    }

    public View getRootView() {
        return this.mRootView;
    }

    public void setRootView(View rootView) {
        this.mRootView = rootView;
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        this.mCaptureHelper.onCreate();
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        this.mCaptureHelper.onResume();
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        this.mCaptureHelper.onPause();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        this.mCaptureHelper.onDestroy();
    }

    @Override // com.king.zxing.OnCaptureCallback
    public boolean onResultCallback(String result) {
        return false;
    }
}
