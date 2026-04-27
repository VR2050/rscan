package com.just.agentweb;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import java.io.File;
import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public final class AgentActionFragment extends Fragment {
    public static final String FRAGMENT_TAG = "AgentWebActionFragment";
    public static final String KEY_FROM_INTENTION = "KEY_FROM_INTENTION";
    public static final String KEY_URI = "KEY_URI";
    public static final int REQUEST_CODE = 596;
    private static final String TAG = AgentActionFragment.class.getSimpleName();
    private boolean isViewCreated = false;
    private Action mAction;

    public interface ChooserListener {
        void onChoiceResult(int i, int i2, Intent intent);
    }

    public interface PermissionListener {
        void onRequestPermissionsResult(String[] strArr, int[] iArr, Bundle bundle);
    }

    public interface RationaleListener {
        void onRationaleResult(boolean z, Bundle bundle);
    }

    public static void start(Activity activity, Action action) {
        FragmentActivity fragmentActivity = (FragmentActivity) activity;
        FragmentManager fragmentManager = fragmentActivity.getSupportFragmentManager();
        AgentActionFragment fragment = (AgentActionFragment) fragmentManager.findFragmentByTag(FRAGMENT_TAG);
        if (fragment == null) {
            fragment = new AgentActionFragment();
            fragmentManager.beginTransaction().add(fragment, FRAGMENT_TAG).commitAllowingStateLoss();
        }
        fragment.mAction = action;
        if (fragment.isViewCreated) {
            fragment.runAction();
        }
    }

    private void resetAction() {
    }

    @Override // androidx.fragment.app.Fragment
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (savedInstanceState != null) {
            LogUtils.i(TAG, "savedInstanceState:" + savedInstanceState);
            return;
        }
        this.isViewCreated = true;
        runAction();
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
    }

    private void runAction() {
        Action action = this.mAction;
        if (action == null) {
            resetAction();
            return;
        }
        if (action.getAction() == 1) {
            if (Build.VERSION.SDK_INT >= 23) {
                requestPermission(this.mAction);
                return;
            } else {
                resetAction();
                return;
            }
        }
        if (this.mAction.getAction() == 3) {
            captureCamera();
        } else if (this.mAction.getAction() == 4) {
            recordVideo();
        } else {
            choose();
        }
    }

    private void choose() {
        try {
            if (this.mAction.getChooserListener() == null) {
                return;
            }
            Intent mIntent = this.mAction.getIntent();
            if (mIntent == null) {
                resetAction();
            } else {
                startActivityForResult(mIntent, REQUEST_CODE);
            }
        } catch (Throwable throwable) {
            LogUtils.i(TAG, "找不到文件选择器");
            chooserActionCallback(-1, null);
            if (LogUtils.isDebug()) {
                throwable.printStackTrace();
            }
        }
    }

    private void chooserActionCallback(int resultCode, Intent data) {
        if (this.mAction.getChooserListener() != null) {
            this.mAction.getChooserListener().onChoiceResult(REQUEST_CODE, resultCode, data);
        }
        resetAction();
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == 596) {
            if (this.mAction.getUri() != null) {
                chooserActionCallback(resultCode, new Intent().putExtra(KEY_URI, this.mAction.getUri()));
            } else {
                chooserActionCallback(resultCode, data);
            }
        }
        resetAction();
    }

    private void requestPermission(Action action) {
        List<String> permissions = action.getPermissions();
        if (AgentWebUtils.isEmptyCollection(permissions)) {
            resetAction();
            return;
        }
        if (this.mAction.getRationaleListener() != null) {
            boolean rationale = false;
            for (String permission : permissions) {
                rationale = shouldShowRequestPermissionRationale(permission);
                if (rationale) {
                    break;
                }
            }
            this.mAction.getRationaleListener().onRationaleResult(rationale, new Bundle());
            resetAction();
            return;
        }
        if (this.mAction.getPermissionListener() != null) {
            requestPermissions((String[]) permissions.toArray(new String[0]), 1);
        }
    }

    private void captureCamera() {
        try {
            if (this.mAction.getChooserListener() == null) {
                resetAction();
                return;
            }
            File mFile = AgentWebUtils.createImageFile(getActivity());
            if (mFile == null) {
                this.mAction.getChooserListener().onChoiceResult(REQUEST_CODE, 0, null);
            }
            Intent intent = AgentWebUtils.getIntentCaptureCompat(getActivity(), mFile);
            this.mAction.setUri((Uri) intent.getParcelableExtra("output"));
            startActivityForResult(intent, REQUEST_CODE);
        } catch (Throwable ignore) {
            LogUtils.e(TAG, "找不到系统相机");
            if (this.mAction.getChooserListener() != null) {
                this.mAction.getChooserListener().onChoiceResult(REQUEST_CODE, 0, null);
            }
            resetAction();
            if (LogUtils.isDebug()) {
                ignore.printStackTrace();
            }
        }
    }

    private void recordVideo() {
        try {
            if (this.mAction.getChooserListener() == null) {
                resetAction();
                return;
            }
            File mFile = AgentWebUtils.createVideoFile(getActivity());
            if (mFile == null) {
                this.mAction.getChooserListener().onChoiceResult(REQUEST_CODE, 0, null);
                resetAction();
            } else {
                Intent intent = AgentWebUtils.getIntentVideoCompat(getActivity(), mFile);
                this.mAction.setUri((Uri) intent.getParcelableExtra("output"));
                startActivityForResult(intent, REQUEST_CODE);
            }
        } catch (Throwable ignore) {
            LogUtils.e(TAG, "找不到系统相机");
            if (this.mAction.getChooserListener() != null) {
                this.mAction.getChooserListener().onChoiceResult(REQUEST_CODE, 0, null);
            }
            resetAction();
            if (LogUtils.isDebug()) {
                ignore.printStackTrace();
            }
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (this.mAction.getPermissionListener() != null) {
            Bundle mBundle = new Bundle();
            mBundle.putInt(KEY_FROM_INTENTION, this.mAction.getFromIntention());
            this.mAction.getPermissionListener().onRequestPermissionsResult(permissions, grantResults, mBundle);
        }
        resetAction();
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
    }
}
