package com.luck.picture.lib;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.view.CameraView;
import androidx.lifecycle.LifecycleOwner;
import com.luck.picture.lib.PictureCustomCameraActivity;
import com.luck.picture.lib.camera.CustomCameraView;
import com.luck.picture.lib.camera.listener.CameraListener;
import com.luck.picture.lib.camera.listener.ClickListener;
import com.luck.picture.lib.camera.listener.ImageCallbackListener;
import com.luck.picture.lib.camera.view.CaptureLayout;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.dialog.PictureCustomDialog;
import com.luck.picture.lib.engine.ImageEngine;
import com.luck.picture.lib.listener.OnResultCallbackListener;
import com.luck.picture.lib.permissions.PermissionChecker;
import java.io.File;
import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public class PictureCustomCameraActivity extends PictureSelectorCameraEmptyActivity {
    private static final String TAG = PictureCustomCameraActivity.class.getSimpleName();
    public boolean isEnterSetting;
    private CustomCameraView mCameraView;

    private void createCameraView() {
        if (this.mCameraView == null) {
            CustomCameraView customCameraView = new CustomCameraView(getContext());
            this.mCameraView = customCameraView;
            setContentView(customCameraView);
            initView();
        }
    }

    public void initView() {
        this.mCameraView.setPictureSelectionConfig(this.config);
        this.mCameraView.setBindToLifecycle((LifecycleOwner) new WeakReference(this).get());
        int i2 = this.config.recordVideoSecond;
        if (i2 > 0) {
            this.mCameraView.setRecordVideoMaxTime(i2);
        }
        int i3 = this.config.recordVideoMinSecond;
        if (i3 > 0) {
            this.mCameraView.setRecordVideoMinTime(i3);
        }
        CameraView cameraView = this.mCameraView.getCameraView();
        if (cameraView != null && this.config.isCameraAroundState) {
            cameraView.toggleCamera();
        }
        CaptureLayout captureLayout = this.mCameraView.getCaptureLayout();
        if (captureLayout != null) {
            captureLayout.setButtonFeatures(this.config.buttonFeatures);
        }
        this.mCameraView.setImageCallbackListener(new ImageCallbackListener() { // from class: b.t.a.a.f
            @Override // com.luck.picture.lib.camera.listener.ImageCallbackListener
            public final void onLoadImage(File file, ImageView imageView) {
                ImageEngine imageEngine;
                PictureCustomCameraActivity pictureCustomCameraActivity = PictureCustomCameraActivity.this;
                if (pictureCustomCameraActivity.config == null || (imageEngine = PictureSelectionConfig.imageEngine) == null || file == null) {
                    return;
                }
                imageEngine.loadImage(pictureCustomCameraActivity.getContext(), file.getAbsolutePath(), imageView);
            }
        });
        this.mCameraView.setCameraListener(new CameraListener() { // from class: com.luck.picture.lib.PictureCustomCameraActivity.1
            @Override // com.luck.picture.lib.camera.listener.CameraListener
            public void onError(int i4, @NonNull String str, @Nullable Throwable th) {
                String unused = PictureCustomCameraActivity.TAG;
            }

            @Override // com.luck.picture.lib.camera.listener.CameraListener
            public void onPictureSuccess(@NonNull File file) {
                PictureCustomCameraActivity.this.config.cameraMimeType = PictureMimeType.ofImage();
                Intent intent = new Intent();
                intent.putExtra(PictureConfig.EXTRA_MEDIA_PATH, file.getAbsolutePath());
                intent.putExtra(PictureConfig.EXTRA_CONFIG, PictureCustomCameraActivity.this.config);
                PictureCustomCameraActivity pictureCustomCameraActivity = PictureCustomCameraActivity.this;
                if (pictureCustomCameraActivity.config.camera) {
                    pictureCustomCameraActivity.dispatchHandleCamera(intent);
                } else {
                    pictureCustomCameraActivity.setResult(-1, intent);
                    PictureCustomCameraActivity.this.onBackPressed();
                }
            }

            @Override // com.luck.picture.lib.camera.listener.CameraListener
            public void onRecordSuccess(@NonNull File file) {
                PictureCustomCameraActivity.this.config.cameraMimeType = PictureMimeType.ofVideo();
                Intent intent = new Intent();
                intent.putExtra(PictureConfig.EXTRA_MEDIA_PATH, file.getAbsolutePath());
                intent.putExtra(PictureConfig.EXTRA_CONFIG, PictureCustomCameraActivity.this.config);
                PictureCustomCameraActivity pictureCustomCameraActivity = PictureCustomCameraActivity.this;
                if (pictureCustomCameraActivity.config.camera) {
                    pictureCustomCameraActivity.dispatchHandleCamera(intent);
                } else {
                    pictureCustomCameraActivity.setResult(-1, intent);
                    PictureCustomCameraActivity.this.onBackPressed();
                }
            }
        });
        this.mCameraView.setOnClickListener(new ClickListener() { // from class: b.t.a.a.d
            @Override // com.luck.picture.lib.camera.listener.ClickListener
            public final void onClick() {
                PictureCustomCameraActivity.this.onBackPressed();
            }
        });
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, android.app.Activity
    public boolean isImmersive() {
        return false;
    }

    @Override // com.luck.picture.lib.PictureSelectorCameraEmptyActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        OnResultCallbackListener onResultCallbackListener;
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig != null && pictureSelectionConfig.camera && (onResultCallbackListener = PictureSelectionConfig.listener) != null) {
            onResultCallbackListener.onCancel();
        }
        exit();
    }

    @Override // com.luck.picture.lib.PictureSelectorCameraEmptyActivity, com.luck.picture.lib.PictureBaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        getWindow().setFlags(1024, 1024);
        getWindow().setFlags(67108864, 67108864);
        getWindow().setFlags(134217728, 134217728);
        if (Build.VERSION.SDK_INT >= 28) {
            WindowManager.LayoutParams attributes = getWindow().getAttributes();
            attributes.layoutInDisplayCutoutMode = 1;
            getWindow().setAttributes(attributes);
        }
        getWindow().addFlags(128);
        super.onCreate(bundle);
        if (!(PermissionChecker.checkSelfPermission(this, "android.permission.READ_EXTERNAL_STORAGE") && PermissionChecker.checkSelfPermission(this, "android.permission.WRITE_EXTERNAL_STORAGE"))) {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"}, 1);
            return;
        }
        if (!PermissionChecker.checkSelfPermission(this, "android.permission.CAMERA")) {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.CAMERA"}, 2);
        } else if (PermissionChecker.checkSelfPermission(this, "android.permission.RECORD_AUDIO")) {
            createCameraView();
        } else {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.RECORD_AUDIO"}, 4);
        }
    }

    @Override // com.luck.picture.lib.PictureSelectorCameraEmptyActivity, com.luck.picture.lib.PictureBaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int i2, @NonNull String[] strArr, @NonNull int[] iArr) {
        if (i2 == 1) {
            if (iArr.length <= 0 || iArr[0] != 0) {
                showPermissionsDialog(true, getString(C3979R.string.picture_jurisdiction));
                return;
            } else {
                PermissionChecker.requestPermissions(this, new String[]{"android.permission.CAMERA"}, 2);
                return;
            }
        }
        if (i2 != 2) {
            if (i2 != 4) {
                return;
            }
            if (iArr.length <= 0 || iArr[0] != 0) {
                showPermissionsDialog(false, getString(C3979R.string.picture_audio));
                return;
            } else {
                createCameraView();
                return;
            }
        }
        if (iArr.length <= 0 || iArr[0] != 0) {
            showPermissionsDialog(true, getString(C3979R.string.picture_camera));
        } else if (PermissionChecker.checkSelfPermission(this, "android.permission.RECORD_AUDIO")) {
            createCameraView();
        } else {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.RECORD_AUDIO"}, 4);
        }
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        if (this.isEnterSetting) {
            if (!(PermissionChecker.checkSelfPermission(this, "android.permission.READ_EXTERNAL_STORAGE") && PermissionChecker.checkSelfPermission(this, "android.permission.WRITE_EXTERNAL_STORAGE"))) {
                showPermissionsDialog(false, getString(C3979R.string.picture_jurisdiction));
            } else if (!PermissionChecker.checkSelfPermission(this, "android.permission.CAMERA")) {
                showPermissionsDialog(false, getString(C3979R.string.picture_camera));
            } else if (PermissionChecker.checkSelfPermission(this, "android.permission.RECORD_AUDIO")) {
                createCameraView();
            } else {
                showPermissionsDialog(false, getString(C3979R.string.picture_audio));
            }
            this.isEnterSetting = false;
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void showPermissionsDialog(boolean z, String str) {
        if (isFinishing()) {
            return;
        }
        final PictureCustomDialog pictureCustomDialog = new PictureCustomDialog(getContext(), C3979R.layout.picture_wind_base_dialog);
        pictureCustomDialog.setCancelable(false);
        pictureCustomDialog.setCanceledOnTouchOutside(false);
        Button button = (Button) pictureCustomDialog.findViewById(C3979R.id.btn_cancel);
        Button button2 = (Button) pictureCustomDialog.findViewById(C3979R.id.btn_commit);
        button2.setText(getString(C3979R.string.picture_go_setting));
        TextView textView = (TextView) pictureCustomDialog.findViewById(C3979R.id.tvTitle);
        TextView textView2 = (TextView) pictureCustomDialog.findViewById(C3979R.id.tv_content);
        textView.setText(getString(C3979R.string.picture_prompt));
        textView2.setText(str);
        button.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.c
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PictureCustomCameraActivity pictureCustomCameraActivity = PictureCustomCameraActivity.this;
                PictureCustomDialog pictureCustomDialog2 = pictureCustomDialog;
                if (!pictureCustomCameraActivity.isFinishing()) {
                    pictureCustomDialog2.dismiss();
                }
                OnResultCallbackListener onResultCallbackListener = PictureSelectionConfig.listener;
                if (onResultCallbackListener != null) {
                    onResultCallbackListener.onCancel();
                }
                pictureCustomCameraActivity.exit();
            }
        });
        button2.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.e
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PictureCustomCameraActivity pictureCustomCameraActivity = PictureCustomCameraActivity.this;
                PictureCustomDialog pictureCustomDialog2 = pictureCustomDialog;
                if (!pictureCustomCameraActivity.isFinishing()) {
                    pictureCustomDialog2.dismiss();
                }
                PermissionChecker.launchAppDetailsSettings(pictureCustomCameraActivity.getContext());
                pictureCustomCameraActivity.isEnterSetting = true;
            }
        });
        pictureCustomDialog.show();
    }
}
