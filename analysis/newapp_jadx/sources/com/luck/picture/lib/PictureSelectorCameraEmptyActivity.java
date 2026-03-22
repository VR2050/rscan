package com.luck.picture.lib;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import com.luck.picture.lib.PictureSelectorCameraEmptyActivity;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.immersive.ImmersiveManage;
import com.luck.picture.lib.listener.OnCallbackListener;
import com.luck.picture.lib.listener.OnCustomCameraInterfaceListener;
import com.luck.picture.lib.listener.OnResultCallbackListener;
import com.luck.picture.lib.manager.UCropManager;
import com.luck.picture.lib.permissions.PermissionChecker;
import com.luck.picture.lib.thread.PictureThreadUtils;
import com.luck.picture.lib.tools.BitmapUtils;
import com.luck.picture.lib.tools.MediaUtils;
import com.luck.picture.lib.tools.PictureFileUtils;
import com.luck.picture.lib.tools.SdkVersionUtils;
import com.luck.picture.lib.tools.ToastUtils;
import com.luck.picture.lib.tools.ValueOf;
import com.yalantis.ucrop.UCrop;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/* loaded from: classes2.dex */
public class PictureSelectorCameraEmptyActivity extends PictureBaseActivity {
    /* JADX INFO: Access modifiers changed from: private */
    public void dispatchCameraHandleResult(LocalMedia localMedia) {
        boolean isHasImage = PictureMimeType.isHasImage(localMedia.getMimeType());
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.enableCrop && isHasImage) {
            String str = pictureSelectionConfig.cameraPath;
            pictureSelectionConfig.originalPath = str;
            UCropManager.ofCrop(this, str, localMedia.getMimeType());
        } else if (pictureSelectionConfig.isCompress && isHasImage && !pictureSelectionConfig.isCheckOriginalImage) {
            ArrayList arrayList = new ArrayList();
            arrayList.add(localMedia);
            compressImage(arrayList);
        } else {
            ArrayList arrayList2 = new ArrayList();
            arrayList2.add(localMedia);
            onResult(arrayList2);
        }
    }

    private void onTakePhoto() {
        if (!PermissionChecker.checkSelfPermission(this, "android.permission.CAMERA")) {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.CAMERA"}, 2);
            return;
        }
        boolean z = true;
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig != null && pictureSelectionConfig.isUseCustomCamera) {
            z = PermissionChecker.checkSelfPermission(this, "android.permission.RECORD_AUDIO");
        }
        if (z) {
            startCamera();
        } else {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.RECORD_AUDIO"}, 4);
        }
    }

    private void startCamera() {
        int i2 = this.config.chooseMode;
        if (i2 == 0 || i2 == 1) {
            startOpenCamera();
        } else if (i2 == 2) {
            startOpenCameraVideo();
        } else {
            if (i2 != 3) {
                return;
            }
            startOpenCameraAudio();
        }
    }

    public void dispatchHandleCamera(final Intent intent) {
        final boolean z = this.config.chooseMode == PictureMimeType.ofAudio();
        PictureSelectionConfig pictureSelectionConfig = this.config;
        pictureSelectionConfig.cameraPath = z ? getAudioPath(intent) : pictureSelectionConfig.cameraPath;
        if (TextUtils.isEmpty(this.config.cameraPath)) {
            return;
        }
        showPleaseDialog();
        PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<LocalMedia>() { // from class: com.luck.picture.lib.PictureSelectorCameraEmptyActivity.1
            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public LocalMedia doInBackground() {
                LocalMedia localMedia = new LocalMedia();
                boolean z2 = z;
                String str = z2 ? PictureMimeType.MIME_TYPE_AUDIO : "";
                long j2 = 0;
                if (!z2) {
                    if (PictureMimeType.isContent(PictureSelectorCameraEmptyActivity.this.config.cameraPath)) {
                        String path = PictureFileUtils.getPath(PictureSelectorCameraEmptyActivity.this.getContext(), Uri.parse(PictureSelectorCameraEmptyActivity.this.config.cameraPath));
                        if (!TextUtils.isEmpty(path)) {
                            File file = new File(path);
                            String mimeType = PictureMimeType.getMimeType(PictureSelectorCameraEmptyActivity.this.config.cameraMimeType);
                            localMedia.setSize(file.length());
                            str = mimeType;
                        }
                        if (PictureMimeType.isHasImage(str)) {
                            int[] imageSizeForUrlToAndroidQ = MediaUtils.getImageSizeForUrlToAndroidQ(PictureSelectorCameraEmptyActivity.this.getContext(), PictureSelectorCameraEmptyActivity.this.config.cameraPath);
                            localMedia.setWidth(imageSizeForUrlToAndroidQ[0]);
                            localMedia.setHeight(imageSizeForUrlToAndroidQ[1]);
                        } else if (PictureMimeType.isHasVideo(str)) {
                            MediaUtils.getVideoSizeForUri(PictureSelectorCameraEmptyActivity.this.getContext(), Uri.parse(PictureSelectorCameraEmptyActivity.this.config.cameraPath), localMedia);
                            j2 = MediaUtils.extractDuration(PictureSelectorCameraEmptyActivity.this.getContext(), SdkVersionUtils.checkedAndroid_Q(), PictureSelectorCameraEmptyActivity.this.config.cameraPath);
                        }
                        int lastIndexOf = PictureSelectorCameraEmptyActivity.this.config.cameraPath.lastIndexOf("/") + 1;
                        localMedia.setId(lastIndexOf > 0 ? ValueOf.toLong(PictureSelectorCameraEmptyActivity.this.config.cameraPath.substring(lastIndexOf)) : -1L);
                        localMedia.setRealPath(path);
                        Intent intent2 = intent;
                        localMedia.setAndroidQToPath(intent2 != null ? intent2.getStringExtra(PictureConfig.EXTRA_MEDIA_PATH) : null);
                    } else {
                        File file2 = new File(PictureSelectorCameraEmptyActivity.this.config.cameraPath);
                        str = PictureMimeType.getMimeType(PictureSelectorCameraEmptyActivity.this.config.cameraMimeType);
                        localMedia.setSize(file2.length());
                        if (PictureMimeType.isHasImage(str)) {
                            BitmapUtils.rotateImage(PictureFileUtils.readPictureDegree(PictureSelectorCameraEmptyActivity.this.getContext(), PictureSelectorCameraEmptyActivity.this.config.cameraPath), PictureSelectorCameraEmptyActivity.this.config.cameraPath);
                            int[] imageSizeForUrl = MediaUtils.getImageSizeForUrl(PictureSelectorCameraEmptyActivity.this.config.cameraPath);
                            localMedia.setWidth(imageSizeForUrl[0]);
                            localMedia.setHeight(imageSizeForUrl[1]);
                        } else if (PictureMimeType.isHasVideo(str)) {
                            int[] videoSizeForUrl = MediaUtils.getVideoSizeForUrl(PictureSelectorCameraEmptyActivity.this.config.cameraPath);
                            j2 = MediaUtils.extractDuration(PictureSelectorCameraEmptyActivity.this.getContext(), SdkVersionUtils.checkedAndroid_Q(), PictureSelectorCameraEmptyActivity.this.config.cameraPath);
                            localMedia.setWidth(videoSizeForUrl[0]);
                            localMedia.setHeight(videoSizeForUrl[1]);
                        }
                        localMedia.setId(System.currentTimeMillis());
                    }
                    localMedia.setPath(PictureSelectorCameraEmptyActivity.this.config.cameraPath);
                    localMedia.setDuration(j2);
                    localMedia.setMimeType(str);
                    if (SdkVersionUtils.checkedAndroid_Q() && PictureMimeType.isHasVideo(localMedia.getMimeType())) {
                        localMedia.setParentFolderName(Environment.DIRECTORY_MOVIES);
                    } else {
                        localMedia.setParentFolderName(PictureMimeType.CAMERA);
                    }
                    localMedia.setChooseModel(PictureSelectorCameraEmptyActivity.this.config.chooseMode);
                    localMedia.setBucketId(MediaUtils.getCameraFirstBucketId(PictureSelectorCameraEmptyActivity.this.getContext()));
                    Context context = PictureSelectorCameraEmptyActivity.this.getContext();
                    PictureSelectionConfig pictureSelectionConfig2 = PictureSelectorCameraEmptyActivity.this.config;
                    MediaUtils.setOrientationSynchronous(context, localMedia, pictureSelectionConfig2.isAndroidQChangeWH, pictureSelectionConfig2.isAndroidQChangeVideoWH);
                }
                return localMedia;
            }

            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public void onSuccess(LocalMedia localMedia) {
                int dCIMLastImageId;
                PictureSelectorCameraEmptyActivity.this.dismissDialog();
                if (!SdkVersionUtils.checkedAndroid_Q()) {
                    PictureSelectorCameraEmptyActivity pictureSelectorCameraEmptyActivity = PictureSelectorCameraEmptyActivity.this;
                    if (pictureSelectorCameraEmptyActivity.config.isFallbackVersion3) {
                        new PictureMediaScannerConnection(pictureSelectorCameraEmptyActivity.getContext(), PictureSelectorCameraEmptyActivity.this.config.cameraPath);
                    } else {
                        pictureSelectorCameraEmptyActivity.sendBroadcast(new Intent("android.intent.action.MEDIA_SCANNER_SCAN_FILE", Uri.fromFile(new File(PictureSelectorCameraEmptyActivity.this.config.cameraPath))));
                    }
                }
                PictureSelectorCameraEmptyActivity.this.dispatchCameraHandleResult(localMedia);
                if (SdkVersionUtils.checkedAndroid_Q() || !PictureMimeType.isHasImage(localMedia.getMimeType()) || (dCIMLastImageId = MediaUtils.getDCIMLastImageId(PictureSelectorCameraEmptyActivity.this.getContext())) == -1) {
                    return;
                }
                MediaUtils.removeMedia(PictureSelectorCameraEmptyActivity.this.getContext(), dCIMLastImageId);
            }
        });
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public int getResourceId() {
        return C3979R.layout.picture_empty;
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void immersive() {
        int i2 = C3979R.color.picture_color_transparent;
        ImmersiveManage.immersiveAboveAPI23(this, ContextCompat.getColor(this, i2), ContextCompat.getColor(this, i2), this.openWhiteStatusBar);
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onActivityResult(int i2, int i3, @Nullable Intent intent) {
        Throwable th;
        super.onActivityResult(i2, i3, intent);
        if (i3 == -1) {
            if (i2 == 69) {
                singleCropHandleResult(intent);
                return;
            } else {
                if (i2 != 909) {
                    return;
                }
                dispatchHandleCamera(intent);
                return;
            }
        }
        if (i3 == 0) {
            OnResultCallbackListener onResultCallbackListener = PictureSelectionConfig.listener;
            if (onResultCallbackListener != null) {
                onResultCallbackListener.onCancel();
            }
            exit();
            return;
        }
        if (i3 != 96 || intent == null || (th = (Throwable) intent.getSerializableExtra(UCrop.EXTRA_ERROR)) == null) {
            return;
        }
        ToastUtils.m4555s(getContext(), th.getMessage());
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        super.onBackPressed();
        exit();
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig == null) {
            exit();
            return;
        }
        if (pictureSelectionConfig.isUseCustomCamera) {
            return;
        }
        if (bundle == null) {
            if (PermissionChecker.checkSelfPermission(this, "android.permission.READ_EXTERNAL_STORAGE") && PermissionChecker.checkSelfPermission(this, "android.permission.WRITE_EXTERNAL_STORAGE")) {
                OnCustomCameraInterfaceListener onCustomCameraInterfaceListener = PictureSelectionConfig.onCustomCameraInterfaceListener;
                if (onCustomCameraInterfaceListener == null) {
                    onTakePhoto();
                } else if (this.config.chooseMode == 2) {
                    onCustomCameraInterfaceListener.onCameraClick(getContext(), this.config, 2);
                } else {
                    onCustomCameraInterfaceListener.onCameraClick(getContext(), this.config, 1);
                }
            } else {
                PermissionChecker.requestPermissions(this, new String[]{"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"}, 1);
            }
        }
        setTheme(C3979R.style.Picture_Theme_Translucent);
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int i2, @NonNull String[] strArr, @NonNull int[] iArr) {
        super.onRequestPermissionsResult(i2, strArr, iArr);
        if (i2 == 1) {
            if (iArr.length > 0 && iArr[0] == 0) {
                PermissionChecker.requestPermissions(this, new String[]{"android.permission.CAMERA"}, 2);
                return;
            } else {
                ToastUtils.m4555s(getContext(), getString(C3979R.string.picture_jurisdiction));
                exit();
                return;
            }
        }
        if (i2 == 2) {
            if (iArr.length > 0 && iArr[0] == 0) {
                onTakePhoto();
                return;
            } else {
                exit();
                ToastUtils.m4555s(getContext(), getString(C3979R.string.picture_camera));
                return;
            }
        }
        if (i2 != 4) {
            return;
        }
        if (iArr.length > 0 && iArr[0] == 0) {
            onTakePhoto();
        } else {
            exit();
            ToastUtils.m4555s(getContext(), getString(C3979R.string.picture_audio));
        }
    }

    public void singleCropHandleResult(Intent intent) {
        if (intent == null) {
            return;
        }
        final ArrayList arrayList = new ArrayList();
        Uri output = UCrop.getOutput(intent);
        if (output == null) {
            return;
        }
        String path = output.getPath();
        boolean isEmpty = TextUtils.isEmpty(path);
        PictureSelectionConfig pictureSelectionConfig = this.config;
        LocalMedia localMedia = new LocalMedia(pictureSelectionConfig.cameraPath, 0L, false, pictureSelectionConfig.isCamera ? 1 : 0, 0, pictureSelectionConfig.chooseMode);
        if (SdkVersionUtils.checkedAndroid_Q()) {
            int lastIndexOf = this.config.cameraPath.lastIndexOf("/") + 1;
            localMedia.setId(lastIndexOf > 0 ? ValueOf.toLong(this.config.cameraPath.substring(lastIndexOf)) : -1L);
            localMedia.setAndroidQToPath(path);
            if (!isEmpty) {
                localMedia.setSize(new File(path).length());
            } else if (PictureMimeType.isContent(this.config.cameraPath)) {
                String path2 = PictureFileUtils.getPath(this, Uri.parse(this.config.cameraPath));
                localMedia.setSize(!TextUtils.isEmpty(path2) ? new File(path2).length() : 0L);
            } else {
                localMedia.setSize(new File(this.config.cameraPath).length());
            }
        } else {
            localMedia.setId(System.currentTimeMillis());
            localMedia.setSize(new File(isEmpty ? localMedia.getPath() : path).length());
        }
        localMedia.setCut(!isEmpty);
        localMedia.setCutPath(path);
        localMedia.setMimeType(PictureMimeType.getImageMimeType(path));
        localMedia.setOrientation(-1);
        if (PictureMimeType.isContent(localMedia.getPath())) {
            if (PictureMimeType.isHasVideo(localMedia.getMimeType())) {
                MediaUtils.getVideoSizeForUri(getContext(), Uri.parse(localMedia.getPath()), localMedia);
            } else if (PictureMimeType.isHasImage(localMedia.getMimeType())) {
                int[] imageSizeForUri = MediaUtils.getImageSizeForUri(getContext(), Uri.parse(localMedia.getPath()));
                localMedia.setWidth(imageSizeForUri[0]);
                localMedia.setHeight(imageSizeForUri[1]);
            }
        } else if (PictureMimeType.isHasVideo(localMedia.getMimeType())) {
            int[] videoSizeForUrl = MediaUtils.getVideoSizeForUrl(localMedia.getPath());
            localMedia.setWidth(videoSizeForUrl[0]);
            localMedia.setHeight(videoSizeForUrl[1]);
        } else if (PictureMimeType.isHasImage(localMedia.getMimeType())) {
            int[] imageSizeForUrl = MediaUtils.getImageSizeForUrl(localMedia.getPath());
            localMedia.setWidth(imageSizeForUrl[0]);
            localMedia.setHeight(imageSizeForUrl[1]);
        }
        Context context = getContext();
        PictureSelectionConfig pictureSelectionConfig2 = this.config;
        MediaUtils.setOrientationAsynchronous(context, localMedia, pictureSelectionConfig2.isAndroidQChangeWH, pictureSelectionConfig2.isAndroidQChangeVideoWH, new OnCallbackListener() { // from class: b.t.a.a.e0
            @Override // com.luck.picture.lib.listener.OnCallbackListener
            public final void onCall(Object obj) {
                PictureSelectorCameraEmptyActivity pictureSelectorCameraEmptyActivity = PictureSelectorCameraEmptyActivity.this;
                List<LocalMedia> list = arrayList;
                Objects.requireNonNull(pictureSelectorCameraEmptyActivity);
                list.add((LocalMedia) obj);
                pictureSelectorCameraEmptyActivity.handlerResult(list);
            }
        });
    }
}
