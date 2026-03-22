package com.luck.picture.lib;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.View;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import com.luck.picture.lib.PictureBaseActivity;
import com.luck.picture.lib.app.PictureAppMaster;
import com.luck.picture.lib.compress.Luban;
import com.luck.picture.lib.compress.OnCompressListener;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.dialog.PictureCustomDialog;
import com.luck.picture.lib.dialog.PictureLoadingDialog;
import com.luck.picture.lib.engine.PictureSelectorEngine;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.entity.LocalMediaFolder;
import com.luck.picture.lib.immersive.ImmersiveManage;
import com.luck.picture.lib.immersive.NavBarUtils;
import com.luck.picture.lib.language.PictureLanguageUtils;
import com.luck.picture.lib.listener.OnResultCallbackListener;
import com.luck.picture.lib.model.LocalMediaPageLoader;
import com.luck.picture.lib.permissions.PermissionChecker;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.style.PictureSelectorUIStyle;
import com.luck.picture.lib.thread.PictureThreadUtils;
import com.luck.picture.lib.tools.AndroidQTransformUtils;
import com.luck.picture.lib.tools.AttrsUtils;
import com.luck.picture.lib.tools.MediaUtils;
import com.luck.picture.lib.tools.PictureFileUtils;
import com.luck.picture.lib.tools.SdkVersionUtils;
import com.luck.picture.lib.tools.StringUtils;
import com.luck.picture.lib.tools.ToastUtils;
import com.luck.picture.lib.tools.VoiceUtils;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public abstract class PictureBaseActivity extends AppCompatActivity {

    /* renamed from: c */
    public static final /* synthetic */ int f10204c = 0;
    public int colorPrimary;
    public int colorPrimaryDark;
    public PictureSelectionConfig config;
    public View container;
    public boolean isOnSaveInstanceState;
    public Handler mHandler;
    public PictureLoadingDialog mLoadingDialog;
    public boolean numComplete;
    public boolean openWhiteStatusBar;
    public List<LocalMedia> selectionMedias;
    public boolean isHasMore = true;
    public int mPage = 1;

    private void compressToLuban(final List<LocalMedia> list) {
        if (this.config.synOrAsy) {
            PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<List<File>>() { // from class: com.luck.picture.lib.PictureBaseActivity.1
                @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                public List<File> doInBackground() {
                    return Luban.with(PictureBaseActivity.this.getContext()).loadMediaData(list).isCamera(PictureBaseActivity.this.config.camera).setTargetDir(PictureBaseActivity.this.config.compressSavePath).setCompressQuality(PictureBaseActivity.this.config.compressQuality).setFocusAlpha(PictureBaseActivity.this.config.focusAlpha).setNewCompressFileName(PictureBaseActivity.this.config.renameCompressFileName).ignoreBy(PictureBaseActivity.this.config.minimumCompressSize).get();
                }

                @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                public void onSuccess(List<File> list2) {
                    if (list2 == null || list2.size() <= 0 || list2.size() != list.size()) {
                        PictureBaseActivity.this.onResult(list);
                    } else {
                        PictureBaseActivity.this.handleCompressCallBack(list, list2);
                    }
                }
            });
        } else {
            Luban.with(this).loadMediaData(list).ignoreBy(this.config.minimumCompressSize).isCamera(this.config.camera).setCompressQuality(this.config.compressQuality).setTargetDir(this.config.compressSavePath).setFocusAlpha(this.config.focusAlpha).setNewCompressFileName(this.config.renameCompressFileName).setCompressListener(new OnCompressListener() { // from class: com.luck.picture.lib.PictureBaseActivity.2
                @Override // com.luck.picture.lib.compress.OnCompressListener
                public void onError(Throwable th) {
                    PictureBaseActivity.this.onResult(list);
                }

                @Override // com.luck.picture.lib.compress.OnCompressListener
                public void onStart() {
                }

                @Override // com.luck.picture.lib.compress.OnCompressListener
                public void onSuccess(List<LocalMedia> list2) {
                    PictureBaseActivity.this.onResult(list2);
                }
            }).launch();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleCompressCallBack(List<LocalMedia> list, List<File> list2) {
        if (list == null || list2 == null) {
            exit();
            return;
        }
        boolean checkedAndroid_Q = SdkVersionUtils.checkedAndroid_Q();
        int size = list.size();
        if (list2.size() == size) {
            for (int i2 = 0; i2 < size; i2++) {
                File file = list2.get(i2);
                if (file != null) {
                    String absolutePath = file.getAbsolutePath();
                    LocalMedia localMedia = list.get(i2);
                    boolean z = !TextUtils.isEmpty(absolutePath) && PictureMimeType.isHasHttp(absolutePath);
                    boolean isHasVideo = PictureMimeType.isHasVideo(localMedia.getMimeType());
                    localMedia.setCompressed((isHasVideo || z) ? false : true);
                    if (isHasVideo || z) {
                        absolutePath = null;
                    }
                    localMedia.setCompressPath(absolutePath);
                    if (checkedAndroid_Q) {
                        localMedia.setAndroidQToPath(localMedia.getCompressPath());
                    }
                }
            }
        }
        onResult(list);
    }

    private void initConfig() {
        List<LocalMedia> list = this.config.selectionMedias;
        if (list == null) {
            list = new ArrayList<>();
        }
        this.selectionMedias = list;
        PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle != null) {
            this.openWhiteStatusBar = pictureSelectorUIStyle.picture_statusBarChangeTextColor;
            int i2 = pictureSelectorUIStyle.picture_top_titleBarBackgroundColor;
            if (i2 != 0) {
                this.colorPrimary = i2;
            }
            int i3 = pictureSelectorUIStyle.picture_statusBarBackgroundColor;
            if (i3 != 0) {
                this.colorPrimaryDark = i3;
            }
            this.numComplete = pictureSelectorUIStyle.picture_switchSelectTotalStyle;
            this.config.checkNumMode = pictureSelectorUIStyle.picture_switchSelectNumberStyle;
        } else {
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle != null) {
                this.openWhiteStatusBar = pictureParameterStyle.isChangeStatusBarFontColor;
                int i4 = pictureParameterStyle.pictureTitleBarBackgroundColor;
                if (i4 != 0) {
                    this.colorPrimary = i4;
                }
                int i5 = pictureParameterStyle.pictureStatusBarColor;
                if (i5 != 0) {
                    this.colorPrimaryDark = i5;
                }
                this.numComplete = pictureParameterStyle.isOpenCompletedNumStyle;
                this.config.checkNumMode = pictureParameterStyle.isOpenCheckNumStyle;
            } else {
                boolean z = this.config.isChangeStatusBarFontColor;
                this.openWhiteStatusBar = z;
                if (!z) {
                    this.openWhiteStatusBar = AttrsUtils.getTypeValueBoolean(this, C3979R.attr.picture_statusFontColor);
                }
                boolean z2 = this.config.isOpenStyleNumComplete;
                this.numComplete = z2;
                if (!z2) {
                    this.numComplete = AttrsUtils.getTypeValueBoolean(this, C3979R.attr.picture_style_numComplete);
                }
                PictureSelectionConfig pictureSelectionConfig = this.config;
                boolean z3 = pictureSelectionConfig.isOpenStyleCheckNumMode;
                pictureSelectionConfig.checkNumMode = z3;
                if (!z3) {
                    pictureSelectionConfig.checkNumMode = AttrsUtils.getTypeValueBoolean(this, C3979R.attr.picture_style_checkNumMode);
                }
                int i6 = this.config.titleBarBackgroundColor;
                if (i6 != 0) {
                    this.colorPrimary = i6;
                } else {
                    this.colorPrimary = AttrsUtils.getTypeValueColor(this, C3979R.attr.colorPrimary);
                }
                int i7 = this.config.pictureStatusBarColor;
                if (i7 != 0) {
                    this.colorPrimaryDark = i7;
                } else {
                    this.colorPrimaryDark = AttrsUtils.getTypeValueColor(this, C3979R.attr.colorPrimaryDark);
                }
            }
        }
        if (this.config.openClickSound) {
            VoiceUtils.getInstance().init(getContext());
        }
    }

    private void newCreateEngine() {
        PictureSelectorEngine pictureSelectorEngine;
        if (PictureSelectionConfig.imageEngine != null || (pictureSelectorEngine = PictureAppMaster.getInstance().getPictureSelectorEngine()) == null) {
            return;
        }
        PictureSelectionConfig.imageEngine = pictureSelectorEngine.createEngine();
    }

    private void newCreateResultCallbackListener() {
        PictureSelectorEngine pictureSelectorEngine;
        if (this.config.isCallbackMode && PictureSelectionConfig.listener == null && (pictureSelectorEngine = PictureAppMaster.getInstance().getPictureSelectorEngine()) != null) {
            PictureSelectionConfig.listener = pictureSelectorEngine.getResultCallbackListener();
        }
    }

    private void onResultToAndroidAsy(final List<LocalMedia> list) {
        PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<List<LocalMedia>>() { // from class: com.luck.picture.lib.PictureBaseActivity.3
            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public List<LocalMedia> doInBackground() {
                int size = list.size();
                for (int i2 = 0; i2 < size; i2++) {
                    LocalMedia localMedia = (LocalMedia) list.get(i2);
                    if (localMedia != null && !TextUtils.isEmpty(localMedia.getPath())) {
                        if (((localMedia.isCut() || localMedia.isCompressed() || !TextUtils.isEmpty(localMedia.getAndroidQToPath())) ? false : true) && PictureMimeType.isContent(localMedia.getPath())) {
                            if (!PictureMimeType.isHasHttp(localMedia.getPath())) {
                                localMedia.setAndroidQToPath(AndroidQTransformUtils.copyPathToAndroidQ(PictureBaseActivity.this.getContext(), localMedia.getPath(), localMedia.getWidth(), localMedia.getHeight(), localMedia.getMimeType(), PictureBaseActivity.this.config.cameraFileName));
                            }
                        } else if (localMedia.isCut() && localMedia.isCompressed()) {
                            localMedia.setAndroidQToPath(localMedia.getCompressPath());
                        }
                        if (PictureBaseActivity.this.config.isCheckOriginalImage) {
                            localMedia.setOriginal(true);
                            localMedia.setOriginalPath(localMedia.getAndroidQToPath());
                        }
                    }
                }
                return list;
            }

            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public void onSuccess(List<LocalMedia> list2) {
                PictureBaseActivity.this.dismissDialog();
                if (list2 != null) {
                    PictureBaseActivity pictureBaseActivity = PictureBaseActivity.this;
                    PictureSelectionConfig pictureSelectionConfig = pictureBaseActivity.config;
                    if (pictureSelectionConfig.camera && pictureSelectionConfig.selectionMode == 2 && pictureBaseActivity.selectionMedias != null) {
                        list2.addAll(list2.size() > 0 ? list2.size() - 1 : 0, PictureBaseActivity.this.selectionMedias);
                    }
                    OnResultCallbackListener onResultCallbackListener = PictureSelectionConfig.listener;
                    if (onResultCallbackListener != null) {
                        onResultCallbackListener.onResult(list2);
                    } else {
                        PictureBaseActivity.this.setResult(-1, PictureSelector.putIntentResult(list2));
                    }
                    PictureBaseActivity.this.exit();
                }
            }
        });
    }

    private void releaseResultListener() {
        if (this.config != null) {
            PictureSelectionConfig.destroy();
            LocalMediaPageLoader.setInstanceNull();
            PictureThreadUtils.cancel(PictureThreadUtils.getIoPool());
        }
    }

    @Override // androidx.appcompat.app.AppCompatActivity, android.app.Activity, android.view.ContextThemeWrapper, android.content.ContextWrapper
    public void attachBaseContext(Context context) {
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig == null) {
            super.attachBaseContext(context);
        } else {
            super.attachBaseContext(PictureContextWrapper.wrap(context, pictureSelectionConfig.language));
        }
    }

    public void compressImage(List<LocalMedia> list) {
        showPleaseDialog();
        compressToLuban(list);
    }

    public void createNewFolder(List<LocalMediaFolder> list) {
        if (list.size() == 0) {
            LocalMediaFolder localMediaFolder = new LocalMediaFolder();
            localMediaFolder.setName(getString(this.config.chooseMode == PictureMimeType.ofAudio() ? C3979R.string.picture_all_audio : C3979R.string.picture_camera_roll));
            localMediaFolder.setFirstImagePath("");
            localMediaFolder.setCameraFolder(true);
            localMediaFolder.setBucketId(-1L);
            localMediaFolder.setChecked(true);
            list.add(localMediaFolder);
        }
    }

    public void dismissDialog() {
        if (isFinishing()) {
            return;
        }
        try {
            PictureLoadingDialog pictureLoadingDialog = this.mLoadingDialog;
            if (pictureLoadingDialog == null || !pictureLoadingDialog.isShowing()) {
                return;
            }
            this.mLoadingDialog.dismiss();
        } catch (Exception e2) {
            this.mLoadingDialog = null;
            e2.printStackTrace();
        }
    }

    public void exit() {
        finish();
        if (this.config.camera) {
            overridePendingTransition(0, C3979R.anim.picture_anim_fade_out);
            if ((getContext() instanceof PictureSelectorCameraEmptyActivity) || (getContext() instanceof PictureCustomCameraActivity)) {
                releaseResultListener();
                return;
            }
            return;
        }
        overridePendingTransition(0, PictureSelectionConfig.windowAnimationStyle.activityExitAnimation);
        if (getContext() instanceof PictureSelectorActivity) {
            releaseResultListener();
            if (this.config.openClickSound) {
                VoiceUtils.getInstance().releaseSoundPool();
            }
        }
    }

    public String getAudioPath(Intent intent) {
        if (intent == null || this.config.chooseMode != PictureMimeType.ofAudio()) {
            return "";
        }
        try {
            Uri data = intent.getData();
            return data != null ? MediaUtils.getAudioFilePathFromUri(getContext(), data) : "";
        } catch (Exception e2) {
            e2.printStackTrace();
            return "";
        }
    }

    public Context getContext() {
        return this;
    }

    public LocalMediaFolder getImageFolder(String str, String str2, List<LocalMediaFolder> list) {
        if (!PictureMimeType.isContent(str)) {
            str2 = str;
        }
        File parentFile = new File(str2).getParentFile();
        for (LocalMediaFolder localMediaFolder : list) {
            if (parentFile != null && localMediaFolder.getName().equals(parentFile.getName())) {
                return localMediaFolder;
            }
        }
        LocalMediaFolder localMediaFolder2 = new LocalMediaFolder();
        localMediaFolder2.setName(parentFile != null ? parentFile.getName() : "");
        localMediaFolder2.setFirstImagePath(str);
        list.add(localMediaFolder2);
        return localMediaFolder2;
    }

    public abstract int getResourceId();

    public void handlerResult(List<LocalMedia> list) {
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (!pictureSelectionConfig.isCompress || pictureSelectionConfig.isCheckOriginalImage) {
            onResult(list);
        } else {
            compressImage(list);
        }
    }

    public void immersive() {
        ImmersiveManage.immersiveAboveAPI23(this, this.colorPrimaryDark, this.colorPrimary, this.openWhiteStatusBar);
    }

    public void initCompleteText(int i2) {
    }

    public void initCompleteText(List<LocalMedia> list) {
    }

    public void initPictureSelectorStyle() {
    }

    public void initWidgets() {
    }

    @Override // android.app.Activity
    public boolean isImmersive() {
        return true;
    }

    public boolean isRequestedOrientation() {
        return true;
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        int i2;
        this.config = PictureSelectionConfig.getInstance();
        PictureLanguageUtils.setAppLanguage(getContext(), this.config.language);
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (!pictureSelectionConfig.camera) {
            int i3 = pictureSelectionConfig.themeStyleId;
            if (i3 == 0) {
                i3 = C3979R.style.picture_default_style;
            }
            setTheme(i3);
        }
        super.onCreate(bundle);
        newCreateEngine();
        newCreateResultCallbackListener();
        if (isRequestedOrientation()) {
            setNewRequestedOrientation();
        }
        this.mHandler = new Handler(Looper.getMainLooper());
        initConfig();
        if (isImmersive()) {
            immersive();
        }
        PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle != null) {
            int i4 = pictureSelectorUIStyle.picture_navBarColor;
            if (i4 != 0) {
                NavBarUtils.setNavBarColor(this, i4);
            }
        } else {
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle != null && (i2 = pictureParameterStyle.pictureNavBarColor) != 0) {
                NavBarUtils.setNavBarColor(this, i2);
            }
        }
        int resourceId = getResourceId();
        if (resourceId != 0) {
            setContentView(resourceId);
        }
        initWidgets();
        initPictureSelectorStyle();
        this.isOnSaveInstanceState = false;
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        PictureLoadingDialog pictureLoadingDialog = this.mLoadingDialog;
        if (pictureLoadingDialog != null) {
            pictureLoadingDialog.dismiss();
            this.mLoadingDialog = null;
        }
        super.onDestroy();
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int i2, @NonNull String[] strArr, @NonNull int[] iArr) {
        super.onRequestPermissionsResult(i2, strArr, iArr);
        if (i2 == 3) {
            if (iArr[0] != 0) {
                ToastUtils.m4555s(getContext(), getString(C3979R.string.picture_audio));
                return;
            }
            Intent intent = new Intent("android.provider.MediaStore.RECORD_SOUND");
            if (intent.resolveActivity(getPackageManager()) != null) {
                startActivityForResult(intent, PictureConfig.REQUEST_CAMERA);
            }
        }
    }

    public void onResult(List<LocalMedia> list) {
        if (SdkVersionUtils.checkedAndroid_Q() && this.config.isAndroidQTransform) {
            showPleaseDialog();
            onResultToAndroidAsy(list);
            return;
        }
        dismissDialog();
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.camera && pictureSelectionConfig.selectionMode == 2 && this.selectionMedias != null) {
            list.addAll(list.size() > 0 ? list.size() - 1 : 0, this.selectionMedias);
        }
        if (this.config.isCheckOriginalImage) {
            int size = list.size();
            for (int i2 = 0; i2 < size; i2++) {
                LocalMedia localMedia = list.get(i2);
                localMedia.setOriginal(true);
                localMedia.setOriginalPath(localMedia.getPath());
            }
        }
        OnResultCallbackListener onResultCallbackListener = PictureSelectionConfig.listener;
        if (onResultCallbackListener != null) {
            onResultCallbackListener.onResult(list);
        } else {
            setResult(-1, PictureSelector.putIntentResult(list));
        }
        exit();
    }

    @Override // androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onSaveInstanceState(@NotNull Bundle bundle) {
        super.onSaveInstanceState(bundle);
        this.isOnSaveInstanceState = true;
        bundle.putParcelable(PictureConfig.EXTRA_CONFIG, this.config);
    }

    public void setNewRequestedOrientation() {
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig == null || pictureSelectionConfig.camera) {
            return;
        }
        setRequestedOrientation(pictureSelectionConfig.requestedOrientation);
    }

    public void showPermissionsDialog(boolean z, String str) {
    }

    public void showPleaseDialog() {
        try {
            if (isFinishing()) {
                return;
            }
            if (this.mLoadingDialog == null) {
                this.mLoadingDialog = new PictureLoadingDialog(getContext());
            }
            if (this.mLoadingDialog.isShowing()) {
                this.mLoadingDialog.dismiss();
            }
            this.mLoadingDialog.show();
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public void showPromptDialog(String str) {
        if (isFinishing()) {
            return;
        }
        final PictureCustomDialog pictureCustomDialog = new PictureCustomDialog(getContext(), C3979R.layout.picture_prompt_dialog);
        TextView textView = (TextView) pictureCustomDialog.findViewById(C3979R.id.btnOk);
        ((TextView) pictureCustomDialog.findViewById(C3979R.id.tv_content)).setText(str);
        textView.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.b
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PictureBaseActivity pictureBaseActivity = PictureBaseActivity.this;
                PictureCustomDialog pictureCustomDialog2 = pictureCustomDialog;
                if (pictureBaseActivity.isFinishing()) {
                    return;
                }
                pictureCustomDialog2.dismiss();
            }
        });
        pictureCustomDialog.show();
    }

    public void sortFolder(List<LocalMediaFolder> list) {
        Collections.sort(list, new Comparator() { // from class: b.t.a.a.a
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                LocalMediaFolder localMediaFolder = (LocalMediaFolder) obj;
                LocalMediaFolder localMediaFolder2 = (LocalMediaFolder) obj2;
                int i2 = PictureBaseActivity.f10204c;
                if (localMediaFolder.getData() == null || localMediaFolder2.getData() == null) {
                    return 0;
                }
                return Integer.compare(localMediaFolder2.getImageNum(), localMediaFolder.getImageNum());
            }
        });
    }

    public void startOpenCamera() {
        String str;
        Uri parUri;
        Intent intent = new Intent("android.media.action.IMAGE_CAPTURE");
        if (intent.resolveActivity(getPackageManager()) != null) {
            if (SdkVersionUtils.checkedAndroid_Q()) {
                parUri = MediaUtils.createImageUri(getApplicationContext(), this.config.suffixType);
                if (parUri == null) {
                    ToastUtils.m4555s(getContext(), "open is camera error，the uri is empty ");
                    if (this.config.camera) {
                        exit();
                        return;
                    }
                    return;
                }
                this.config.cameraPath = parUri.toString();
            } else {
                PictureSelectionConfig pictureSelectionConfig = this.config;
                int i2 = pictureSelectionConfig.chooseMode;
                if (i2 == 0) {
                    i2 = 1;
                }
                if (TextUtils.isEmpty(pictureSelectionConfig.cameraFileName)) {
                    str = "";
                } else {
                    boolean isSuffixOfImage = PictureMimeType.isSuffixOfImage(this.config.cameraFileName);
                    PictureSelectionConfig pictureSelectionConfig2 = this.config;
                    pictureSelectionConfig2.cameraFileName = !isSuffixOfImage ? StringUtils.renameSuffix(pictureSelectionConfig2.cameraFileName, ".jpeg") : pictureSelectionConfig2.cameraFileName;
                    PictureSelectionConfig pictureSelectionConfig3 = this.config;
                    boolean z = pictureSelectionConfig3.camera;
                    str = pictureSelectionConfig3.cameraFileName;
                    if (!z) {
                        str = StringUtils.rename(str);
                    }
                }
                Context applicationContext = getApplicationContext();
                PictureSelectionConfig pictureSelectionConfig4 = this.config;
                File createCameraFile = PictureFileUtils.createCameraFile(applicationContext, i2, str, pictureSelectionConfig4.suffixType, pictureSelectionConfig4.outPutCameraPath);
                this.config.cameraPath = createCameraFile.getAbsolutePath();
                parUri = PictureFileUtils.parUri(this, createCameraFile);
            }
            this.config.cameraMimeType = PictureMimeType.ofImage();
            if (this.config.isCameraAroundState) {
                intent.putExtra(PictureConfig.CAMERA_FACING, 1);
            }
            intent.putExtra("output", parUri);
            startActivityForResult(intent, PictureConfig.REQUEST_CAMERA);
        }
    }

    public void startOpenCameraAudio() {
        if (!PermissionChecker.checkSelfPermission(this, "android.permission.RECORD_AUDIO")) {
            PermissionChecker.requestPermissions(this, new String[]{"android.permission.RECORD_AUDIO"}, 3);
            return;
        }
        Intent intent = new Intent("android.provider.MediaStore.RECORD_SOUND");
        if (intent.resolveActivity(getPackageManager()) != null) {
            this.config.cameraMimeType = PictureMimeType.ofAudio();
            startActivityForResult(intent, PictureConfig.REQUEST_CAMERA);
        }
    }

    public void startOpenCameraVideo() {
        String str;
        Uri parUri;
        Intent intent = new Intent("android.media.action.VIDEO_CAPTURE");
        if (intent.resolveActivity(getPackageManager()) != null) {
            if (SdkVersionUtils.checkedAndroid_Q()) {
                parUri = MediaUtils.createVideoUri(getApplicationContext(), this.config.suffixType);
                if (parUri == null) {
                    ToastUtils.m4555s(getContext(), "open is camera error，the uri is empty ");
                    if (this.config.camera) {
                        exit();
                        return;
                    }
                    return;
                }
                this.config.cameraPath = parUri.toString();
            } else {
                PictureSelectionConfig pictureSelectionConfig = this.config;
                int i2 = pictureSelectionConfig.chooseMode;
                if (i2 == 0) {
                    i2 = 2;
                }
                if (TextUtils.isEmpty(pictureSelectionConfig.cameraFileName)) {
                    str = "";
                } else {
                    boolean isSuffixOfImage = PictureMimeType.isSuffixOfImage(this.config.cameraFileName);
                    PictureSelectionConfig pictureSelectionConfig2 = this.config;
                    pictureSelectionConfig2.cameraFileName = isSuffixOfImage ? StringUtils.renameSuffix(pictureSelectionConfig2.cameraFileName, ".mp4") : pictureSelectionConfig2.cameraFileName;
                    PictureSelectionConfig pictureSelectionConfig3 = this.config;
                    boolean z = pictureSelectionConfig3.camera;
                    str = pictureSelectionConfig3.cameraFileName;
                    if (!z) {
                        str = StringUtils.rename(str);
                    }
                }
                Context applicationContext = getApplicationContext();
                PictureSelectionConfig pictureSelectionConfig4 = this.config;
                File createCameraFile = PictureFileUtils.createCameraFile(applicationContext, i2, str, pictureSelectionConfig4.suffixType, pictureSelectionConfig4.outPutCameraPath);
                this.config.cameraPath = createCameraFile.getAbsolutePath();
                parUri = PictureFileUtils.parUri(this, createCameraFile);
            }
            this.config.cameraMimeType = PictureMimeType.ofVideo();
            intent.putExtra("output", parUri);
            if (this.config.isCameraAroundState) {
                intent.putExtra(PictureConfig.CAMERA_FACING, 1);
            }
            intent.putExtra(PictureConfig.EXTRA_QUICK_CAPTURE, this.config.isQuickCapture);
            intent.putExtra("android.intent.extra.durationLimit", this.config.recordVideoSecond);
            intent.putExtra("android.intent.extra.videoQuality", this.config.videoQuality);
            startActivityForResult(intent, PictureConfig.REQUEST_CAMERA);
        }
    }
}
