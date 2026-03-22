package com.luck.picture.lib;

import android.app.Activity;
import android.content.Intent;
import android.text.TextUtils;
import androidx.annotation.ColorInt;
import androidx.annotation.FloatRange;
import androidx.annotation.IntRange;
import androidx.annotation.StyleRes;
import androidx.fragment.app.Fragment;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.config.UCropOptions;
import com.luck.picture.lib.engine.CacheResourcesEngine;
import com.luck.picture.lib.engine.ImageEngine;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnCustomCameraInterfaceListener;
import com.luck.picture.lib.listener.OnCustomImagePreviewCallback;
import com.luck.picture.lib.listener.OnResultCallbackListener;
import com.luck.picture.lib.listener.OnVideoSelectedPlayCallback;
import com.luck.picture.lib.style.PictureCropParameterStyle;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.style.PictureSelectorUIStyle;
import com.luck.picture.lib.style.PictureWindowAnimationStyle;
import com.luck.picture.lib.tools.DoubleUtils;
import com.luck.picture.lib.tools.SdkVersionUtils;
import java.lang.ref.WeakReference;
import java.util.List;
import java.util.Objects;

/* loaded from: classes2.dex */
public class PictureSelectionModel {
    private PictureSelectionConfig selectionConfig;
    private PictureSelector selector;

    public PictureSelectionModel(PictureSelector pictureSelector, int i2) {
        this.selector = pictureSelector;
        PictureSelectionConfig cleanInstance = PictureSelectionConfig.getCleanInstance();
        this.selectionConfig = cleanInstance;
        cleanInstance.chooseMode = i2;
    }

    public PictureSelectionModel basicUCropConfig(UCropOptions uCropOptions) {
        this.selectionConfig.uCropOptions = uCropOptions;
        return this;
    }

    public PictureSelectionModel bindCustomCameraInterfaceListener(OnCustomCameraInterfaceListener onCustomCameraInterfaceListener) {
        PictureSelectionConfig.onCustomCameraInterfaceListener = (OnCustomCameraInterfaceListener) new WeakReference(onCustomCameraInterfaceListener).get();
        return this;
    }

    public PictureSelectionModel bindCustomPlayVideoCallback(OnVideoSelectedPlayCallback onVideoSelectedPlayCallback) {
        PictureSelectionConfig.customVideoPlayCallback = (OnVideoSelectedPlayCallback) new WeakReference(onVideoSelectedPlayCallback).get();
        return this;
    }

    public PictureSelectionModel bindCustomPreviewCallback(OnCustomImagePreviewCallback onCustomImagePreviewCallback) {
        PictureSelectionConfig.onCustomImagePreviewCallback = (OnCustomImagePreviewCallback) new WeakReference(onCustomImagePreviewCallback).get();
        return this;
    }

    @Deprecated
    public PictureSelectionModel bindPictureSelectorInterfaceListener(OnCustomCameraInterfaceListener onCustomCameraInterfaceListener) {
        PictureSelectionConfig.onCustomCameraInterfaceListener = (OnCustomCameraInterfaceListener) new WeakReference(onCustomCameraInterfaceListener).get();
        return this;
    }

    public PictureSelectionModel cameraFileName(String str) {
        this.selectionConfig.cameraFileName = str;
        return this;
    }

    public PictureSelectionModel circleDimmedLayer(boolean z) {
        this.selectionConfig.circleDimmedLayer = z;
        return this;
    }

    public PictureSelectionModel closeAndroidQChangeVideoWH(boolean z) {
        this.selectionConfig.isAndroidQChangeVideoWH = z;
        return this;
    }

    public PictureSelectionModel closeAndroidQChangeWH(boolean z) {
        this.selectionConfig.isAndroidQChangeWH = z;
        return this;
    }

    @Deprecated
    public PictureSelectionModel compress(boolean z) {
        this.selectionConfig.isCompress = z;
        return this;
    }

    public PictureSelectionModel compressFocusAlpha(boolean z) {
        this.selectionConfig.focusAlpha = z;
        return this;
    }

    public PictureSelectionModel compressQuality(int i2) {
        this.selectionConfig.compressQuality = i2;
        return this;
    }

    public PictureSelectionModel compressSavePath(String str) {
        this.selectionConfig.compressSavePath = str;
        return this;
    }

    @Deprecated
    public PictureSelectionModel cropCompressQuality(int i2) {
        this.selectionConfig.cropCompressQuality = i2;
        return this;
    }

    public PictureSelectionModel cropImageWideHigh(int i2, int i3) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.cropWidth = i2;
        pictureSelectionConfig.cropHeight = i3;
        return this;
    }

    @Deprecated
    public PictureSelectionModel cropWH(int i2, int i3) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.cropWidth = i2;
        pictureSelectionConfig.cropHeight = i3;
        return this;
    }

    public PictureSelectionModel cutOutQuality(int i2) {
        this.selectionConfig.cropCompressQuality = i2;
        return this;
    }

    @Deprecated
    public PictureSelectionModel enableCrop(boolean z) {
        this.selectionConfig.enableCrop = z;
        return this;
    }

    @Deprecated
    public PictureSelectionModel enablePreviewAudio(boolean z) {
        this.selectionConfig.enablePreviewAudio = z;
        return this;
    }

    public void externalPictureVideo(String str) {
        PictureSelector pictureSelector = this.selector;
        Objects.requireNonNull(pictureSelector, "This PictureSelector is Null");
        pictureSelector.externalPictureVideo(str);
    }

    public void forResult(int i2) {
        Activity activity;
        PictureSelectionConfig pictureSelectionConfig;
        Intent intent;
        if (DoubleUtils.isFastDoubleClick() || (activity = this.selector.getActivity()) == null || (pictureSelectionConfig = this.selectionConfig) == null) {
            return;
        }
        if (pictureSelectionConfig.camera && pictureSelectionConfig.isUseCustomCamera) {
            intent = new Intent(activity, (Class<?>) PictureCustomCameraActivity.class);
        } else {
            PictureSelectionConfig pictureSelectionConfig2 = this.selectionConfig;
            intent = new Intent(activity, (Class<?>) (pictureSelectionConfig2.camera ? PictureSelectorCameraEmptyActivity.class : pictureSelectionConfig2.isWeChatStyle ? PictureSelectorWeChatStyleActivity.class : PictureSelectorActivity.class));
        }
        this.selectionConfig.isCallbackMode = false;
        Fragment fragment = this.selector.getFragment();
        if (fragment != null) {
            fragment.startActivityForResult(intent, i2);
        } else {
            activity.startActivityForResult(intent, i2);
        }
        activity.overridePendingTransition(PictureSelectionConfig.windowAnimationStyle.activityEnterAnimation, C3979R.anim.picture_anim_fade_in);
    }

    public PictureSelectionModel freeStyleCropEnabled(boolean z) {
        this.selectionConfig.freeStyleCropEnabled = z;
        return this;
    }

    @Deprecated
    public PictureSelectionModel glideOverride(@IntRange(from = 100) int i2, @IntRange(from = 100) int i3) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.overrideWidth = i2;
        pictureSelectionConfig.overrideHeight = i3;
        return this;
    }

    public PictureSelectionModel hideBottomControls(boolean z) {
        this.selectionConfig.hideBottomControls = z;
        return this;
    }

    public PictureSelectionModel imageEngine(ImageEngine imageEngine) {
        if (PictureSelectionConfig.imageEngine != imageEngine) {
            PictureSelectionConfig.imageEngine = imageEngine;
        }
        return this;
    }

    public PictureSelectionModel imageFormat(String str) {
        if (SdkVersionUtils.checkedAndroid_Q() || SdkVersionUtils.checkedAndroid_R()) {
            if (TextUtils.equals(str, PictureMimeType.PNG)) {
                str = PictureMimeType.PNG_Q;
            }
            if (TextUtils.equals(str, ".jpeg")) {
                str = "image/jpeg";
            }
            if (TextUtils.equals(str, ".mp4")) {
                str = "video/mp4";
            }
        }
        this.selectionConfig.suffixType = str;
        return this;
    }

    public PictureSelectionModel imageSpanCount(int i2) {
        this.selectionConfig.imageSpanCount = i2;
        return this;
    }

    public PictureSelectionModel isAndroidQTransform(boolean z) {
        this.selectionConfig.isAndroidQTransform = z;
        return this;
    }

    public PictureSelectionModel isAutomaticTitleRecyclerTop(boolean z) {
        this.selectionConfig.isAutomaticTitleRecyclerTop = z;
        return this;
    }

    public PictureSelectionModel isBmp(boolean z) {
        this.selectionConfig.isWebp = z;
        return this;
    }

    public PictureSelectionModel isCamera(boolean z) {
        this.selectionConfig.isCamera = z;
        return this;
    }

    public PictureSelectionModel isCameraAroundState(boolean z) {
        this.selectionConfig.isCameraAroundState = z;
        return this;
    }

    @Deprecated
    public PictureSelectionModel isChangeStatusBarFontColor(boolean z) {
        this.selectionConfig.isChangeStatusBarFontColor = z;
        return this;
    }

    public PictureSelectionModel isCompress(boolean z) {
        this.selectionConfig.isCompress = z;
        return this;
    }

    public PictureSelectionModel isDragFrame(boolean z) {
        this.selectionConfig.isDragFrame = z;
        return this;
    }

    public PictureSelectionModel isEnableCrop(boolean z) {
        this.selectionConfig.enableCrop = z;
        return this;
    }

    public PictureSelectionModel isEnablePreviewAudio(boolean z) {
        this.selectionConfig.enablePreviewAudio = z;
        return this;
    }

    public PictureSelectionModel isFallbackVersion(boolean z) {
        this.selectionConfig.isFallbackVersion = z;
        return this;
    }

    public PictureSelectionModel isFallbackVersion2(boolean z) {
        this.selectionConfig.isFallbackVersion2 = z;
        return this;
    }

    public PictureSelectionModel isFallbackVersion3(boolean z) {
        this.selectionConfig.isFallbackVersion3 = z;
        return this;
    }

    public PictureSelectionModel isGif(boolean z) {
        this.selectionConfig.isGif = z;
        return this;
    }

    public PictureSelectionModel isMaxSelectEnabledMask(boolean z) {
        this.selectionConfig.isMaxSelectEnabledMask = z;
        return this;
    }

    public PictureSelectionModel isMultipleRecyclerAnimation(boolean z) {
        this.selectionConfig.isMultipleRecyclerAnimation = z;
        return this;
    }

    public PictureSelectionModel isMultipleSkipCrop(boolean z) {
        this.selectionConfig.isMultipleSkipCrop = z;
        return this;
    }

    public PictureSelectionModel isNotPreviewDownload(boolean z) {
        this.selectionConfig.isNotPreviewDownload = z;
        return this;
    }

    public PictureSelectionModel isOpenClickSound(boolean z) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.openClickSound = !pictureSelectionConfig.camera && z;
        return this;
    }

    @Deprecated
    public PictureSelectionModel isOpenStyleCheckNumMode(boolean z) {
        this.selectionConfig.isOpenStyleCheckNumMode = z;
        return this;
    }

    @Deprecated
    public PictureSelectionModel isOpenStyleNumComplete(boolean z) {
        this.selectionConfig.isOpenStyleNumComplete = z;
        return this;
    }

    public PictureSelectionModel isOriginalImageControl(boolean z) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.isOriginalControl = (pictureSelectionConfig.camera || pictureSelectionConfig.chooseMode == PictureMimeType.ofVideo() || this.selectionConfig.chooseMode == PictureMimeType.ofAudio() || !z) ? false : true;
        return this;
    }

    public PictureSelectionModel isPageStrategy(boolean z, int i2) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.isPageStrategy = z;
        if (i2 < 10) {
            i2 = 60;
        }
        pictureSelectionConfig.pageSize = i2;
        return this;
    }

    public PictureSelectionModel isPreviewEggs(boolean z) {
        this.selectionConfig.previewEggs = z;
        return this;
    }

    public PictureSelectionModel isPreviewImage(boolean z) {
        this.selectionConfig.enablePreview = z;
        return this;
    }

    public PictureSelectionModel isPreviewVideo(boolean z) {
        this.selectionConfig.enPreviewVideo = z;
        return this;
    }

    public PictureSelectionModel isQuickCapture(boolean z) {
        this.selectionConfig.isQuickCapture = z;
        return this;
    }

    public PictureSelectionModel isReturnEmpty(boolean z) {
        this.selectionConfig.returnEmpty = z;
        return this;
    }

    public PictureSelectionModel isSingleDirectReturn(boolean z) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        int i2 = pictureSelectionConfig.selectionMode;
        boolean z2 = false;
        pictureSelectionConfig.isSingleDirectReturn = i2 == 1 && z;
        if ((i2 != 1 || !z) && pictureSelectionConfig.isOriginalControl) {
            z2 = true;
        }
        pictureSelectionConfig.isOriginalControl = z2;
        return this;
    }

    public PictureSelectionModel isUseCustomCamera(boolean z) {
        this.selectionConfig.isUseCustomCamera = z;
        return this;
    }

    public PictureSelectionModel isWeChatStyle(boolean z) {
        this.selectionConfig.isWeChatStyle = z;
        return this;
    }

    public PictureSelectionModel isWebp(boolean z) {
        this.selectionConfig.isWebp = z;
        return this;
    }

    public PictureSelectionModel isWithVideoImage(boolean z) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.isWithVideoImage = pictureSelectionConfig.selectionMode != 1 && pictureSelectionConfig.chooseMode == PictureMimeType.ofAll() && z;
        return this;
    }

    public PictureSelectionModel isZoomAnim(boolean z) {
        this.selectionConfig.zoomAnim = z;
        return this;
    }

    @Deprecated
    public PictureSelectionModel loadCacheResourcesCallback(CacheResourcesEngine cacheResourcesEngine) {
        if (SdkVersionUtils.checkedAndroid_Q() && PictureSelectionConfig.cacheResourcesEngine != cacheResourcesEngine) {
            PictureSelectionConfig.cacheResourcesEngine = (CacheResourcesEngine) new WeakReference(cacheResourcesEngine).get();
        }
        return this;
    }

    @Deprecated
    public PictureSelectionModel loadImageEngine(ImageEngine imageEngine) {
        if (PictureSelectionConfig.imageEngine != imageEngine) {
            PictureSelectionConfig.imageEngine = imageEngine;
        }
        return this;
    }

    public PictureSelectionModel maxSelectNum(int i2) {
        this.selectionConfig.maxSelectNum = i2;
        return this;
    }

    public PictureSelectionModel maxVideoSelectNum(int i2) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        if (pictureSelectionConfig.chooseMode == PictureMimeType.ofVideo()) {
            i2 = 0;
        }
        pictureSelectionConfig.maxVideoSelectNum = i2;
        return this;
    }

    public PictureSelectionModel minSelectNum(int i2) {
        this.selectionConfig.minSelectNum = i2;
        return this;
    }

    public PictureSelectionModel minVideoSelectNum(int i2) {
        this.selectionConfig.minVideoSelectNum = i2;
        return this;
    }

    public PictureSelectionModel minimumCompressSize(int i2) {
        this.selectionConfig.minimumCompressSize = i2;
        return this;
    }

    @Deprecated
    public PictureSelectionModel openClickSound(boolean z) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.openClickSound = !pictureSelectionConfig.camera && z;
        return this;
    }

    public void openExternalPreview(int i2, List<LocalMedia> list) {
        PictureSelector pictureSelector = this.selector;
        Objects.requireNonNull(pictureSelector, "This PictureSelector is Null");
        pictureSelector.externalPicturePreview(i2, list, PictureSelectionConfig.windowAnimationStyle.activityPreviewEnterAnimation);
    }

    @Deprecated
    public PictureSelectionModel previewEggs(boolean z) {
        this.selectionConfig.previewEggs = z;
        return this;
    }

    @Deprecated
    public PictureSelectionModel previewImage(boolean z) {
        this.selectionConfig.enablePreview = z;
        return this;
    }

    @Deprecated
    public PictureSelectionModel previewVideo(boolean z) {
        this.selectionConfig.enPreviewVideo = z;
        return this;
    }

    public PictureSelectionModel queryMaxFileSize(float f2) {
        this.selectionConfig.filterFileSize = f2;
        return this;
    }

    public PictureSelectionModel querySpecifiedFormatSuffix(String str) {
        this.selectionConfig.specifiedFormat = str;
        return this;
    }

    public PictureSelectionModel recordVideoMinSecond(int i2) {
        this.selectionConfig.recordVideoMinSecond = i2;
        return this;
    }

    public PictureSelectionModel recordVideoSecond(int i2) {
        this.selectionConfig.recordVideoSecond = i2;
        return this;
    }

    public PictureSelectionModel renameCompressFile(String str) {
        this.selectionConfig.renameCompressFileName = str;
        return this;
    }

    public PictureSelectionModel renameCropFileName(String str) {
        this.selectionConfig.renameCropFileName = str;
        return this;
    }

    public PictureSelectionModel rotateEnabled(boolean z) {
        this.selectionConfig.rotateEnabled = z;
        return this;
    }

    public PictureSelectionModel scaleEnabled(boolean z) {
        this.selectionConfig.scaleEnabled = z;
        return this;
    }

    public PictureSelectionModel selectionData(List<LocalMedia> list) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        if (pictureSelectionConfig.selectionMode == 1 && pictureSelectionConfig.isSingleDirectReturn) {
            pictureSelectionConfig.selectionMedias = null;
        } else {
            pictureSelectionConfig.selectionMedias = list;
        }
        return this;
    }

    @Deprecated
    public PictureSelectionModel selectionMedia(List<LocalMedia> list) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        if (pictureSelectionConfig.selectionMode == 1 && pictureSelectionConfig.isSingleDirectReturn) {
            pictureSelectionConfig.selectionMedias = null;
        } else {
            pictureSelectionConfig.selectionMedias = list;
        }
        return this;
    }

    public PictureSelectionModel selectionMode(int i2) {
        this.selectionConfig.selectionMode = i2;
        return this;
    }

    public PictureSelectionModel setButtonFeatures(int i2) {
        this.selectionConfig.buttonFeatures = i2;
        return this;
    }

    public PictureSelectionModel setCircleDimmedBorderColor(int i2) {
        this.selectionConfig.circleDimmedBorderColor = i2;
        return this;
    }

    @Deprecated
    public PictureSelectionModel setCircleDimmedColor(int i2) {
        this.selectionConfig.circleDimmedColor = i2;
        return this;
    }

    public PictureSelectionModel setCircleStrokeWidth(int i2) {
        this.selectionConfig.circleStrokeWidth = i2;
        return this;
    }

    public PictureSelectionModel setCropDimmedColor(int i2) {
        this.selectionConfig.circleDimmedColor = i2;
        return this;
    }

    @Deprecated
    public PictureSelectionModel setCropStatusBarColorPrimaryDark(@ColorInt int i2) {
        this.selectionConfig.cropStatusBarColorPrimaryDark = i2;
        return this;
    }

    @Deprecated
    public PictureSelectionModel setCropTitleBarBackgroundColor(@ColorInt int i2) {
        this.selectionConfig.cropTitleBarBackgroundColor = i2;
        return this;
    }

    @Deprecated
    public PictureSelectionModel setCropTitleColor(@ColorInt int i2) {
        this.selectionConfig.cropTitleColor = i2;
        return this;
    }

    @Deprecated
    public PictureSelectionModel setDownArrowDrawable(int i2) {
        this.selectionConfig.downResId = i2;
        return this;
    }

    public PictureSelectionModel setLanguage(int i2) {
        this.selectionConfig.language = i2;
        return this;
    }

    public PictureSelectionModel setOutputCameraPath(String str) {
        this.selectionConfig.outPutCameraPath = str;
        return this;
    }

    @Deprecated
    public PictureSelectionModel setPictureCropStyle(PictureCropParameterStyle pictureCropParameterStyle) {
        if (pictureCropParameterStyle != null) {
            PictureSelectionConfig.cropStyle = pictureCropParameterStyle;
        } else {
            PictureSelectionConfig.cropStyle = PictureCropParameterStyle.ofDefaultCropStyle();
        }
        return this;
    }

    @Deprecated
    public PictureSelectionModel setPictureStyle(PictureParameterStyle pictureParameterStyle) {
        if (pictureParameterStyle != null) {
            PictureSelectionConfig.style = pictureParameterStyle;
            PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
            if (!pictureSelectionConfig.isWeChatStyle) {
                pictureSelectionConfig.isWeChatStyle = pictureParameterStyle.isNewSelectStyle;
            }
        } else {
            PictureSelectionConfig.style = PictureParameterStyle.ofDefaultStyle();
        }
        return this;
    }

    public PictureSelectionModel setPictureUIStyle(PictureSelectorUIStyle pictureSelectorUIStyle) {
        if (pictureSelectorUIStyle != null) {
            PictureSelectionConfig.uiStyle = pictureSelectorUIStyle;
            PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
            if (!pictureSelectionConfig.isWeChatStyle) {
                pictureSelectionConfig.isWeChatStyle = pictureSelectorUIStyle.isNewSelectStyle;
            }
        }
        return this;
    }

    public PictureSelectionModel setPictureWindowAnimationStyle(PictureWindowAnimationStyle pictureWindowAnimationStyle) {
        if (pictureWindowAnimationStyle != null) {
            PictureSelectionConfig.windowAnimationStyle = pictureWindowAnimationStyle;
        } else {
            PictureSelectionConfig.windowAnimationStyle = PictureWindowAnimationStyle.ofDefaultWindowAnimationStyle();
        }
        return this;
    }

    public PictureSelectionModel setRecyclerAnimationMode(int i2) {
        this.selectionConfig.animationMode = i2;
        return this;
    }

    public PictureSelectionModel setRequestedOrientation(int i2) {
        this.selectionConfig.requestedOrientation = i2;
        return this;
    }

    @Deprecated
    public PictureSelectionModel setStatusBarColorPrimaryDark(@ColorInt int i2) {
        this.selectionConfig.pictureStatusBarColor = i2;
        return this;
    }

    @Deprecated
    public PictureSelectionModel setTitleBarBackgroundColor(@ColorInt int i2) {
        this.selectionConfig.titleBarBackgroundColor = i2;
        return this;
    }

    @Deprecated
    public PictureSelectionModel setUpArrowDrawable(int i2) {
        this.selectionConfig.upResId = i2;
        return this;
    }

    public PictureSelectionModel showCropFrame(boolean z) {
        this.selectionConfig.showCropFrame = z;
        return this;
    }

    public PictureSelectionModel showCropGrid(boolean z) {
        this.selectionConfig.showCropGrid = z;
        return this;
    }

    @Deprecated
    public PictureSelectionModel sizeMultiplier(@FloatRange(from = 0.10000000149011612d) float f2) {
        this.selectionConfig.sizeMultiplier = f2;
        return this;
    }

    public PictureSelectionModel synOrAsy(boolean z) {
        this.selectionConfig.synOrAsy = z;
        return this;
    }

    public PictureSelectionModel theme(@StyleRes int i2) {
        this.selectionConfig.themeStyleId = i2;
        return this;
    }

    public PictureSelectionModel videoMaxSecond(int i2) {
        this.selectionConfig.videoMaxSecond = i2 * 1000;
        return this;
    }

    public PictureSelectionModel videoMinSecond(int i2) {
        this.selectionConfig.videoMinSecond = i2 * 1000;
        return this;
    }

    public PictureSelectionModel videoQuality(int i2) {
        this.selectionConfig.videoQuality = i2;
        return this;
    }

    public PictureSelectionModel withAspectRatio(int i2, int i3) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.aspect_ratio_x = i2;
        pictureSelectionConfig.aspect_ratio_y = i3;
        return this;
    }

    public PictureSelectionModel isPageStrategy(boolean z, int i2, boolean z2) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.isPageStrategy = z;
        if (i2 < 10) {
            i2 = 60;
        }
        pictureSelectionConfig.pageSize = i2;
        pictureSelectionConfig.isFilterInvalidFile = z2;
        return this;
    }

    @Deprecated
    public void openExternalPreview(int i2, String str, List<LocalMedia> list) {
        PictureSelector pictureSelector = this.selector;
        Objects.requireNonNull(pictureSelector, "This PictureSelector is Null");
        pictureSelector.externalPicturePreview(i2, str, list, PictureSelectionConfig.windowAnimationStyle.activityPreviewEnterAnimation);
    }

    public PictureSelectionModel(PictureSelector pictureSelector, int i2, boolean z) {
        this.selector = pictureSelector;
        PictureSelectionConfig cleanInstance = PictureSelectionConfig.getCleanInstance();
        this.selectionConfig = cleanInstance;
        cleanInstance.camera = z;
        cleanInstance.chooseMode = i2;
    }

    public PictureSelectionModel isPageStrategy(boolean z) {
        this.selectionConfig.isPageStrategy = z;
        return this;
    }

    public PictureSelectionModel isPageStrategy(boolean z, boolean z2) {
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.isPageStrategy = z;
        pictureSelectionConfig.isFilterInvalidFile = z2;
        return this;
    }

    @Deprecated
    public void forResult(int i2, int i3, int i4) {
        Activity activity;
        if (DoubleUtils.isFastDoubleClick() || (activity = this.selector.getActivity()) == null) {
            return;
        }
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        Intent intent = new Intent(activity, (Class<?>) ((pictureSelectionConfig == null || !pictureSelectionConfig.camera) ? pictureSelectionConfig.isWeChatStyle ? PictureSelectorWeChatStyleActivity.class : PictureSelectorActivity.class : PictureSelectorCameraEmptyActivity.class));
        this.selectionConfig.isCallbackMode = false;
        Fragment fragment = this.selector.getFragment();
        if (fragment != null) {
            fragment.startActivityForResult(intent, i2);
        } else {
            activity.startActivityForResult(intent, i2);
        }
        activity.overridePendingTransition(i3, i4);
    }

    public void forResult(OnResultCallbackListener onResultCallbackListener) {
        Activity activity;
        Intent intent;
        if (DoubleUtils.isFastDoubleClick() || (activity = this.selector.getActivity()) == null || this.selectionConfig == null) {
            return;
        }
        PictureSelectionConfig.listener = (OnResultCallbackListener) new WeakReference(onResultCallbackListener).get();
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.isCallbackMode = true;
        if (pictureSelectionConfig.camera && pictureSelectionConfig.isUseCustomCamera) {
            intent = new Intent(activity, (Class<?>) PictureCustomCameraActivity.class);
        } else {
            PictureSelectionConfig pictureSelectionConfig2 = this.selectionConfig;
            intent = new Intent(activity, (Class<?>) (pictureSelectionConfig2.camera ? PictureSelectorCameraEmptyActivity.class : pictureSelectionConfig2.isWeChatStyle ? PictureSelectorWeChatStyleActivity.class : PictureSelectorActivity.class));
        }
        Fragment fragment = this.selector.getFragment();
        if (fragment != null) {
            fragment.startActivity(intent);
        } else {
            activity.startActivity(intent);
        }
        activity.overridePendingTransition(PictureSelectionConfig.windowAnimationStyle.activityEnterAnimation, C3979R.anim.picture_anim_fade_in);
    }

    public void forResult(int i2, OnResultCallbackListener onResultCallbackListener) {
        Activity activity;
        Intent intent;
        if (DoubleUtils.isFastDoubleClick() || (activity = this.selector.getActivity()) == null || this.selectionConfig == null) {
            return;
        }
        PictureSelectionConfig.listener = (OnResultCallbackListener) new WeakReference(onResultCallbackListener).get();
        PictureSelectionConfig pictureSelectionConfig = this.selectionConfig;
        pictureSelectionConfig.isCallbackMode = true;
        if (pictureSelectionConfig.camera && pictureSelectionConfig.isUseCustomCamera) {
            intent = new Intent(activity, (Class<?>) PictureCustomCameraActivity.class);
        } else {
            PictureSelectionConfig pictureSelectionConfig2 = this.selectionConfig;
            intent = new Intent(activity, (Class<?>) (pictureSelectionConfig2.camera ? PictureSelectorCameraEmptyActivity.class : pictureSelectionConfig2.isWeChatStyle ? PictureSelectorWeChatStyleActivity.class : PictureSelectorActivity.class));
        }
        Fragment fragment = this.selector.getFragment();
        if (fragment != null) {
            fragment.startActivityForResult(intent, i2);
        } else {
            activity.startActivityForResult(intent, i2);
        }
        activity.overridePendingTransition(PictureSelectionConfig.windowAnimationStyle.activityEnterAnimation, C3979R.anim.picture_anim_fade_in);
    }
}
