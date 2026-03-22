package com.luck.picture.lib.config;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.ColorInt;
import androidx.annotation.StyleRes;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.camera.CustomCameraView;
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
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class PictureSelectionConfig implements Parcelable {
    public static CacheResourcesEngine cacheResourcesEngine;
    public static PictureCropParameterStyle cropStyle;
    public static OnVideoSelectedPlayCallback customVideoPlayCallback;
    public static ImageEngine imageEngine;
    public static OnResultCallbackListener listener;
    public static OnCustomCameraInterfaceListener onCustomCameraInterfaceListener;
    public static OnCustomImagePreviewCallback onCustomImagePreviewCallback;
    public static PictureParameterStyle style;
    public static PictureSelectorUIStyle uiStyle;
    public int animationMode;
    public int aspect_ratio_x;
    public int aspect_ratio_y;
    public int buttonFeatures;
    public boolean camera;
    public String cameraFileName;
    public int cameraMimeType;
    public String cameraPath;
    public boolean checkNumMode;
    public int chooseMode;

    @ColorInt
    public int circleDimmedBorderColor;

    @ColorInt
    public int circleDimmedColor;
    public boolean circleDimmedLayer;
    public int circleStrokeWidth;
    public int compressQuality;
    public String compressSavePath;
    public int cropCompressQuality;
    public int cropHeight;

    @Deprecated
    public int cropStatusBarColorPrimaryDark;

    @Deprecated
    public int cropTitleBarBackgroundColor;

    @Deprecated
    public int cropTitleColor;
    public int cropWidth;

    @Deprecated
    public int downResId;
    public boolean enPreviewVideo;
    public boolean enableCrop;
    public boolean enablePreview;
    public boolean enablePreviewAudio;
    public float filterFileSize;
    public boolean focusAlpha;
    public boolean freeStyleCropEnabled;
    public boolean hideBottomControls;
    public int imageSpanCount;
    public boolean isAndroidQChangeVideoWH;
    public boolean isAndroidQChangeWH;
    public boolean isAndroidQTransform;
    public boolean isAutomaticTitleRecyclerTop;
    public boolean isBmp;
    public boolean isCallbackMode;
    public boolean isCamera;
    public boolean isCameraAroundState;

    @Deprecated
    public boolean isChangeStatusBarFontColor;
    public boolean isCheckOriginalImage;
    public boolean isCompress;
    public boolean isDragFrame;
    public boolean isFallbackVersion;
    public boolean isFallbackVersion2;
    public boolean isFallbackVersion3;
    public boolean isFilterInvalidFile;
    public boolean isGif;
    public boolean isMaxSelectEnabledMask;
    public boolean isMultipleRecyclerAnimation;
    public boolean isMultipleSkipCrop;
    public boolean isNotPreviewDownload;

    @Deprecated
    public boolean isOpenStyleCheckNumMode;

    @Deprecated
    public boolean isOpenStyleNumComplete;
    public boolean isOriginalControl;
    public boolean isPageStrategy;
    public boolean isQuickCapture;
    public boolean isSingleDirectReturn;
    public boolean isUseCustomCamera;
    public boolean isWeChatStyle;
    public boolean isWebp;
    public boolean isWithVideoImage;
    public int language;
    public int maxSelectNum;
    public int maxVideoSelectNum;
    public int minSelectNum;
    public int minVideoSelectNum;
    public int minimumCompressSize;
    public boolean openClickSound;
    public String originalPath;
    public String outPutCameraPath;

    @Deprecated
    public int overrideHeight;

    @Deprecated
    public int overrideWidth;
    public int pageSize;

    @Deprecated
    public int pictureStatusBarColor;
    public boolean previewEggs;
    public int recordVideoMinSecond;
    public int recordVideoSecond;
    public String renameCompressFileName;
    public String renameCropFileName;
    public int requestedOrientation;
    public boolean returnEmpty;
    public boolean rotateEnabled;
    public boolean scaleEnabled;
    public List<LocalMedia> selectionMedias;
    public int selectionMode;
    public boolean showCropFrame;
    public boolean showCropGrid;

    @Deprecated
    public float sizeMultiplier;
    public String specifiedFormat;
    public String suffixType;
    public boolean synOrAsy;

    @StyleRes
    public int themeStyleId;

    @Deprecated
    public int titleBarBackgroundColor;
    public UCropOptions uCropOptions;

    @Deprecated
    public int upResId;
    public int videoMaxSecond;
    public int videoMinSecond;
    public int videoQuality;
    public boolean zoomAnim;
    public static PictureWindowAnimationStyle windowAnimationStyle = PictureWindowAnimationStyle.ofDefaultWindowAnimationStyle();
    public static final Parcelable.Creator<PictureSelectionConfig> CREATOR = new Parcelable.Creator<PictureSelectionConfig>() { // from class: com.luck.picture.lib.config.PictureSelectionConfig.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public PictureSelectionConfig createFromParcel(Parcel parcel) {
            return new PictureSelectionConfig(parcel);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public PictureSelectionConfig[] newArray(int i2) {
            return new PictureSelectionConfig[i2];
        }
    };

    public static final class InstanceHolder {
        private static final PictureSelectionConfig INSTANCE = new PictureSelectionConfig();

        private InstanceHolder() {
        }
    }

    public PictureSelectionConfig() {
        this.requestedOrientation = -1;
        this.buttonFeatures = CustomCameraView.BUTTON_STATE_BOTH;
        this.maxVideoSelectNum = 1;
        this.minimumCompressSize = 100;
        this.imageSpanCount = 4;
        this.pageSize = 60;
    }

    public static void destroy() {
        listener = null;
        customVideoPlayCallback = null;
        onCustomImagePreviewCallback = null;
        onCustomCameraInterfaceListener = null;
        cacheResourcesEngine = null;
    }

    public static PictureSelectionConfig getCleanInstance() {
        PictureSelectionConfig pictureSelectionConfig = getInstance();
        pictureSelectionConfig.initDefaultValue();
        return pictureSelectionConfig;
    }

    public static PictureSelectionConfig getInstance() {
        return InstanceHolder.INSTANCE;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public void initDefaultValue() {
        this.chooseMode = PictureMimeType.ofImage();
        this.camera = false;
        this.themeStyleId = C3979R.style.picture_default_style;
        this.selectionMode = 2;
        uiStyle = null;
        style = null;
        cropStyle = null;
        this.maxSelectNum = 9;
        this.minSelectNum = 0;
        this.maxVideoSelectNum = 1;
        this.minVideoSelectNum = 0;
        this.videoQuality = 1;
        this.language = -1;
        this.cropCompressQuality = 90;
        this.videoMaxSecond = 0;
        this.videoMinSecond = 0;
        this.filterFileSize = -1.0f;
        this.recordVideoSecond = 60;
        this.recordVideoMinSecond = 0;
        this.compressQuality = 80;
        this.imageSpanCount = 4;
        this.isCompress = false;
        this.isOriginalControl = false;
        this.aspect_ratio_x = 0;
        this.aspect_ratio_y = 0;
        this.cropWidth = 0;
        this.cropHeight = 0;
        this.isCameraAroundState = false;
        this.isWithVideoImage = false;
        this.isAndroidQTransform = false;
        this.isCamera = true;
        this.isGif = false;
        this.isWebp = true;
        this.isBmp = true;
        this.focusAlpha = false;
        this.isCheckOriginalImage = false;
        this.isSingleDirectReturn = false;
        this.enablePreview = true;
        this.enPreviewVideo = true;
        this.enablePreviewAudio = true;
        this.checkNumMode = false;
        this.isNotPreviewDownload = false;
        this.openClickSound = false;
        this.isFallbackVersion = false;
        this.isFallbackVersion2 = true;
        this.isFallbackVersion3 = true;
        this.enableCrop = false;
        this.isWeChatStyle = false;
        this.isUseCustomCamera = false;
        this.isMultipleSkipCrop = true;
        this.isMultipleRecyclerAnimation = true;
        this.freeStyleCropEnabled = false;
        this.circleDimmedLayer = false;
        this.showCropFrame = true;
        this.showCropGrid = true;
        this.hideBottomControls = true;
        this.rotateEnabled = true;
        this.scaleEnabled = true;
        this.previewEggs = false;
        this.returnEmpty = false;
        this.synOrAsy = true;
        this.zoomAnim = true;
        this.circleDimmedColor = 0;
        this.circleDimmedBorderColor = 0;
        this.circleStrokeWidth = 1;
        this.isDragFrame = true;
        this.compressSavePath = "";
        this.suffixType = "";
        this.cameraFileName = "";
        this.specifiedFormat = "";
        this.renameCompressFileName = "";
        this.renameCropFileName = "";
        this.selectionMedias = new ArrayList();
        this.uCropOptions = null;
        this.titleBarBackgroundColor = 0;
        this.pictureStatusBarColor = 0;
        this.cropTitleBarBackgroundColor = 0;
        this.cropStatusBarColorPrimaryDark = 0;
        this.cropTitleColor = 0;
        this.upResId = 0;
        this.downResId = 0;
        this.isChangeStatusBarFontColor = false;
        this.isOpenStyleNumComplete = false;
        this.isOpenStyleCheckNumMode = false;
        this.outPutCameraPath = "";
        this.sizeMultiplier = 0.5f;
        this.overrideWidth = 0;
        this.overrideHeight = 0;
        this.originalPath = "";
        this.cameraPath = "";
        this.cameraMimeType = -1;
        this.pageSize = 60;
        this.isPageStrategy = true;
        this.isFilterInvalidFile = false;
        this.isMaxSelectEnabledMask = false;
        this.animationMode = -1;
        this.isAutomaticTitleRecyclerTop = true;
        this.isCallbackMode = false;
        this.isAndroidQChangeWH = true;
        this.isAndroidQChangeVideoWH = false;
        this.isQuickCapture = true;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.chooseMode);
        parcel.writeByte(this.camera ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isSingleDirectReturn ? (byte) 1 : (byte) 0);
        parcel.writeString(this.compressSavePath);
        parcel.writeString(this.suffixType);
        parcel.writeByte(this.focusAlpha ? (byte) 1 : (byte) 0);
        parcel.writeString(this.renameCompressFileName);
        parcel.writeString(this.renameCropFileName);
        parcel.writeString(this.specifiedFormat);
        parcel.writeInt(this.requestedOrientation);
        parcel.writeInt(this.buttonFeatures);
        parcel.writeByte(this.isCameraAroundState ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isAndroidQTransform ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.themeStyleId);
        parcel.writeInt(this.selectionMode);
        parcel.writeInt(this.maxSelectNum);
        parcel.writeInt(this.minSelectNum);
        parcel.writeInt(this.maxVideoSelectNum);
        parcel.writeInt(this.minVideoSelectNum);
        parcel.writeInt(this.videoQuality);
        parcel.writeInt(this.cropCompressQuality);
        parcel.writeInt(this.videoMaxSecond);
        parcel.writeInt(this.videoMinSecond);
        parcel.writeInt(this.recordVideoSecond);
        parcel.writeInt(this.recordVideoMinSecond);
        parcel.writeInt(this.minimumCompressSize);
        parcel.writeInt(this.imageSpanCount);
        parcel.writeInt(this.aspect_ratio_x);
        parcel.writeInt(this.aspect_ratio_y);
        parcel.writeInt(this.cropWidth);
        parcel.writeInt(this.cropHeight);
        parcel.writeInt(this.compressQuality);
        parcel.writeFloat(this.filterFileSize);
        parcel.writeInt(this.language);
        parcel.writeByte(this.isMultipleRecyclerAnimation ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isMultipleSkipCrop ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isWeChatStyle ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isUseCustomCamera ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.zoomAnim ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isCompress ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isOriginalControl ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isCamera ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isGif ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isWebp ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isBmp ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.enablePreview ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.enPreviewVideo ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.enablePreviewAudio ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.checkNumMode ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.openClickSound ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.enableCrop ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.freeStyleCropEnabled ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.circleDimmedLayer ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.circleDimmedColor);
        parcel.writeInt(this.circleDimmedBorderColor);
        parcel.writeInt(this.circleStrokeWidth);
        parcel.writeByte(this.showCropFrame ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.showCropGrid ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.hideBottomControls ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.rotateEnabled ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.scaleEnabled ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.previewEggs ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.synOrAsy ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.returnEmpty ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isDragFrame ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isNotPreviewDownload ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isWithVideoImage ? (byte) 1 : (byte) 0);
        parcel.writeParcelable(this.uCropOptions, i2);
        parcel.writeTypedList(this.selectionMedias);
        parcel.writeString(this.cameraFileName);
        parcel.writeByte(this.isCheckOriginalImage ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.overrideWidth);
        parcel.writeInt(this.overrideHeight);
        parcel.writeFloat(this.sizeMultiplier);
        parcel.writeByte(this.isChangeStatusBarFontColor ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isOpenStyleNumComplete ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isOpenStyleCheckNumMode ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.titleBarBackgroundColor);
        parcel.writeInt(this.pictureStatusBarColor);
        parcel.writeInt(this.cropTitleBarBackgroundColor);
        parcel.writeInt(this.cropStatusBarColorPrimaryDark);
        parcel.writeInt(this.cropTitleColor);
        parcel.writeInt(this.upResId);
        parcel.writeInt(this.downResId);
        parcel.writeString(this.outPutCameraPath);
        parcel.writeString(this.originalPath);
        parcel.writeString(this.cameraPath);
        parcel.writeInt(this.cameraMimeType);
        parcel.writeInt(this.pageSize);
        parcel.writeByte(this.isPageStrategy ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isFilterInvalidFile ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isMaxSelectEnabledMask ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.animationMode);
        parcel.writeByte(this.isAutomaticTitleRecyclerTop ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isCallbackMode ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isAndroidQChangeWH ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isAndroidQChangeVideoWH ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isQuickCapture ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isFallbackVersion ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isFallbackVersion2 ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isFallbackVersion3 ? (byte) 1 : (byte) 0);
    }

    public PictureSelectionConfig(Parcel parcel) {
        this.requestedOrientation = -1;
        this.buttonFeatures = CustomCameraView.BUTTON_STATE_BOTH;
        this.maxVideoSelectNum = 1;
        this.minimumCompressSize = 100;
        this.imageSpanCount = 4;
        this.pageSize = 60;
        this.chooseMode = parcel.readInt();
        this.camera = parcel.readByte() != 0;
        this.isSingleDirectReturn = parcel.readByte() != 0;
        this.compressSavePath = parcel.readString();
        this.suffixType = parcel.readString();
        this.focusAlpha = parcel.readByte() != 0;
        this.renameCompressFileName = parcel.readString();
        this.renameCropFileName = parcel.readString();
        this.specifiedFormat = parcel.readString();
        this.requestedOrientation = parcel.readInt();
        this.buttonFeatures = parcel.readInt();
        this.isCameraAroundState = parcel.readByte() != 0;
        this.isAndroidQTransform = parcel.readByte() != 0;
        this.themeStyleId = parcel.readInt();
        this.selectionMode = parcel.readInt();
        this.maxSelectNum = parcel.readInt();
        this.minSelectNum = parcel.readInt();
        this.maxVideoSelectNum = parcel.readInt();
        this.minVideoSelectNum = parcel.readInt();
        this.videoQuality = parcel.readInt();
        this.cropCompressQuality = parcel.readInt();
        this.videoMaxSecond = parcel.readInt();
        this.videoMinSecond = parcel.readInt();
        this.recordVideoSecond = parcel.readInt();
        this.recordVideoMinSecond = parcel.readInt();
        this.minimumCompressSize = parcel.readInt();
        this.imageSpanCount = parcel.readInt();
        this.aspect_ratio_x = parcel.readInt();
        this.aspect_ratio_y = parcel.readInt();
        this.cropWidth = parcel.readInt();
        this.cropHeight = parcel.readInt();
        this.compressQuality = parcel.readInt();
        this.filterFileSize = parcel.readFloat();
        this.language = parcel.readInt();
        this.isMultipleRecyclerAnimation = parcel.readByte() != 0;
        this.isMultipleSkipCrop = parcel.readByte() != 0;
        this.isWeChatStyle = parcel.readByte() != 0;
        this.isUseCustomCamera = parcel.readByte() != 0;
        this.zoomAnim = parcel.readByte() != 0;
        this.isCompress = parcel.readByte() != 0;
        this.isOriginalControl = parcel.readByte() != 0;
        this.isCamera = parcel.readByte() != 0;
        this.isGif = parcel.readByte() != 0;
        this.isWebp = parcel.readByte() != 0;
        this.isBmp = parcel.readByte() != 0;
        this.enablePreview = parcel.readByte() != 0;
        this.enPreviewVideo = parcel.readByte() != 0;
        this.enablePreviewAudio = parcel.readByte() != 0;
        this.checkNumMode = parcel.readByte() != 0;
        this.openClickSound = parcel.readByte() != 0;
        this.enableCrop = parcel.readByte() != 0;
        this.freeStyleCropEnabled = parcel.readByte() != 0;
        this.circleDimmedLayer = parcel.readByte() != 0;
        this.circleDimmedColor = parcel.readInt();
        this.circleDimmedBorderColor = parcel.readInt();
        this.circleStrokeWidth = parcel.readInt();
        this.showCropFrame = parcel.readByte() != 0;
        this.showCropGrid = parcel.readByte() != 0;
        this.hideBottomControls = parcel.readByte() != 0;
        this.rotateEnabled = parcel.readByte() != 0;
        this.scaleEnabled = parcel.readByte() != 0;
        this.previewEggs = parcel.readByte() != 0;
        this.synOrAsy = parcel.readByte() != 0;
        this.returnEmpty = parcel.readByte() != 0;
        this.isDragFrame = parcel.readByte() != 0;
        this.isNotPreviewDownload = parcel.readByte() != 0;
        this.isWithVideoImage = parcel.readByte() != 0;
        this.uCropOptions = (UCropOptions) parcel.readParcelable(UCropOptions.class.getClassLoader());
        this.selectionMedias = parcel.createTypedArrayList(LocalMedia.CREATOR);
        this.cameraFileName = parcel.readString();
        this.isCheckOriginalImage = parcel.readByte() != 0;
        this.overrideWidth = parcel.readInt();
        this.overrideHeight = parcel.readInt();
        this.sizeMultiplier = parcel.readFloat();
        this.isChangeStatusBarFontColor = parcel.readByte() != 0;
        this.isOpenStyleNumComplete = parcel.readByte() != 0;
        this.isOpenStyleCheckNumMode = parcel.readByte() != 0;
        this.titleBarBackgroundColor = parcel.readInt();
        this.pictureStatusBarColor = parcel.readInt();
        this.cropTitleBarBackgroundColor = parcel.readInt();
        this.cropStatusBarColorPrimaryDark = parcel.readInt();
        this.cropTitleColor = parcel.readInt();
        this.upResId = parcel.readInt();
        this.downResId = parcel.readInt();
        this.outPutCameraPath = parcel.readString();
        this.originalPath = parcel.readString();
        this.cameraPath = parcel.readString();
        this.cameraMimeType = parcel.readInt();
        this.pageSize = parcel.readInt();
        this.isPageStrategy = parcel.readByte() != 0;
        this.isFilterInvalidFile = parcel.readByte() != 0;
        this.isMaxSelectEnabledMask = parcel.readByte() != 0;
        this.animationMode = parcel.readInt();
        this.isAutomaticTitleRecyclerTop = parcel.readByte() != 0;
        this.isCallbackMode = parcel.readByte() != 0;
        this.isAndroidQChangeWH = parcel.readByte() != 0;
        this.isAndroidQChangeVideoWH = parcel.readByte() != 0;
        this.isQuickCapture = parcel.readByte() != 0;
        this.isFallbackVersion = parcel.readByte() != 0;
        this.isFallbackVersion2 = parcel.readByte() != 0;
        this.isFallbackVersion3 = parcel.readByte() != 0;
    }
}
