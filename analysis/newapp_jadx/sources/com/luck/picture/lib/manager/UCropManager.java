package com.luck.picture.lib.manager;

import android.app.Activity;
import android.net.Uri;
import android.text.TextUtils;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.tools.DateUtils;
import com.luck.picture.lib.tools.DoubleUtils;
import com.luck.picture.lib.tools.PictureFileUtils;
import com.luck.picture.lib.tools.SdkVersionUtils;
import com.luck.picture.lib.tools.StringUtils;
import com.luck.picture.lib.tools.ToastUtils;
import com.yalantis.ucrop.UCrop;
import com.yalantis.ucrop.model.CutInfo;
import java.io.File;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public class UCropManager {
    /* JADX WARN: Code restructure failed: missing block: B:10:0x001b, code lost:
    
        if (r1 != 0) goto L14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x001d, code lost:
    
        r2 = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x0035, code lost:
    
        if (r1 != 0) goto L14;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.yalantis.ucrop.UCrop.Options basicOptions(android.content.Context r6) {
        /*
            Method dump skipped, instructions count: 242
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.manager.UCropManager.basicOptions(android.content.Context):com.yalantis.ucrop.UCrop$Options");
    }

    public static void ofCrop(Activity activity, String str, String str2) {
        String str3;
        if (DoubleUtils.isFastDoubleClick()) {
            return;
        }
        if (TextUtils.isEmpty(str)) {
            ToastUtils.m4555s(activity.getApplicationContext(), activity.getString(C3979R.string.picture_not_crop_data));
            return;
        }
        PictureSelectionConfig pictureSelectionConfig = PictureSelectionConfig.getInstance();
        boolean isHasHttp = PictureMimeType.isHasHttp(str);
        String replace = str2.replace("image/", ".");
        String diskCacheDir = PictureFileUtils.getDiskCacheDir(activity.getApplicationContext());
        if (TextUtils.isEmpty(pictureSelectionConfig.renameCropFileName)) {
            str3 = DateUtils.getCreateFileName("IMG_CROP_") + replace;
        } else {
            str3 = pictureSelectionConfig.renameCropFileName;
        }
        UCrop.m4745of((isHasHttp || SdkVersionUtils.checkedAndroid_Q()) ? Uri.parse(str) : Uri.fromFile(new File(str)), Uri.fromFile(new File(diskCacheDir, str3))).withOptions(basicOptions(activity)).startAnimationActivity(activity, PictureSelectionConfig.windowAnimationStyle.activityCropEnterAnimation);
    }

    public static void ofCrop(Activity activity, ArrayList<CutInfo> arrayList) {
        Uri fromFile;
        String str;
        if (DoubleUtils.isFastDoubleClick()) {
            return;
        }
        if (arrayList != null && arrayList.size() != 0) {
            PictureSelectionConfig pictureSelectionConfig = PictureSelectionConfig.getInstance();
            UCrop.Options basicOptions = basicOptions(activity);
            basicOptions.setCutListData(arrayList);
            int size = arrayList.size();
            int i2 = 0;
            if (pictureSelectionConfig.chooseMode == PictureMimeType.ofAll() && pictureSelectionConfig.isWithVideoImage) {
                if (PictureMimeType.isHasVideo(size > 0 ? arrayList.get(0).getMimeType() : "")) {
                    int i3 = 0;
                    while (true) {
                        if (i3 < size) {
                            CutInfo cutInfo = arrayList.get(i3);
                            if (cutInfo != null && PictureMimeType.isHasImage(cutInfo.getMimeType())) {
                                i2 = i3;
                                break;
                            }
                            i3++;
                        } else {
                            break;
                        }
                    }
                }
            }
            if (i2 < size) {
                CutInfo cutInfo2 = arrayList.get(i2);
                boolean isHasHttp = PictureMimeType.isHasHttp(cutInfo2.getPath());
                if (TextUtils.isEmpty(cutInfo2.getAndroidQToPath())) {
                    fromFile = (isHasHttp || SdkVersionUtils.checkedAndroid_Q()) ? Uri.parse(cutInfo2.getPath()) : Uri.fromFile(new File(cutInfo2.getPath()));
                } else {
                    fromFile = Uri.fromFile(new File(cutInfo2.getAndroidQToPath()));
                }
                String replace = cutInfo2.getMimeType().replace("image/", ".");
                String diskCacheDir = PictureFileUtils.getDiskCacheDir(activity);
                if (TextUtils.isEmpty(pictureSelectionConfig.renameCropFileName)) {
                    str = DateUtils.getCreateFileName("IMG_CROP_") + replace;
                } else if (!pictureSelectionConfig.camera && size != 1) {
                    str = StringUtils.rename(pictureSelectionConfig.renameCropFileName);
                } else {
                    str = pictureSelectionConfig.renameCropFileName;
                }
                UCrop.m4745of(fromFile, Uri.fromFile(new File(diskCacheDir, str))).withOptions(basicOptions).startAnimationMultipleCropActivity(activity, PictureSelectionConfig.windowAnimationStyle.activityCropEnterAnimation);
                return;
            }
            return;
        }
        ToastUtils.m4555s(activity.getApplicationContext(), activity.getString(C3979R.string.picture_not_crop_data));
    }
}
