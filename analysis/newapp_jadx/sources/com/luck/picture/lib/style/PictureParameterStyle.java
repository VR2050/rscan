package com.luck.picture.lib.style;

import android.graphics.Color;
import androidx.annotation.ColorInt;
import androidx.annotation.DrawableRes;
import com.luck.picture.lib.C3979R;

/* loaded from: classes2.dex */
public class PictureParameterStyle {
    public int folderTextColor;
    public int folderTextSize;
    public boolean isChangeStatusBarFontColor;
    public boolean isCompleteReplaceNum;
    public boolean isNewSelectStyle;
    public boolean isOpenCheckNumStyle;
    public boolean isOpenCompletedNumStyle;

    @DrawableRes
    public int pictureAlbumStyle;

    @ColorInt
    public int pictureBottomBgColor;

    @ColorInt
    @Deprecated
    public int pictureCancelTextColor;

    @DrawableRes
    public int pictureCheckNumBgStyle;

    @DrawableRes
    public int pictureCheckedStyle;

    @DrawableRes
    public int pictureCompleteBackgroundStyle;
    public String pictureCompleteText;

    @ColorInt
    public int pictureCompleteTextColor;
    public int pictureCompleteTextSize;

    @ColorInt
    public int pictureContainerBackgroundColor;

    @DrawableRes
    public int pictureExternalPreviewDeleteStyle;
    public boolean pictureExternalPreviewGonePreviewDelete;

    @DrawableRes
    public int pictureFolderCheckedDotStyle;

    @DrawableRes
    public int pictureLeftBackIcon;

    @ColorInt
    public int pictureNavBarColor;

    @DrawableRes
    public int pictureOriginalControlStyle;

    @ColorInt
    public int pictureOriginalFontColor;
    public int pictureOriginalTextSize;

    @ColorInt
    public int picturePreviewBottomBgColor;
    public String picturePreviewText;

    @ColorInt
    public int picturePreviewTextColor;
    public int picturePreviewTextSize;
    public String pictureRightDefaultText;

    @ColorInt
    public int pictureRightDefaultTextColor;

    @ColorInt
    public int pictureRightSelectedTextColor;
    public int pictureRightTextSize;

    @ColorInt
    public int pictureStatusBarColor;

    @ColorInt
    public int pictureTitleBarBackgroundColor;
    public int pictureTitleBarHeight;

    @DrawableRes
    public int pictureTitleDownResId;
    public int pictureTitleRightArrowLeftPadding;

    @ColorInt
    public int pictureTitleTextColor;
    public int pictureTitleTextSize;

    @DrawableRes
    public int pictureTitleUpResId;

    @DrawableRes
    public int pictureUnCompleteBackgroundStyle;
    public String pictureUnCompleteText;

    @ColorInt
    public int pictureUnCompleteTextColor;
    public String pictureUnPreviewText;

    @ColorInt
    public int pictureUnPreviewTextColor;

    @DrawableRes
    public int pictureWeChatChooseStyle;

    @DrawableRes
    public int pictureWeChatLeftBackStyle;
    public String pictureWeChatPreviewSelectedText;
    public int pictureWeChatPreviewSelectedTextSize;

    @DrawableRes
    public int pictureWeChatTitleBackgroundStyle;

    public static PictureParameterStyle ofDefaultStyle() {
        PictureParameterStyle pictureParameterStyle = new PictureParameterStyle();
        pictureParameterStyle.isChangeStatusBarFontColor = false;
        pictureParameterStyle.isOpenCompletedNumStyle = false;
        pictureParameterStyle.isOpenCheckNumStyle = false;
        pictureParameterStyle.pictureStatusBarColor = Color.parseColor("#393a3e");
        pictureParameterStyle.pictureTitleBarBackgroundColor = Color.parseColor("#393a3e");
        pictureParameterStyle.pictureContainerBackgroundColor = Color.parseColor("#000000");
        pictureParameterStyle.pictureTitleUpResId = C3979R.drawable.picture_icon_arrow_up;
        pictureParameterStyle.pictureTitleDownResId = C3979R.drawable.picture_icon_arrow_down;
        pictureParameterStyle.pictureFolderCheckedDotStyle = C3979R.drawable.picture_orange_oval;
        pictureParameterStyle.pictureLeftBackIcon = C3979R.drawable.picture_icon_back;
        pictureParameterStyle.pictureTitleTextColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureCancelTextColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureAlbumStyle = C3979R.drawable.picture_item_select_bg;
        pictureParameterStyle.pictureCheckedStyle = C3979R.drawable.picture_checkbox_selector;
        pictureParameterStyle.pictureBottomBgColor = Color.parseColor("#393a3e");
        pictureParameterStyle.pictureCheckNumBgStyle = C3979R.drawable.picture_num_oval;
        pictureParameterStyle.picturePreviewTextColor = Color.parseColor("#FA632D");
        pictureParameterStyle.pictureUnPreviewTextColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureCompleteTextColor = Color.parseColor("#FA632D");
        pictureParameterStyle.pictureUnCompleteTextColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.picturePreviewBottomBgColor = Color.parseColor("#393a3e");
        pictureParameterStyle.pictureExternalPreviewDeleteStyle = C3979R.drawable.picture_icon_delete;
        pictureParameterStyle.pictureOriginalControlStyle = C3979R.drawable.picture_original_wechat_checkbox;
        pictureParameterStyle.pictureOriginalFontColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureExternalPreviewGonePreviewDelete = true;
        pictureParameterStyle.pictureNavBarColor = Color.parseColor("#393a3e");
        return pictureParameterStyle;
    }

    public static PictureParameterStyle ofNewStyle() {
        PictureParameterStyle pictureParameterStyle = new PictureParameterStyle();
        pictureParameterStyle.isNewSelectStyle = true;
        pictureParameterStyle.isChangeStatusBarFontColor = false;
        pictureParameterStyle.isOpenCompletedNumStyle = false;
        pictureParameterStyle.isOpenCheckNumStyle = true;
        pictureParameterStyle.pictureStatusBarColor = Color.parseColor("#393a3e");
        pictureParameterStyle.pictureTitleBarBackgroundColor = Color.parseColor("#393a3e");
        pictureParameterStyle.pictureContainerBackgroundColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureTitleUpResId = C3979R.drawable.picture_icon_wechat_up;
        pictureParameterStyle.pictureTitleDownResId = C3979R.drawable.picture_icon_wechat_down;
        pictureParameterStyle.pictureFolderCheckedDotStyle = C3979R.drawable.picture_orange_oval;
        pictureParameterStyle.pictureLeftBackIcon = C3979R.drawable.picture_icon_close;
        pictureParameterStyle.pictureTitleTextColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureCancelTextColor = Color.parseColor("#53575e");
        pictureParameterStyle.pictureRightDefaultTextColor = Color.parseColor("#53575e");
        pictureParameterStyle.pictureRightSelectedTextColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureUnCompleteBackgroundStyle = C3979R.drawable.picture_send_button_default_bg;
        pictureParameterStyle.pictureCompleteBackgroundStyle = C3979R.drawable.picture_send_button_bg;
        pictureParameterStyle.pictureAlbumStyle = C3979R.drawable.picture_item_select_bg;
        pictureParameterStyle.pictureCheckedStyle = C3979R.drawable.picture_wechat_num_selector;
        pictureParameterStyle.pictureWeChatTitleBackgroundStyle = C3979R.drawable.picture_album_bg;
        pictureParameterStyle.pictureWeChatChooseStyle = C3979R.drawable.picture_wechat_select_cb;
        pictureParameterStyle.pictureWeChatLeftBackStyle = C3979R.drawable.picture_icon_back;
        pictureParameterStyle.pictureBottomBgColor = Color.parseColor("#393a3e");
        pictureParameterStyle.pictureCheckNumBgStyle = C3979R.drawable.picture_num_oval;
        pictureParameterStyle.picturePreviewTextColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureUnPreviewTextColor = Color.parseColor("#9b9b9b");
        pictureParameterStyle.pictureCompleteTextColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureUnCompleteTextColor = Color.parseColor("#53575e");
        pictureParameterStyle.picturePreviewBottomBgColor = Color.parseColor("#a0393a3e");
        pictureParameterStyle.pictureExternalPreviewDeleteStyle = C3979R.drawable.picture_icon_delete;
        pictureParameterStyle.pictureOriginalControlStyle = C3979R.drawable.picture_original_wechat_checkbox;
        pictureParameterStyle.pictureOriginalFontColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureExternalPreviewGonePreviewDelete = true;
        pictureParameterStyle.pictureNavBarColor = Color.parseColor("#393a3e");
        return pictureParameterStyle;
    }

    public static PictureParameterStyle ofSelectNumberStyle() {
        PictureParameterStyle pictureParameterStyle = new PictureParameterStyle();
        pictureParameterStyle.isChangeStatusBarFontColor = false;
        pictureParameterStyle.isOpenCompletedNumStyle = false;
        pictureParameterStyle.isOpenCheckNumStyle = true;
        pictureParameterStyle.pictureStatusBarColor = Color.parseColor("#7D7DFF");
        pictureParameterStyle.pictureTitleBarBackgroundColor = Color.parseColor("#7D7DFF");
        pictureParameterStyle.pictureTitleUpResId = C3979R.drawable.picture_icon_arrow_up;
        pictureParameterStyle.pictureTitleDownResId = C3979R.drawable.picture_icon_arrow_down;
        pictureParameterStyle.pictureFolderCheckedDotStyle = C3979R.drawable.picture_orange_oval;
        pictureParameterStyle.pictureLeftBackIcon = C3979R.drawable.picture_icon_back;
        pictureParameterStyle.pictureTitleTextColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureCancelTextColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureAlbumStyle = C3979R.drawable.picture_item_select_bg;
        pictureParameterStyle.pictureCheckedStyle = C3979R.drawable.picture_checkbox_num_selector;
        pictureParameterStyle.pictureBottomBgColor = Color.parseColor("#FAFAFA");
        pictureParameterStyle.pictureCheckNumBgStyle = C3979R.drawable.picture_num_oval_blue;
        pictureParameterStyle.picturePreviewTextColor = Color.parseColor("#7D7DFF");
        pictureParameterStyle.pictureUnPreviewTextColor = Color.parseColor("#7D7DFF");
        pictureParameterStyle.pictureCompleteTextColor = Color.parseColor("#7D7DFF");
        pictureParameterStyle.pictureUnCompleteTextColor = Color.parseColor("#7D7DFF");
        pictureParameterStyle.picturePreviewBottomBgColor = Color.parseColor("#FAFAFA");
        pictureParameterStyle.pictureOriginalControlStyle = C3979R.drawable.picture_original_blue_checkbox;
        pictureParameterStyle.pictureOriginalFontColor = Color.parseColor("#7D7DFF");
        pictureParameterStyle.pictureExternalPreviewDeleteStyle = C3979R.drawable.picture_icon_delete;
        pictureParameterStyle.pictureExternalPreviewGonePreviewDelete = true;
        return pictureParameterStyle;
    }

    public static PictureParameterStyle ofSelectTotalStyle() {
        PictureParameterStyle pictureParameterStyle = new PictureParameterStyle();
        pictureParameterStyle.isChangeStatusBarFontColor = true;
        pictureParameterStyle.isOpenCompletedNumStyle = true;
        pictureParameterStyle.isOpenCheckNumStyle = false;
        pictureParameterStyle.pictureStatusBarColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureTitleBarBackgroundColor = Color.parseColor("#FFFFFF");
        pictureParameterStyle.pictureTitleUpResId = C3979R.drawable.picture_icon_orange_arrow_up;
        pictureParameterStyle.pictureTitleDownResId = C3979R.drawable.picture_icon_orange_arrow_down;
        pictureParameterStyle.pictureFolderCheckedDotStyle = C3979R.drawable.picture_orange_oval;
        pictureParameterStyle.pictureLeftBackIcon = C3979R.drawable.picture_icon_back_arrow;
        pictureParameterStyle.pictureTitleTextColor = Color.parseColor("#000000");
        pictureParameterStyle.pictureCancelTextColor = Color.parseColor("#000000");
        pictureParameterStyle.pictureAlbumStyle = C3979R.drawable.picture_item_select_bg;
        pictureParameterStyle.pictureCheckedStyle = C3979R.drawable.picture_checkbox_selector;
        pictureParameterStyle.pictureBottomBgColor = Color.parseColor("#FAFAFA");
        pictureParameterStyle.pictureCheckNumBgStyle = C3979R.drawable.picture_num_oval;
        pictureParameterStyle.picturePreviewTextColor = Color.parseColor("#FA632D");
        pictureParameterStyle.pictureUnPreviewTextColor = Color.parseColor("#9b9b9b");
        pictureParameterStyle.pictureCompleteTextColor = Color.parseColor("#FA632D");
        pictureParameterStyle.pictureUnCompleteTextColor = Color.parseColor("#9b9b9b");
        pictureParameterStyle.picturePreviewBottomBgColor = Color.parseColor("#FAFAFA");
        pictureParameterStyle.pictureOriginalControlStyle = C3979R.drawable.picture_original_checkbox;
        pictureParameterStyle.pictureOriginalFontColor = Color.parseColor("#53575e");
        pictureParameterStyle.pictureExternalPreviewDeleteStyle = C3979R.drawable.picture_icon_black_delete;
        pictureParameterStyle.pictureExternalPreviewGonePreviewDelete = true;
        return pictureParameterStyle;
    }
}
