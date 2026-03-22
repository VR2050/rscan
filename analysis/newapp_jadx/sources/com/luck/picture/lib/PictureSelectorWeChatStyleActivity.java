package com.luck.picture.lib;

import android.content.Context;
import android.content.res.ColorStateList;
import android.text.TextUtils;
import android.view.View;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.style.PictureSelectorUIStyle;
import com.luck.picture.lib.tools.AttrsUtils;
import com.luck.picture.lib.widget.FolderPopWindow;
import java.util.List;

/* loaded from: classes2.dex */
public class PictureSelectorWeChatStyleActivity extends PictureSelectorActivity {
    private RelativeLayout rlAlbum;

    private void goneParentView() {
        this.mTvPictureImgNum.setVisibility(8);
        this.mTvPictureOk.setVisibility(8);
    }

    @Override // com.luck.picture.lib.PictureSelectorActivity
    public void changeImageNumber(List<LocalMedia> list) {
        int size = list.size();
        if (!(size != 0)) {
            this.mTvPictureRight.setEnabled(false);
            this.mTvPictureRight.setSelected(false);
            this.mTvPicturePreview.setEnabled(false);
            this.mTvPicturePreview.setSelected(false);
            PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle != null) {
                int i2 = pictureSelectorUIStyle.picture_top_titleRightTextDefaultBackground;
                if (i2 != 0) {
                    this.mTvPictureRight.setBackgroundResource(i2);
                } else {
                    this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_default_bg);
                }
                if (TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_top_titleRightDefaultText)) {
                    this.mTvPictureRight.setText(getString(C3979R.string.picture_send));
                } else {
                    this.mTvPictureRight.setText(PictureSelectionConfig.uiStyle.picture_top_titleRightDefaultText);
                }
                if (TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_bottom_previewDefaultText)) {
                    this.mTvPicturePreview.setText(getString(C3979R.string.picture_preview));
                    return;
                } else {
                    this.mTvPicturePreview.setText(PictureSelectionConfig.uiStyle.picture_bottom_previewDefaultText);
                    return;
                }
            }
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle == null) {
                this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_default_bg);
                this.mTvPictureRight.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_53575e));
                this.mTvPicturePreview.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_9b));
                this.mTvPicturePreview.setText(getString(C3979R.string.picture_preview));
                this.mTvPictureRight.setText(getString(C3979R.string.picture_send));
                return;
            }
            int i3 = pictureParameterStyle.pictureUnCompleteBackgroundStyle;
            if (i3 != 0) {
                this.mTvPictureRight.setBackgroundResource(i3);
            } else {
                this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_default_bg);
            }
            int i4 = PictureSelectionConfig.style.pictureUnCompleteTextColor;
            if (i4 != 0) {
                this.mTvPictureRight.setTextColor(i4);
            } else {
                this.mTvPictureRight.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_53575e));
            }
            int i5 = PictureSelectionConfig.style.pictureUnPreviewTextColor;
            if (i5 != 0) {
                this.mTvPicturePreview.setTextColor(i5);
            } else {
                this.mTvPicturePreview.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_9b));
            }
            if (TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText)) {
                this.mTvPictureRight.setText(getString(C3979R.string.picture_send));
            } else {
                this.mTvPictureRight.setText(PictureSelectionConfig.style.pictureUnCompleteText);
            }
            if (TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnPreviewText)) {
                this.mTvPicturePreview.setText(getString(C3979R.string.picture_preview));
                return;
            } else {
                this.mTvPicturePreview.setText(PictureSelectionConfig.style.pictureUnPreviewText);
                return;
            }
        }
        this.mTvPictureRight.setEnabled(true);
        this.mTvPictureRight.setSelected(true);
        this.mTvPicturePreview.setEnabled(true);
        this.mTvPicturePreview.setSelected(true);
        initCompleteText(list);
        PictureSelectorUIStyle pictureSelectorUIStyle2 = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle2 != null) {
            int i6 = pictureSelectorUIStyle2.picture_top_titleRightTextNormalBackground;
            if (i6 != 0) {
                this.mTvPictureRight.setBackgroundResource(i6);
            } else {
                this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_bg);
            }
            int[] iArr = PictureSelectionConfig.uiStyle.picture_bottom_previewTextColor;
            if (iArr.length > 0) {
                ColorStateList colorStateList = AttrsUtils.getColorStateList(iArr);
                if (colorStateList != null) {
                    this.mTvPicturePreview.setTextColor(colorStateList);
                }
            } else {
                this.mTvPicturePreview.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_white));
            }
            if (TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_bottom_previewNormalText)) {
                this.mTvPicturePreview.setText(getString(C3979R.string.picture_preview_num, new Object[]{Integer.valueOf(size)}));
                return;
            }
            PictureSelectorUIStyle pictureSelectorUIStyle3 = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle3.isCompleteReplaceNum) {
                this.mTvPicturePreview.setText(String.format(pictureSelectorUIStyle3.picture_bottom_previewNormalText, Integer.valueOf(size)));
                return;
            } else {
                this.mTvPicturePreview.setText(pictureSelectorUIStyle3.picture_bottom_previewNormalText);
                return;
            }
        }
        PictureParameterStyle pictureParameterStyle2 = PictureSelectionConfig.style;
        if (pictureParameterStyle2 == null) {
            this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_bg);
            TextView textView = this.mTvPictureRight;
            Context context = getContext();
            int i7 = C3979R.color.picture_color_white;
            textView.setTextColor(ContextCompat.getColor(context, i7));
            this.mTvPicturePreview.setTextColor(ContextCompat.getColor(getContext(), i7));
            this.mTvPicturePreview.setText(getString(C3979R.string.picture_preview_num, new Object[]{Integer.valueOf(size)}));
            return;
        }
        int i8 = pictureParameterStyle2.pictureCompleteBackgroundStyle;
        if (i8 != 0) {
            this.mTvPictureRight.setBackgroundResource(i8);
        } else {
            this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_bg);
        }
        int i9 = PictureSelectionConfig.style.pictureCompleteTextColor;
        if (i9 != 0) {
            this.mTvPictureRight.setTextColor(i9);
        } else {
            this.mTvPictureRight.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_white));
        }
        int i10 = PictureSelectionConfig.style.picturePreviewTextColor;
        if (i10 != 0) {
            this.mTvPicturePreview.setTextColor(i10);
        } else {
            this.mTvPicturePreview.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_white));
        }
        if (TextUtils.isEmpty(PictureSelectionConfig.style.picturePreviewText)) {
            this.mTvPicturePreview.setText(getString(C3979R.string.picture_preview_num, new Object[]{Integer.valueOf(size)}));
        } else {
            this.mTvPicturePreview.setText(PictureSelectionConfig.style.picturePreviewText);
        }
    }

    @Override // com.luck.picture.lib.PictureSelectorActivity, com.luck.picture.lib.PictureBaseActivity
    public int getResourceId() {
        return C3979R.layout.picture_wechat_style_selector;
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initCompleteText(List<LocalMedia> list) {
        int i2;
        int size = list.size();
        PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
        boolean z = pictureParameterStyle != null;
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.isWithVideoImage) {
            if (pictureSelectionConfig.selectionMode != 1) {
                if (!(z && pictureParameterStyle.isCompleteReplaceNum) || TextUtils.isEmpty(pictureParameterStyle.pictureCompleteText)) {
                    this.mTvPictureRight.setText((!z || TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText)) ? getString(C3979R.string.picture_send_num, new Object[]{Integer.valueOf(size), Integer.valueOf(this.config.maxSelectNum)}) : PictureSelectionConfig.style.pictureUnCompleteText);
                    return;
                } else {
                    this.mTvPictureRight.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(size), Integer.valueOf(this.config.maxSelectNum)));
                    return;
                }
            }
            if (size <= 0) {
                this.mTvPictureRight.setText((!z || TextUtils.isEmpty(pictureParameterStyle.pictureUnCompleteText)) ? getString(C3979R.string.picture_send) : PictureSelectionConfig.style.pictureUnCompleteText);
                return;
            }
            if (!(z && pictureParameterStyle.isCompleteReplaceNum) || TextUtils.isEmpty(pictureParameterStyle.pictureCompleteText)) {
                this.mTvPictureRight.setText((!z || TextUtils.isEmpty(PictureSelectionConfig.style.pictureCompleteText)) ? getString(C3979R.string.picture_send) : PictureSelectionConfig.style.pictureCompleteText);
                return;
            } else {
                this.mTvPictureRight.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(size), 1));
                return;
            }
        }
        if (!PictureMimeType.isHasVideo(list.get(0).getMimeType()) || (i2 = this.config.maxVideoSelectNum) <= 0) {
            i2 = this.config.maxSelectNum;
        }
        if (this.config.selectionMode == 1) {
            if (!(z && PictureSelectionConfig.style.isCompleteReplaceNum) || TextUtils.isEmpty(PictureSelectionConfig.style.pictureCompleteText)) {
                this.mTvPictureRight.setText((!z || TextUtils.isEmpty(PictureSelectionConfig.style.pictureCompleteText)) ? getString(C3979R.string.picture_send) : PictureSelectionConfig.style.pictureCompleteText);
                return;
            } else {
                this.mTvPictureRight.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(size), 1));
                return;
            }
        }
        if (!(z && PictureSelectionConfig.style.isCompleteReplaceNum) || TextUtils.isEmpty(PictureSelectionConfig.style.pictureCompleteText)) {
            this.mTvPictureRight.setText((!z || TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText)) ? getString(C3979R.string.picture_send_num, new Object[]{Integer.valueOf(size), Integer.valueOf(i2)}) : PictureSelectionConfig.style.pictureUnCompleteText);
        } else {
            this.mTvPictureRight.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(size), Integer.valueOf(i2)));
        }
    }

    @Override // com.luck.picture.lib.PictureSelectorActivity, com.luck.picture.lib.PictureBaseActivity
    public void initPictureSelectorStyle() {
        PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle != null) {
            int i2 = pictureSelectorUIStyle.picture_top_titleRightTextDefaultBackground;
            if (i2 != 0) {
                this.mTvPictureRight.setBackgroundResource(i2);
            } else {
                this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_default_bg);
            }
            int i3 = PictureSelectionConfig.uiStyle.picture_bottom_barBackgroundColor;
            if (i3 != 0) {
                this.mBottomLayout.setBackgroundColor(i3);
            } else {
                this.mBottomLayout.setBackgroundColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_grey));
            }
            int[] iArr = PictureSelectionConfig.uiStyle.picture_top_titleRightTextColor;
            if (iArr.length > 0) {
                ColorStateList colorStateList = AttrsUtils.getColorStateList(iArr);
                if (colorStateList != null) {
                    this.mTvPictureRight.setTextColor(colorStateList);
                }
            } else {
                this.mTvPictureRight.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_53575e));
            }
            int i4 = PictureSelectionConfig.uiStyle.picture_top_titleRightTextSize;
            if (i4 != 0) {
                this.mTvPictureRight.setTextSize(i4);
            }
            if (this.config.isOriginalControl) {
                int i5 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureCheckStyle;
                if (i5 != 0) {
                    this.mCbOriginal.setButtonDrawable(i5);
                }
                int i6 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureTextColor;
                if (i6 != 0) {
                    this.mCbOriginal.setTextColor(i6);
                }
                int i7 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureTextSize;
                if (i7 != 0) {
                    this.mCbOriginal.setTextSize(i7);
                }
            }
            int i8 = PictureSelectionConfig.uiStyle.picture_container_backgroundColor;
            if (i8 != 0) {
                this.container.setBackgroundColor(i8);
            }
            int i9 = PictureSelectionConfig.uiStyle.picture_top_titleAlbumBackground;
            if (i9 != 0) {
                this.rlAlbum.setBackgroundResource(i9);
            } else {
                this.rlAlbum.setBackgroundResource(C3979R.drawable.picture_album_bg);
            }
            if (!TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_top_titleRightDefaultText)) {
                this.mTvPictureRight.setText(PictureSelectionConfig.uiStyle.picture_top_titleRightDefaultText);
            }
        } else {
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle != null) {
                int i10 = pictureParameterStyle.pictureUnCompleteBackgroundStyle;
                if (i10 != 0) {
                    this.mTvPictureRight.setBackgroundResource(i10);
                } else {
                    this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_default_bg);
                }
                int i11 = PictureSelectionConfig.style.pictureBottomBgColor;
                if (i11 != 0) {
                    this.mBottomLayout.setBackgroundColor(i11);
                } else {
                    this.mBottomLayout.setBackgroundColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_grey));
                }
                PictureParameterStyle pictureParameterStyle2 = PictureSelectionConfig.style;
                int i12 = pictureParameterStyle2.pictureUnCompleteTextColor;
                if (i12 != 0) {
                    this.mTvPictureRight.setTextColor(i12);
                } else {
                    int i13 = pictureParameterStyle2.pictureCancelTextColor;
                    if (i13 != 0) {
                        this.mTvPictureRight.setTextColor(i13);
                    } else {
                        this.mTvPictureRight.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_53575e));
                    }
                }
                int i14 = PictureSelectionConfig.style.pictureRightTextSize;
                if (i14 != 0) {
                    this.mTvPictureRight.setTextSize(i14);
                }
                if (PictureSelectionConfig.style.pictureOriginalFontColor == 0) {
                    this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_white));
                }
                if (this.config.isOriginalControl && PictureSelectionConfig.style.pictureOriginalControlStyle == 0) {
                    this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_wechat_checkbox));
                }
                int i15 = PictureSelectionConfig.style.pictureContainerBackgroundColor;
                if (i15 != 0) {
                    this.container.setBackgroundColor(i15);
                }
                int i16 = PictureSelectionConfig.style.pictureWeChatTitleBackgroundStyle;
                if (i16 != 0) {
                    this.rlAlbum.setBackgroundResource(i16);
                } else {
                    this.rlAlbum.setBackgroundResource(C3979R.drawable.picture_album_bg);
                }
                if (!TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText)) {
                    this.mTvPictureRight.setText(PictureSelectionConfig.style.pictureUnCompleteText);
                }
            } else {
                this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_default_bg);
                this.rlAlbum.setBackgroundResource(C3979R.drawable.picture_album_bg);
                this.mTvPictureRight.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_53575e));
                int typeValueColor = AttrsUtils.getTypeValueColor(getContext(), C3979R.attr.picture_bottom_bg);
                RelativeLayout relativeLayout = this.mBottomLayout;
                if (typeValueColor == 0) {
                    typeValueColor = ContextCompat.getColor(getContext(), C3979R.color.picture_color_grey);
                }
                relativeLayout.setBackgroundColor(typeValueColor);
                this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_white));
                this.mIvArrow.setImageDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_icon_wechat_down));
                if (this.config.isOriginalControl) {
                    this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_wechat_checkbox));
                }
            }
        }
        super.initPictureSelectorStyle();
        goneParentView();
    }

    @Override // com.luck.picture.lib.PictureSelectorActivity, com.luck.picture.lib.PictureBaseActivity
    public void initWidgets() {
        super.initWidgets();
        this.rlAlbum = (RelativeLayout) findViewById(C3979R.id.rlAlbum);
        this.mTvPictureRight.setOnClickListener(this);
        this.mTvPictureRight.setText(getString(C3979R.string.picture_send));
        this.mTvPicturePreview.setTextSize(16.0f);
        this.mCbOriginal.setTextSize(16.0f);
        PictureSelectionConfig pictureSelectionConfig = this.config;
        boolean z = pictureSelectionConfig.selectionMode == 1 && pictureSelectionConfig.isSingleDirectReturn;
        this.mTvPictureRight.setVisibility(z ? 8 : 0);
        this.mTvPictureRight.setOnClickListener(this);
        if (this.rlAlbum.getLayoutParams() instanceof RelativeLayout.LayoutParams) {
            RelativeLayout.LayoutParams layoutParams = (RelativeLayout.LayoutParams) this.rlAlbum.getLayoutParams();
            if (z) {
                layoutParams.addRule(14);
            } else {
                layoutParams.addRule(1, C3979R.id.pictureLeftBack);
            }
        }
    }

    @Override // com.luck.picture.lib.PictureSelectorActivity
    public void onChangeData(List<LocalMedia> list) {
        super.onChangeData(list);
        initCompleteText(list);
    }

    @Override // com.luck.picture.lib.PictureSelectorActivity, android.view.View.OnClickListener
    public void onClick(View view) {
        if (view.getId() != C3979R.id.picture_right) {
            super.onClick(view);
            return;
        }
        FolderPopWindow folderPopWindow = this.folderWindow;
        if (folderPopWindow == null || !folderPopWindow.isShowing()) {
            this.mTvPictureOk.performClick();
        } else {
            this.folderWindow.dismiss();
        }
    }
}
