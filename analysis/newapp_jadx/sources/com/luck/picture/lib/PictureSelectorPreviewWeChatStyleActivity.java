package com.luck.picture.lib;

import android.content.Context;
import android.graphics.Color;
import android.text.TextUtils;
import android.view.View;
import android.view.animation.AccelerateInterpolator;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;
import com.luck.picture.lib.adapter.PictureWeChatPreviewGalleryAdapter;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.style.PictureSelectorUIStyle;
import java.util.List;

/* loaded from: classes2.dex */
public class PictureSelectorPreviewWeChatStyleActivity extends PicturePreviewActivity {
    private static final int ALPHA_DURATION = 300;
    private View bottomLine;
    private PictureWeChatPreviewGalleryAdapter mGalleryAdapter;
    private RecyclerView mRvGallery;
    private TextView mTvSelected;

    private void goneParent() {
        if (this.tvMediaNum.getVisibility() == 0) {
            this.tvMediaNum.setVisibility(8);
        }
        if (this.mTvPictureOk.getVisibility() == 0) {
            this.mTvPictureOk.setVisibility(8);
        }
        if (TextUtils.isEmpty(this.check.getText())) {
            return;
        }
        this.check.setText("");
    }

    private boolean isEqualsDirectory(String str, String str2) {
        return this.isBottomPreview || TextUtils.isEmpty(str) || TextUtils.isEmpty(str2) || str2.equals(getString(C3979R.string.picture_camera_roll)) || str.equals(str2);
    }

    private void onChangeMediaStatus(LocalMedia localMedia) {
        int itemCount;
        PictureWeChatPreviewGalleryAdapter pictureWeChatPreviewGalleryAdapter = this.mGalleryAdapter;
        if (pictureWeChatPreviewGalleryAdapter == null || (itemCount = pictureWeChatPreviewGalleryAdapter.getItemCount()) <= 0) {
            return;
        }
        boolean z = false;
        for (int i2 = 0; i2 < itemCount; i2++) {
            LocalMedia item = this.mGalleryAdapter.getItem(i2);
            if (item != null && !TextUtils.isEmpty(item.getPath())) {
                boolean isChecked = item.isChecked();
                boolean z2 = true;
                boolean z3 = item.getPath().equals(localMedia.getPath()) || item.getId() == localMedia.getId();
                if (!z) {
                    if ((!isChecked || z3) && (isChecked || !z3)) {
                        z2 = false;
                    }
                    z = z2;
                }
                item.setChecked(z3);
            }
        }
        if (z) {
            this.mGalleryAdapter.notifyDataSetChanged();
        }
    }

    /* renamed from: c */
    public /* synthetic */ void m4532c(int i2, LocalMedia localMedia, View view) {
        if (this.viewPager == null || localMedia == null || !isEqualsDirectory(localMedia.getParentFolderName(), this.currentDirectory)) {
            return;
        }
        if (!this.isBottomPreview) {
            i2 = this.isShowCamera ? localMedia.position - 1 : localMedia.position;
        }
        this.viewPager.setCurrentItem(i2);
    }

    @Override // com.luck.picture.lib.PicturePreviewActivity, com.luck.picture.lib.PictureBaseActivity
    public int getResourceId() {
        return C3979R.layout.picture_wechat_style_preview;
    }

    @Override // com.luck.picture.lib.PicturePreviewActivity, com.luck.picture.lib.PictureBaseActivity
    public void initCompleteText(int i2) {
        int i3;
        PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
        boolean z = pictureParameterStyle != null;
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.isWithVideoImage) {
            if (pictureSelectionConfig.selectionMode != 1) {
                if (!(z && pictureParameterStyle.isCompleteReplaceNum) || TextUtils.isEmpty(pictureParameterStyle.pictureCompleteText)) {
                    this.mTvPictureRight.setText((!z || TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText)) ? getString(C3979R.string.picture_send_num, new Object[]{Integer.valueOf(this.selectData.size()), Integer.valueOf(this.config.maxSelectNum)}) : PictureSelectionConfig.style.pictureUnCompleteText);
                    return;
                } else {
                    this.mTvPictureRight.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(this.selectData.size()), Integer.valueOf(this.config.maxSelectNum)));
                    return;
                }
            }
            if (i2 <= 0) {
                this.mTvPictureRight.setText((!z || TextUtils.isEmpty(pictureParameterStyle.pictureUnCompleteText)) ? getString(C3979R.string.picture_send) : PictureSelectionConfig.style.pictureUnCompleteText);
                return;
            }
            if (!(z && pictureParameterStyle.isCompleteReplaceNum) || TextUtils.isEmpty(pictureParameterStyle.pictureCompleteText)) {
                this.mTvPictureRight.setText((!z || TextUtils.isEmpty(PictureSelectionConfig.style.pictureCompleteText)) ? getString(C3979R.string.picture_send) : PictureSelectionConfig.style.pictureCompleteText);
                return;
            } else {
                this.mTvPictureRight.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(this.selectData.size()), 1));
                return;
            }
        }
        if (!PictureMimeType.isHasVideo(this.selectData.get(0).getMimeType()) || (i3 = this.config.maxVideoSelectNum) <= 0) {
            i3 = this.config.maxSelectNum;
        }
        if (this.config.selectionMode != 1) {
            if (!(z && PictureSelectionConfig.style.isCompleteReplaceNum) || TextUtils.isEmpty(PictureSelectionConfig.style.pictureCompleteText)) {
                this.mTvPictureRight.setText((!z || TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText)) ? getString(C3979R.string.picture_send_num, new Object[]{Integer.valueOf(this.selectData.size()), Integer.valueOf(i3)}) : PictureSelectionConfig.style.pictureUnCompleteText);
                return;
            } else {
                this.mTvPictureRight.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(this.selectData.size()), Integer.valueOf(i3)));
                return;
            }
        }
        if (i2 <= 0) {
            this.mTvPictureRight.setText((!z || TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText)) ? getString(C3979R.string.picture_send) : PictureSelectionConfig.style.pictureUnCompleteText);
            return;
        }
        if (!(z && PictureSelectionConfig.style.isCompleteReplaceNum) || TextUtils.isEmpty(PictureSelectionConfig.style.pictureCompleteText)) {
            this.mTvPictureRight.setText((!z || TextUtils.isEmpty(PictureSelectionConfig.style.pictureCompleteText)) ? getString(C3979R.string.picture_send) : PictureSelectionConfig.style.pictureCompleteText);
        } else {
            this.mTvPictureRight.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(this.selectData.size()), 1));
        }
    }

    @Override // com.luck.picture.lib.PicturePreviewActivity, com.luck.picture.lib.PictureBaseActivity
    public void initPictureSelectorStyle() {
        super.initPictureSelectorStyle();
        PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle != null) {
            if (!TextUtils.isEmpty(pictureSelectorUIStyle.picture_top_titleRightDefaultText)) {
                this.mTvPictureRight.setText(PictureSelectionConfig.uiStyle.picture_top_titleRightDefaultText);
            }
            int i2 = PictureSelectionConfig.uiStyle.picture_top_titleRightTextNormalBackground;
            if (i2 != 0) {
                this.mTvPictureRight.setBackgroundResource(i2);
            } else {
                this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_bg);
            }
            int i3 = PictureSelectionConfig.uiStyle.picture_top_titleRightTextSize;
            if (i3 != 0) {
                this.mTvPictureRight.setTextSize(i3);
            }
            if (!TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_bottom_selectedText)) {
                this.mTvSelected.setText(PictureSelectionConfig.uiStyle.picture_bottom_selectedText);
            }
            int i4 = PictureSelectionConfig.uiStyle.picture_bottom_selectedTextSize;
            if (i4 != 0) {
                this.mTvSelected.setTextSize(i4);
            }
            int i5 = PictureSelectionConfig.uiStyle.picture_bottom_selectedTextColor;
            if (i5 != 0) {
                this.mTvSelected.setTextColor(i5);
            }
            int i6 = PictureSelectionConfig.uiStyle.picture_bottom_barBackgroundColor;
            if (i6 != 0) {
                this.selectBarLayout.setBackgroundColor(i6);
            } else {
                this.selectBarLayout.setBackgroundColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_half_grey));
            }
            this.mTvPictureRight.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_white));
            int i7 = PictureSelectionConfig.uiStyle.picture_bottom_selectedCheckStyle;
            if (i7 != 0) {
                this.check.setBackgroundResource(i7);
            } else {
                this.check.setBackgroundResource(C3979R.drawable.picture_wechat_select_cb);
            }
            int i8 = PictureSelectionConfig.uiStyle.picture_top_leftBack;
            if (i8 != 0) {
                this.pictureLeftBack.setImageResource(i8);
            } else {
                this.pictureLeftBack.setImageResource(C3979R.drawable.picture_icon_back);
            }
            int i9 = PictureSelectionConfig.uiStyle.picture_bottom_gallery_backgroundColor;
            if (i9 != 0) {
                this.mRvGallery.setBackgroundColor(i9);
            }
            if (PictureSelectionConfig.uiStyle.picture_bottom_gallery_height > 0) {
                this.mRvGallery.getLayoutParams().height = PictureSelectionConfig.uiStyle.picture_bottom_gallery_height;
            }
            if (this.config.isOriginalControl) {
                if (TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_bottom_originalPictureText)) {
                    this.mCbOriginal.setText(getString(C3979R.string.picture_original_image));
                } else {
                    this.mCbOriginal.setText(PictureSelectionConfig.uiStyle.picture_bottom_originalPictureText);
                }
                int i10 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureTextSize;
                if (i10 != 0) {
                    this.mCbOriginal.setTextSize(i10);
                } else {
                    this.mCbOriginal.setTextSize(14.0f);
                }
                int i11 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureTextColor;
                if (i11 != 0) {
                    this.mCbOriginal.setTextColor(i11);
                } else {
                    this.mCbOriginal.setTextColor(Color.parseColor("#FFFFFF"));
                }
                int i12 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureCheckStyle;
                if (i12 != 0) {
                    this.mCbOriginal.setButtonDrawable(i12);
                } else {
                    this.mCbOriginal.setButtonDrawable(C3979R.drawable.picture_original_wechat_checkbox);
                }
            }
        } else {
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle != null) {
                int i13 = pictureParameterStyle.pictureCompleteBackgroundStyle;
                if (i13 != 0) {
                    this.mTvPictureRight.setBackgroundResource(i13);
                } else {
                    this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_bg);
                }
                int i14 = PictureSelectionConfig.style.pictureRightTextSize;
                if (i14 != 0) {
                    this.mTvPictureRight.setTextSize(i14);
                }
                if (!TextUtils.isEmpty(PictureSelectionConfig.style.pictureWeChatPreviewSelectedText)) {
                    this.mTvSelected.setText(PictureSelectionConfig.style.pictureWeChatPreviewSelectedText);
                }
                int i15 = PictureSelectionConfig.style.pictureWeChatPreviewSelectedTextSize;
                if (i15 != 0) {
                    this.mTvSelected.setTextSize(i15);
                }
                int i16 = PictureSelectionConfig.style.picturePreviewBottomBgColor;
                if (i16 != 0) {
                    this.selectBarLayout.setBackgroundColor(i16);
                } else {
                    this.selectBarLayout.setBackgroundColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_half_grey));
                }
                PictureParameterStyle pictureParameterStyle2 = PictureSelectionConfig.style;
                int i17 = pictureParameterStyle2.pictureCompleteTextColor;
                if (i17 != 0) {
                    this.mTvPictureRight.setTextColor(i17);
                } else {
                    int i18 = pictureParameterStyle2.pictureCancelTextColor;
                    if (i18 != 0) {
                        this.mTvPictureRight.setTextColor(i18);
                    } else {
                        this.mTvPictureRight.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_white));
                    }
                }
                if (PictureSelectionConfig.style.pictureOriginalFontColor == 0) {
                    this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_white));
                }
                int i19 = PictureSelectionConfig.style.pictureWeChatChooseStyle;
                if (i19 != 0) {
                    this.check.setBackgroundResource(i19);
                } else {
                    this.check.setBackgroundResource(C3979R.drawable.picture_wechat_select_cb);
                }
                if (this.config.isOriginalControl && PictureSelectionConfig.style.pictureOriginalControlStyle == 0) {
                    this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_wechat_checkbox));
                }
                int i20 = PictureSelectionConfig.style.pictureWeChatLeftBackStyle;
                if (i20 != 0) {
                    this.pictureLeftBack.setImageResource(i20);
                } else {
                    this.pictureLeftBack.setImageResource(C3979R.drawable.picture_icon_back);
                }
                if (!TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText)) {
                    this.mTvPictureRight.setText(PictureSelectionConfig.style.pictureUnCompleteText);
                }
            } else {
                this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_bg);
                TextView textView = this.mTvPictureRight;
                Context context = getContext();
                int i21 = C3979R.color.picture_color_white;
                textView.setTextColor(ContextCompat.getColor(context, i21));
                this.selectBarLayout.setBackgroundColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_half_grey));
                this.check.setBackgroundResource(C3979R.drawable.picture_wechat_select_cb);
                this.pictureLeftBack.setImageResource(C3979R.drawable.picture_icon_back);
                this.mCbOriginal.setTextColor(ContextCompat.getColor(this, i21));
                if (this.config.isOriginalControl) {
                    this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_wechat_checkbox));
                }
            }
        }
        onSelectNumChange(false);
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x00e6, code lost:
    
        r5 = true;
     */
    @Override // com.luck.picture.lib.PicturePreviewActivity, com.luck.picture.lib.PictureBaseActivity
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void initWidgets() {
        /*
            Method dump skipped, instructions count: 240
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.PictureSelectorPreviewWeChatStyleActivity.initWidgets():void");
    }

    @Override // com.luck.picture.lib.PicturePreviewActivity, android.view.View.OnClickListener
    public void onClick(View view) {
        super.onClick(view);
        if (view.getId() == C3979R.id.picture_right) {
            if (this.selectData.size() != 0) {
                this.mTvPictureOk.performClick();
                return;
            }
            this.btnCheck.performClick();
            if (this.selectData.size() != 0) {
                this.mTvPictureOk.performClick();
            }
        }
    }

    @Override // com.luck.picture.lib.PicturePreviewActivity
    public void onPageSelectedChange(LocalMedia localMedia) {
        super.onPageSelectedChange(localMedia);
        goneParent();
        if (this.config.previewEggs) {
            return;
        }
        onChangeMediaStatus(localMedia);
    }

    @Override // com.luck.picture.lib.PicturePreviewActivity
    public void onSelectNumChange(boolean z) {
        goneParent();
        List<LocalMedia> list = this.selectData;
        if (!((list == null || list.size() == 0) ? false : true)) {
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle == null || TextUtils.isEmpty(pictureParameterStyle.pictureUnCompleteText)) {
                this.mTvPictureRight.setText(getString(C3979R.string.picture_send));
            } else {
                this.mTvPictureRight.setText(PictureSelectionConfig.style.pictureUnCompleteText);
            }
            this.mRvGallery.animate().alpha(0.0f).setDuration(300L).setInterpolator(new AccelerateInterpolator());
            this.mRvGallery.setVisibility(8);
            this.bottomLine.animate().alpha(0.0f).setDuration(300L).setInterpolator(new AccelerateInterpolator());
            this.bottomLine.setVisibility(8);
            return;
        }
        initCompleteText(this.selectData.size());
        if (this.mRvGallery.getVisibility() == 8) {
            this.mRvGallery.animate().alpha(1.0f).setDuration(300L).setInterpolator(new AccelerateInterpolator());
            this.mRvGallery.setVisibility(0);
            this.bottomLine.animate().alpha(1.0f).setDuration(300L).setInterpolator(new AccelerateInterpolator());
            this.bottomLine.setVisibility(0);
            this.mGalleryAdapter.setNewData(this.selectData);
        }
        PictureParameterStyle pictureParameterStyle2 = PictureSelectionConfig.style;
        if (pictureParameterStyle2 == null) {
            this.mTvPictureRight.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_white));
            this.mTvPictureRight.setBackgroundResource(C3979R.drawable.picture_send_button_bg);
            return;
        }
        int i2 = pictureParameterStyle2.pictureCompleteTextColor;
        if (i2 != 0) {
            this.mTvPictureRight.setTextColor(i2);
        }
        int i3 = PictureSelectionConfig.style.pictureCompleteBackgroundStyle;
        if (i3 != 0) {
            this.mTvPictureRight.setBackgroundResource(i3);
        }
    }

    @Override // com.luck.picture.lib.PicturePreviewActivity
    public void onSelectedChange(boolean z, LocalMedia localMedia) {
        if (z) {
            localMedia.setChecked(true);
            if (this.config.selectionMode == 1) {
                this.mGalleryAdapter.addSingleMediaToData(localMedia);
            }
        } else {
            localMedia.setChecked(false);
            this.mGalleryAdapter.removeMediaToData(localMedia);
            if (this.isBottomPreview) {
                List<LocalMedia> list = this.selectData;
                if (list != null) {
                    int size = list.size();
                    int i2 = this.position;
                    if (size > i2) {
                        this.selectData.get(i2).setChecked(true);
                    }
                }
                if (this.mGalleryAdapter.isDataEmpty()) {
                    onActivityBackPressed();
                } else {
                    int currentItem = this.viewPager.getCurrentItem();
                    this.adapter.remove(currentItem);
                    this.adapter.removeCacheView(currentItem);
                    this.position = currentItem;
                    this.tvTitle.setText(getString(C3979R.string.picture_preview_image_num, new Object[]{Integer.valueOf(currentItem + 1), Integer.valueOf(this.adapter.getSize())}));
                    this.check.setSelected(true);
                    this.adapter.notifyDataSetChanged();
                }
            }
        }
        int itemCount = this.mGalleryAdapter.getItemCount();
        if (itemCount > 5) {
            this.mRvGallery.smoothScrollToPosition(itemCount - 1);
        }
    }

    @Override // com.luck.picture.lib.PicturePreviewActivity
    public void onUpdateSelectedChange(LocalMedia localMedia) {
        onChangeMediaStatus(localMedia);
    }
}
