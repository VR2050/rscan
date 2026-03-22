package com.luck.picture.lib;

import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import androidx.viewpager.widget.ViewPager;
import com.luck.picture.lib.PicturePreviewActivity;
import com.luck.picture.lib.adapter.PictureSimpleFragmentAdapter;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnQueryDataResultListener;
import com.luck.picture.lib.manager.UCropManager;
import com.luck.picture.lib.model.LocalMediaPageLoader;
import com.luck.picture.lib.observable.ImagesObservable;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.style.PictureSelectorUIStyle;
import com.luck.picture.lib.tools.AttrsUtils;
import com.luck.picture.lib.tools.MediaUtils;
import com.luck.picture.lib.tools.ScreenUtils;
import com.luck.picture.lib.tools.StringUtils;
import com.luck.picture.lib.tools.ToastUtils;
import com.luck.picture.lib.tools.ValueOf;
import com.luck.picture.lib.tools.VoiceUtils;
import com.luck.picture.lib.widget.PreviewViewPager;
import com.yalantis.ucrop.UCrop;
import com.yalantis.ucrop.model.CutInfo;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public class PicturePreviewActivity extends PictureBaseActivity implements View.OnClickListener, PictureSimpleFragmentAdapter.OnCallBackActivity {
    private static final String TAG = PicturePreviewActivity.class.getSimpleName();
    public PictureSimpleFragmentAdapter adapter;
    public Animation animation;
    public View btnCheck;
    public TextView check;
    public String currentDirectory;
    public int index;
    public boolean isBottomPreview;
    public boolean isChangeSelectedData;
    public boolean isCompleteOrSelected;
    public boolean isShowCamera;
    public CheckBox mCbOriginal;
    public Handler mHandler;
    public ImageView mIvArrow;
    public View mPicturePreview;
    public ViewGroup mTitleBar;
    public TextView mTvPictureOk;
    public TextView mTvPictureRight;
    public ImageView pictureLeftBack;
    public int position;
    public boolean refresh;
    public int screenWidth;
    public RelativeLayout selectBarLayout;
    private int totalNumber;
    public TextView tvMediaNum;
    public TextView tvTitle;
    public PreviewViewPager viewPager;
    public List<LocalMedia> selectData = new ArrayList();
    private int mPage = 0;

    private void bothMimeTypeWith(String str, LocalMedia localMedia) {
        if (!this.config.enableCrop) {
            onBackPressed();
            return;
        }
        this.isCompleteOrSelected = false;
        boolean isHasImage = PictureMimeType.isHasImage(str);
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.selectionMode == 1 && isHasImage) {
            pictureSelectionConfig.originalPath = localMedia.getPath();
            UCropManager.ofCrop(this, this.config.originalPath, localMedia.getMimeType());
            return;
        }
        ArrayList arrayList = new ArrayList();
        int size = this.selectData.size();
        int i2 = 0;
        for (int i3 = 0; i3 < size; i3++) {
            LocalMedia localMedia2 = this.selectData.get(i3);
            if (localMedia2 != null && !TextUtils.isEmpty(localMedia2.getPath())) {
                if (PictureMimeType.isHasImage(localMedia2.getMimeType())) {
                    i2++;
                }
                CutInfo cutInfo = new CutInfo();
                cutInfo.setId(localMedia2.getId());
                cutInfo.setPath(localMedia2.getPath());
                cutInfo.setImageWidth(localMedia2.getWidth());
                cutInfo.setImageHeight(localMedia2.getHeight());
                cutInfo.setMimeType(localMedia2.getMimeType());
                cutInfo.setAndroidQToPath(localMedia2.getAndroidQToPath());
                cutInfo.setId(localMedia2.getId());
                cutInfo.setDuration(localMedia2.getDuration());
                cutInfo.setRealPath(localMedia2.getRealPath());
                arrayList.add(cutInfo);
            }
        }
        if (i2 > 0) {
            UCropManager.ofCrop(this, arrayList);
        } else {
            this.isCompleteOrSelected = true;
            onBackPressed();
        }
    }

    private void initViewPageAdapterData(List<LocalMedia> list) {
        PictureSimpleFragmentAdapter pictureSimpleFragmentAdapter = new PictureSimpleFragmentAdapter(this.config, this);
        this.adapter = pictureSimpleFragmentAdapter;
        pictureSimpleFragmentAdapter.bindData(list);
        this.viewPager.setAdapter(this.adapter);
        this.viewPager.setCurrentItem(this.position);
        setTitle();
        onImageChecked(this.position);
        LocalMedia item = this.adapter.getItem(this.position);
        if (item != null) {
            this.index = item.getPosition();
            if (this.config.checkNumMode) {
                this.tvMediaNum.setSelected(true);
                this.check.setText(ValueOf.toString(Integer.valueOf(item.getNum())));
                notifyCheckChanged(item);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void isPreviewEggs(boolean z, int i2, int i3) {
        if (!z || this.adapter.getSize() <= 0) {
            return;
        }
        if (i3 < this.screenWidth / 2) {
            LocalMedia item = this.adapter.getItem(i2);
            if (item != null) {
                this.check.setSelected(isSelected(item));
                PictureSelectionConfig pictureSelectionConfig = this.config;
                if (pictureSelectionConfig.isWeChatStyle) {
                    onUpdateSelectedChange(item);
                    return;
                } else {
                    if (pictureSelectionConfig.checkNumMode) {
                        this.check.setText(ValueOf.toString(Integer.valueOf(item.getNum())));
                        notifyCheckChanged(item);
                        onImageChecked(i2);
                        return;
                    }
                    return;
                }
            }
            return;
        }
        int i4 = i2 + 1;
        LocalMedia item2 = this.adapter.getItem(i4);
        if (item2 != null) {
            this.check.setSelected(isSelected(item2));
            PictureSelectionConfig pictureSelectionConfig2 = this.config;
            if (pictureSelectionConfig2.isWeChatStyle) {
                onUpdateSelectedChange(item2);
            } else if (pictureSelectionConfig2.checkNumMode) {
                this.check.setText(ValueOf.toString(Integer.valueOf(item2.getNum())));
                notifyCheckChanged(item2);
                onImageChecked(i4);
            }
        }
    }

    private void loadData() {
        long longExtra = getIntent().getLongExtra(PictureConfig.EXTRA_BUCKET_ID, -1L);
        this.mPage++;
        LocalMediaPageLoader.getInstance(getContext()).loadPageMediaData(longExtra, this.mPage, this.config.pageSize, new OnQueryDataResultListener() { // from class: b.t.a.a.s
            @Override // com.luck.picture.lib.listener.OnQueryDataResultListener
            public final void onComplete(List list, int i2, boolean z) {
                PicturePreviewActivity.this.m4525a(list, i2, z);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadMoreData() {
        long longExtra = getIntent().getLongExtra(PictureConfig.EXTRA_BUCKET_ID, -1L);
        this.mPage++;
        LocalMediaPageLoader.getInstance(getContext()).loadPageMediaData(longExtra, this.mPage, this.config.pageSize, new OnQueryDataResultListener() { // from class: b.t.a.a.q
            @Override // com.luck.picture.lib.listener.OnQueryDataResultListener
            public final void onComplete(List list, int i2, boolean z) {
                PicturePreviewActivity.this.m4526b(list, i2, z);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyCheckChanged(LocalMedia localMedia) {
        if (this.config.checkNumMode) {
            this.check.setText("");
            int size = this.selectData.size();
            for (int i2 = 0; i2 < size; i2++) {
                LocalMedia localMedia2 = this.selectData.get(i2);
                if (localMedia2.getPath().equals(localMedia.getPath()) || localMedia2.getId() == localMedia.getId()) {
                    localMedia.setNum(localMedia2.getNum());
                    this.check.setText(String.valueOf(localMedia.getNum()));
                }
            }
        }
    }

    private void separateMimeTypeWith(String str, LocalMedia localMedia) {
        if (!this.config.enableCrop || !PictureMimeType.isHasImage(str)) {
            onBackPressed();
            return;
        }
        this.isCompleteOrSelected = false;
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.selectionMode == 1) {
            pictureSelectionConfig.originalPath = localMedia.getPath();
            UCropManager.ofCrop(this, this.config.originalPath, localMedia.getMimeType());
            return;
        }
        ArrayList arrayList = new ArrayList();
        int size = this.selectData.size();
        for (int i2 = 0; i2 < size; i2++) {
            LocalMedia localMedia2 = this.selectData.get(i2);
            if (localMedia2 != null && !TextUtils.isEmpty(localMedia2.getPath())) {
                CutInfo cutInfo = new CutInfo();
                cutInfo.setId(localMedia2.getId());
                cutInfo.setPath(localMedia2.getPath());
                cutInfo.setImageWidth(localMedia2.getWidth());
                cutInfo.setImageHeight(localMedia2.getHeight());
                cutInfo.setMimeType(localMedia2.getMimeType());
                cutInfo.setAndroidQToPath(localMedia2.getAndroidQToPath());
                cutInfo.setId(localMedia2.getId());
                cutInfo.setDuration(localMedia2.getDuration());
                cutInfo.setRealPath(localMedia2.getRealPath());
                arrayList.add(cutInfo);
            }
        }
        UCropManager.ofCrop(this, arrayList);
    }

    private void setNewTitle() {
        this.mPage = 0;
        this.position = 0;
        setTitle();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setTitle() {
        if (!this.config.isPageStrategy || this.isBottomPreview) {
            this.tvTitle.setText(getString(C3979R.string.picture_preview_image_num, new Object[]{Integer.valueOf(this.position + 1), Integer.valueOf(this.adapter.getSize())}));
        } else {
            this.tvTitle.setText(getString(C3979R.string.picture_preview_image_num, new Object[]{Integer.valueOf(this.position + 1), Integer.valueOf(this.totalNumber)}));
        }
    }

    private void subSelectPosition() {
        int size = this.selectData.size();
        int i2 = 0;
        while (i2 < size) {
            LocalMedia localMedia = this.selectData.get(i2);
            i2++;
            localMedia.setNum(i2);
        }
    }

    private void updateResult() {
        Intent intent = new Intent();
        if (this.isChangeSelectedData) {
            intent.putExtra(PictureConfig.EXTRA_COMPLETE_SELECTED, this.isCompleteOrSelected);
            intent.putParcelableArrayListExtra(PictureConfig.EXTRA_SELECT_LIST, (ArrayList) this.selectData);
        }
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.isOriginalControl) {
            intent.putExtra(PictureConfig.EXTRA_CHANGE_ORIGINAL, pictureSelectionConfig.isCheckOriginalImage);
        }
        setResult(0, intent);
    }

    /* renamed from: a */
    public /* synthetic */ void m4525a(List list, int i2, boolean z) {
        PictureSimpleFragmentAdapter pictureSimpleFragmentAdapter;
        if (isFinishing()) {
            return;
        }
        this.isHasMore = z;
        if (z) {
            if (list.size() <= 0 || (pictureSimpleFragmentAdapter = this.adapter) == null) {
                loadMoreData();
            } else {
                pictureSimpleFragmentAdapter.getData().addAll(list);
                this.adapter.notifyDataSetChanged();
            }
        }
    }

    /* renamed from: b */
    public /* synthetic */ void m4526b(List list, int i2, boolean z) {
        PictureSimpleFragmentAdapter pictureSimpleFragmentAdapter;
        if (isFinishing()) {
            return;
        }
        this.isHasMore = z;
        if (z) {
            if (list.size() <= 0 || (pictureSimpleFragmentAdapter = this.adapter) == null) {
                loadMoreData();
            } else {
                pictureSimpleFragmentAdapter.getData().addAll(list);
                this.adapter.notifyDataSetChanged();
            }
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public int getResourceId() {
        return C3979R.layout.picture_preview;
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initCompleteText(int i2) {
        if (this.config.selectionMode == 1) {
            if (i2 <= 0) {
                PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
                if (pictureSelectorUIStyle != null) {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(pictureSelectorUIStyle.picture_bottom_completeDefaultText) ? PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText : getString(C3979R.string.picture_please_select));
                    return;
                }
                PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
                if (pictureParameterStyle != null) {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(pictureParameterStyle.pictureUnCompleteText) ? PictureSelectionConfig.style.pictureUnCompleteText : getString(C3979R.string.picture_please_select));
                    return;
                }
                return;
            }
            PictureSelectorUIStyle pictureSelectorUIStyle2 = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle2 != null) {
                if (!pictureSelectorUIStyle2.isCompleteReplaceNum || TextUtils.isEmpty(pictureSelectorUIStyle2.picture_bottom_completeNormalText)) {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_bottom_completeNormalText) ? PictureSelectionConfig.uiStyle.picture_bottom_completeNormalText : getString(C3979R.string.picture_done));
                    return;
                } else {
                    this.mTvPictureOk.setText(String.format(PictureSelectionConfig.uiStyle.picture_bottom_completeNormalText, Integer.valueOf(i2), 1));
                    return;
                }
            }
            PictureParameterStyle pictureParameterStyle2 = PictureSelectionConfig.style;
            if (pictureParameterStyle2 != null) {
                if (!pictureParameterStyle2.isCompleteReplaceNum || TextUtils.isEmpty(pictureParameterStyle2.pictureCompleteText)) {
                    this.mTvPictureOk.setText(!TextUtils.isEmpty(PictureSelectionConfig.style.pictureCompleteText) ? PictureSelectionConfig.style.pictureCompleteText : getString(C3979R.string.picture_done));
                    return;
                } else {
                    this.mTvPictureOk.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(i2), 1));
                    return;
                }
            }
            return;
        }
        if (i2 <= 0) {
            PictureSelectorUIStyle pictureSelectorUIStyle3 = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle3 != null) {
                this.mTvPictureOk.setText((!pictureSelectorUIStyle3.isCompleteReplaceNum || TextUtils.isEmpty(pictureSelectorUIStyle3.picture_bottom_completeDefaultText)) ? getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}) : String.format(PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText, Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)));
                return;
            }
            PictureParameterStyle pictureParameterStyle3 = PictureSelectionConfig.style;
            if (pictureParameterStyle3 != null) {
                this.mTvPictureOk.setText((!pictureParameterStyle3.isCompleteReplaceNum || TextUtils.isEmpty(pictureParameterStyle3.pictureUnCompleteText)) ? getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}) : PictureSelectionConfig.style.pictureUnCompleteText);
                return;
            }
            return;
        }
        PictureSelectorUIStyle pictureSelectorUIStyle4 = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle4 != null) {
            if (!pictureSelectorUIStyle4.isCompleteReplaceNum || TextUtils.isEmpty(pictureSelectorUIStyle4.picture_bottom_completeNormalText)) {
                this.mTvPictureOk.setText(getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}));
                return;
            } else {
                this.mTvPictureOk.setText(String.format(PictureSelectionConfig.uiStyle.picture_bottom_completeNormalText, Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)));
                return;
            }
        }
        PictureParameterStyle pictureParameterStyle4 = PictureSelectionConfig.style;
        if (pictureParameterStyle4 != null) {
            if (!pictureParameterStyle4.isCompleteReplaceNum || TextUtils.isEmpty(pictureParameterStyle4.pictureCompleteText)) {
                this.mTvPictureOk.setText(getString(C3979R.string.picture_done_front_num, new Object[]{Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)}));
            } else {
                this.mTvPictureOk.setText(String.format(PictureSelectionConfig.style.pictureCompleteText, Integer.valueOf(i2), Integer.valueOf(this.config.maxSelectNum)));
            }
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initPictureSelectorStyle() {
        ColorStateList colorStateList;
        PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle != null) {
            int i2 = pictureSelectorUIStyle.picture_top_titleTextColor;
            if (i2 != 0) {
                this.tvTitle.setTextColor(i2);
            }
            int i3 = PictureSelectionConfig.uiStyle.picture_top_titleTextSize;
            if (i3 != 0) {
                this.tvTitle.setTextSize(i3);
            }
            int i4 = PictureSelectionConfig.uiStyle.picture_top_leftBack;
            if (i4 != 0) {
                this.pictureLeftBack.setImageResource(i4);
            }
            int i5 = PictureSelectionConfig.uiStyle.picture_bottom_barBackgroundColor;
            if (i5 != 0) {
                this.selectBarLayout.setBackgroundColor(i5);
            }
            int i6 = PictureSelectionConfig.uiStyle.picture_bottom_completeRedDotBackground;
            if (i6 != 0) {
                this.tvMediaNum.setBackgroundResource(i6);
            }
            int i7 = PictureSelectionConfig.uiStyle.picture_check_style;
            if (i7 != 0) {
                this.check.setBackgroundResource(i7);
            }
            int[] iArr = PictureSelectionConfig.uiStyle.picture_bottom_completeTextColor;
            if (iArr.length > 0 && (colorStateList = AttrsUtils.getColorStateList(iArr)) != null) {
                this.mTvPictureOk.setTextColor(colorStateList);
            }
            if (!TextUtils.isEmpty(PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText)) {
                this.mTvPictureOk.setText(PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText);
            }
            if (PictureSelectionConfig.uiStyle.picture_top_titleBarHeight > 0) {
                this.mTitleBar.getLayoutParams().height = PictureSelectionConfig.uiStyle.picture_top_titleBarHeight;
            }
            if (PictureSelectionConfig.uiStyle.picture_bottom_barHeight > 0) {
                this.selectBarLayout.getLayoutParams().height = PictureSelectionConfig.uiStyle.picture_bottom_barHeight;
            }
            if (this.config.isOriginalControl) {
                int i8 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureCheckStyle;
                if (i8 != 0) {
                    this.mCbOriginal.setButtonDrawable(i8);
                } else {
                    this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_checkbox));
                }
                int i9 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureTextColor;
                if (i9 != 0) {
                    this.mCbOriginal.setTextColor(i9);
                } else {
                    this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_53575e));
                }
                int i10 = PictureSelectionConfig.uiStyle.picture_bottom_originalPictureTextSize;
                if (i10 != 0) {
                    this.mCbOriginal.setTextSize(i10);
                }
            } else {
                this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_checkbox));
                this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_53575e));
            }
        } else {
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle != null) {
                int i11 = pictureParameterStyle.pictureTitleTextColor;
                if (i11 != 0) {
                    this.tvTitle.setTextColor(i11);
                }
                int i12 = PictureSelectionConfig.style.pictureTitleTextSize;
                if (i12 != 0) {
                    this.tvTitle.setTextSize(i12);
                }
                int i13 = PictureSelectionConfig.style.pictureLeftBackIcon;
                if (i13 != 0) {
                    this.pictureLeftBack.setImageResource(i13);
                }
                int i14 = PictureSelectionConfig.style.picturePreviewBottomBgColor;
                if (i14 != 0) {
                    this.selectBarLayout.setBackgroundColor(i14);
                }
                int i15 = PictureSelectionConfig.style.pictureCheckNumBgStyle;
                if (i15 != 0) {
                    this.tvMediaNum.setBackgroundResource(i15);
                }
                int i16 = PictureSelectionConfig.style.pictureCheckedStyle;
                if (i16 != 0) {
                    this.check.setBackgroundResource(i16);
                }
                int i17 = PictureSelectionConfig.style.pictureUnCompleteTextColor;
                if (i17 != 0) {
                    this.mTvPictureOk.setTextColor(i17);
                }
                if (!TextUtils.isEmpty(PictureSelectionConfig.style.pictureUnCompleteText)) {
                    this.mTvPictureOk.setText(PictureSelectionConfig.style.pictureUnCompleteText);
                }
                if (PictureSelectionConfig.style.pictureTitleBarHeight > 0) {
                    this.mTitleBar.getLayoutParams().height = PictureSelectionConfig.style.pictureTitleBarHeight;
                }
                if (this.config.isOriginalControl) {
                    int i18 = PictureSelectionConfig.style.pictureOriginalControlStyle;
                    if (i18 != 0) {
                        this.mCbOriginal.setButtonDrawable(i18);
                    } else {
                        this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_checkbox));
                    }
                    int i19 = PictureSelectionConfig.style.pictureOriginalFontColor;
                    if (i19 != 0) {
                        this.mCbOriginal.setTextColor(i19);
                    } else {
                        this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_53575e));
                    }
                    int i20 = PictureSelectionConfig.style.pictureOriginalTextSize;
                    if (i20 != 0) {
                        this.mCbOriginal.setTextSize(i20);
                    }
                } else {
                    this.mCbOriginal.setButtonDrawable(ContextCompat.getDrawable(this, C3979R.drawable.picture_original_checkbox));
                    this.mCbOriginal.setTextColor(ContextCompat.getColor(this, C3979R.color.picture_color_53575e));
                }
            } else {
                this.check.setBackground(AttrsUtils.getTypeValueDrawable(getContext(), C3979R.attr.picture_checked_style, C3979R.drawable.picture_checkbox_selector));
                ColorStateList typeValueColorStateList = AttrsUtils.getTypeValueColorStateList(getContext(), C3979R.attr.picture_ac_preview_complete_textColor);
                if (typeValueColorStateList != null) {
                    this.mTvPictureOk.setTextColor(typeValueColorStateList);
                }
                this.pictureLeftBack.setImageDrawable(AttrsUtils.getTypeValueDrawable(getContext(), C3979R.attr.picture_preview_leftBack_icon, C3979R.drawable.picture_icon_back));
                this.tvMediaNum.setBackground(AttrsUtils.getTypeValueDrawable(getContext(), C3979R.attr.picture_num_style, C3979R.drawable.picture_num_oval));
                int typeValueColor = AttrsUtils.getTypeValueColor(getContext(), C3979R.attr.picture_ac_preview_bottom_bg);
                if (typeValueColor != 0) {
                    this.selectBarLayout.setBackgroundColor(typeValueColor);
                }
                int typeValueSizeForInt = AttrsUtils.getTypeValueSizeForInt(getContext(), C3979R.attr.picture_titleBar_height);
                if (typeValueSizeForInt > 0) {
                    this.mTitleBar.getLayoutParams().height = typeValueSizeForInt;
                }
                if (this.config.isOriginalControl) {
                    this.mCbOriginal.setButtonDrawable(AttrsUtils.getTypeValueDrawable(getContext(), C3979R.attr.picture_original_check_style, C3979R.drawable.picture_original_wechat_checkbox));
                    int typeValueColor2 = AttrsUtils.getTypeValueColor(getContext(), C3979R.attr.picture_original_text_color);
                    if (typeValueColor2 != 0) {
                        this.mCbOriginal.setTextColor(typeValueColor2);
                    }
                }
            }
        }
        this.mTitleBar.setBackgroundColor(this.colorPrimary);
        onSelectNumChange(false);
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initWidgets() {
        super.initWidgets();
        this.mHandler = new Handler();
        this.mTitleBar = (ViewGroup) findViewById(C3979R.id.titleBar);
        this.screenWidth = ScreenUtils.getScreenWidth(this);
        this.animation = AnimationUtils.loadAnimation(this, C3979R.anim.picture_anim_modal_in);
        this.pictureLeftBack = (ImageView) findViewById(C3979R.id.pictureLeftBack);
        this.mTvPictureRight = (TextView) findViewById(C3979R.id.picture_right);
        this.mIvArrow = (ImageView) findViewById(C3979R.id.ivArrow);
        this.viewPager = (PreviewViewPager) findViewById(C3979R.id.preview_pager);
        this.mPicturePreview = findViewById(C3979R.id.picture_id_preview);
        this.btnCheck = findViewById(C3979R.id.btnCheck);
        this.check = (TextView) findViewById(C3979R.id.check);
        this.pictureLeftBack.setOnClickListener(this);
        this.mTvPictureOk = (TextView) findViewById(C3979R.id.picture_tv_ok);
        this.mCbOriginal = (CheckBox) findViewById(C3979R.id.cb_original);
        this.tvMediaNum = (TextView) findViewById(C3979R.id.tv_media_num);
        this.selectBarLayout = (RelativeLayout) findViewById(C3979R.id.select_bar_layout);
        this.mTvPictureOk.setOnClickListener(this);
        this.tvMediaNum.setOnClickListener(this);
        this.tvTitle = (TextView) findViewById(C3979R.id.picture_title);
        this.mPicturePreview.setVisibility(8);
        this.mIvArrow.setVisibility(8);
        this.mTvPictureRight.setVisibility(8);
        this.check.setVisibility(0);
        this.btnCheck.setVisibility(0);
        this.position = getIntent().getIntExtra("position", 0);
        if (this.numComplete) {
            initCompleteText(0);
        }
        this.tvMediaNum.setSelected(this.config.checkNumMode);
        this.btnCheck.setOnClickListener(this);
        if (getIntent().getParcelableArrayListExtra(PictureConfig.EXTRA_SELECT_LIST) != null) {
            this.selectData = getIntent().getParcelableArrayListExtra(PictureConfig.EXTRA_SELECT_LIST);
        }
        this.isBottomPreview = getIntent().getBooleanExtra(PictureConfig.EXTRA_BOTTOM_PREVIEW, false);
        this.isShowCamera = getIntent().getBooleanExtra(PictureConfig.EXTRA_SHOW_CAMERA, this.config.isCamera);
        this.currentDirectory = getIntent().getStringExtra(PictureConfig.EXTRA_IS_CURRENT_DIRECTORY);
        if (this.isBottomPreview) {
            initViewPageAdapterData(getIntent().getParcelableArrayListExtra(PictureConfig.EXTRA_PREVIEW_SELECT_LIST));
        } else {
            ArrayList arrayList = new ArrayList(ImagesObservable.getInstance().readPreviewMediaData());
            boolean z = arrayList.size() == 0;
            this.totalNumber = getIntent().getIntExtra(PictureConfig.EXTRA_DATA_COUNT, 0);
            if (this.config.isPageStrategy) {
                if (z) {
                    setNewTitle();
                } else {
                    this.mPage = getIntent().getIntExtra("page", 0);
                }
                initViewPageAdapterData(arrayList);
                loadData();
                setTitle();
            } else {
                initViewPageAdapterData(arrayList);
                if (z) {
                    this.config.isPageStrategy = true;
                    setNewTitle();
                    loadData();
                }
            }
        }
        this.viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.luck.picture.lib.PicturePreviewActivity.1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int i2) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int i2, float f2, int i3) {
                PicturePreviewActivity picturePreviewActivity = PicturePreviewActivity.this;
                picturePreviewActivity.isPreviewEggs(picturePreviewActivity.config.previewEggs, i2, i3);
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int i2) {
                PicturePreviewActivity picturePreviewActivity = PicturePreviewActivity.this;
                picturePreviewActivity.position = i2;
                picturePreviewActivity.setTitle();
                PicturePreviewActivity picturePreviewActivity2 = PicturePreviewActivity.this;
                LocalMedia item = picturePreviewActivity2.adapter.getItem(picturePreviewActivity2.position);
                if (item == null) {
                    return;
                }
                PicturePreviewActivity.this.index = item.getPosition();
                PicturePreviewActivity picturePreviewActivity3 = PicturePreviewActivity.this;
                PictureSelectionConfig pictureSelectionConfig = picturePreviewActivity3.config;
                if (!pictureSelectionConfig.previewEggs) {
                    if (pictureSelectionConfig.checkNumMode) {
                        picturePreviewActivity3.check.setText(ValueOf.toString(Integer.valueOf(item.getNum())));
                        PicturePreviewActivity.this.notifyCheckChanged(item);
                    }
                    PicturePreviewActivity picturePreviewActivity4 = PicturePreviewActivity.this;
                    picturePreviewActivity4.onImageChecked(picturePreviewActivity4.position);
                }
                if (PicturePreviewActivity.this.config.isOriginalControl) {
                    PicturePreviewActivity.this.mCbOriginal.setVisibility(PictureMimeType.isHasVideo(item.getMimeType()) ? 8 : 0);
                    PicturePreviewActivity picturePreviewActivity5 = PicturePreviewActivity.this;
                    picturePreviewActivity5.mCbOriginal.setChecked(picturePreviewActivity5.config.isCheckOriginalImage);
                }
                PicturePreviewActivity.this.onPageSelectedChange(item);
                PicturePreviewActivity picturePreviewActivity6 = PicturePreviewActivity.this;
                if (picturePreviewActivity6.config.isPageStrategy && !picturePreviewActivity6.isBottomPreview && picturePreviewActivity6.isHasMore) {
                    if (picturePreviewActivity6.position != (picturePreviewActivity6.adapter.getSize() - 1) - 10) {
                        if (PicturePreviewActivity.this.position != r4.adapter.getSize() - 1) {
                            return;
                        }
                    }
                    PicturePreviewActivity.this.loadMoreData();
                }
            }
        });
        if (this.config.isOriginalControl) {
            boolean booleanExtra = getIntent().getBooleanExtra(PictureConfig.EXTRA_CHANGE_ORIGINAL, this.config.isCheckOriginalImage);
            this.mCbOriginal.setVisibility(0);
            this.config.isCheckOriginalImage = booleanExtra;
            this.mCbOriginal.setChecked(booleanExtra);
            this.mCbOriginal.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: b.t.a.a.r
                @Override // android.widget.CompoundButton.OnCheckedChangeListener
                public final void onCheckedChanged(CompoundButton compoundButton, boolean z2) {
                    PicturePreviewActivity.this.config.isCheckOriginalImage = z2;
                }
            });
        }
    }

    public boolean isSelected(LocalMedia localMedia) {
        int size = this.selectData.size();
        for (int i2 = 0; i2 < size; i2++) {
            LocalMedia localMedia2 = this.selectData.get(i2);
            if (localMedia2.getPath().equals(localMedia.getPath()) || localMedia2.getId() == localMedia.getId()) {
                return true;
            }
        }
        return false;
    }

    @Override // com.luck.picture.lib.adapter.PictureSimpleFragmentAdapter.OnCallBackActivity
    public void onActivityBackPressed() {
        onBackPressed();
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onActivityResult(int i2, int i3, Intent intent) {
        Throwable th;
        super.onActivityResult(i2, i3, intent);
        if (i3 != -1) {
            if (i3 != 96 || (th = (Throwable) intent.getSerializableExtra(UCrop.EXTRA_ERROR)) == null) {
                return;
            }
            ToastUtils.m4555s(getContext(), th.getMessage());
            return;
        }
        if (i2 == 69) {
            if (intent != null) {
                intent.putParcelableArrayListExtra(PictureConfig.EXTRA_SELECT_LIST, (ArrayList) this.selectData);
                setResult(-1, intent);
            }
            finish();
            return;
        }
        if (i2 != 609) {
            return;
        }
        intent.putParcelableArrayListExtra(UCrop.Options.EXTRA_OUTPUT_URI_LIST, (ArrayList) UCrop.getMultipleOutput(intent));
        intent.putParcelableArrayListExtra(PictureConfig.EXTRA_SELECT_LIST, (ArrayList) this.selectData);
        setResult(-1, intent);
        finish();
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        updateResult();
        finish();
        overridePendingTransition(0, PictureSelectionConfig.windowAnimationStyle.activityPreviewExitAnimation);
    }

    public void onCheckedComplete() {
        int i2;
        boolean z;
        if (this.adapter.getSize() > 0) {
            LocalMedia item = this.adapter.getItem(this.viewPager.getCurrentItem());
            String realPath = item.getRealPath();
            if (!TextUtils.isEmpty(realPath) && !new File(realPath).exists()) {
                ToastUtils.m4555s(getContext(), PictureMimeType.m4554s(getContext(), item.getMimeType()));
                return;
            }
            String mimeType = this.selectData.size() > 0 ? this.selectData.get(0).getMimeType() : "";
            int size = this.selectData.size();
            if (this.config.isWithVideoImage) {
                int i3 = 0;
                for (int i4 = 0; i4 < size; i4++) {
                    if (PictureMimeType.isHasVideo(this.selectData.get(i4).getMimeType())) {
                        i3++;
                    }
                }
                if (PictureMimeType.isHasVideo(item.getMimeType())) {
                    PictureSelectionConfig pictureSelectionConfig = this.config;
                    if (pictureSelectionConfig.maxVideoSelectNum <= 0) {
                        showPromptDialog(getString(C3979R.string.picture_rule));
                        return;
                    }
                    if (size >= pictureSelectionConfig.maxSelectNum && !this.check.isSelected()) {
                        showPromptDialog(getString(C3979R.string.picture_message_max_num, new Object[]{Integer.valueOf(this.config.maxSelectNum)}));
                        return;
                    }
                    if (i3 >= this.config.maxVideoSelectNum && !this.check.isSelected()) {
                        showPromptDialog(StringUtils.getMsg(getContext(), item.getMimeType(), this.config.maxVideoSelectNum));
                        return;
                    }
                    if (!this.check.isSelected() && this.config.videoMinSecond > 0 && item.getDuration() < this.config.videoMinSecond) {
                        showPromptDialog(getContext().getString(C3979R.string.picture_choose_min_seconds, Integer.valueOf(this.config.videoMinSecond / 1000)));
                        return;
                    } else if (!this.check.isSelected() && this.config.videoMaxSecond > 0 && item.getDuration() > this.config.videoMaxSecond) {
                        showPromptDialog(getContext().getString(C3979R.string.picture_choose_max_seconds, Integer.valueOf(this.config.videoMaxSecond / 1000)));
                        return;
                    }
                } else if (size >= this.config.maxSelectNum && !this.check.isSelected()) {
                    showPromptDialog(getString(C3979R.string.picture_message_max_num, new Object[]{Integer.valueOf(this.config.maxSelectNum)}));
                    return;
                }
            } else {
                if (!TextUtils.isEmpty(mimeType) && !PictureMimeType.isMimeTypeSame(mimeType, item.getMimeType())) {
                    showPromptDialog(getString(C3979R.string.picture_rule));
                    return;
                }
                if (!PictureMimeType.isHasVideo(mimeType) || (i2 = this.config.maxVideoSelectNum) <= 0) {
                    if (size >= this.config.maxSelectNum && !this.check.isSelected()) {
                        showPromptDialog(StringUtils.getMsg(getContext(), mimeType, this.config.maxSelectNum));
                        return;
                    }
                    if (PictureMimeType.isHasVideo(item.getMimeType())) {
                        if (!this.check.isSelected() && this.config.videoMinSecond > 0 && item.getDuration() < this.config.videoMinSecond) {
                            showPromptDialog(getContext().getString(C3979R.string.picture_choose_min_seconds, Integer.valueOf(this.config.videoMinSecond / 1000)));
                            return;
                        } else if (!this.check.isSelected() && this.config.videoMaxSecond > 0 && item.getDuration() > this.config.videoMaxSecond) {
                            showPromptDialog(getContext().getString(C3979R.string.picture_choose_max_seconds, Integer.valueOf(this.config.videoMaxSecond / 1000)));
                            return;
                        }
                    }
                } else {
                    if (size >= i2 && !this.check.isSelected()) {
                        showPromptDialog(StringUtils.getMsg(getContext(), mimeType, this.config.maxVideoSelectNum));
                        return;
                    }
                    if (!this.check.isSelected() && this.config.videoMinSecond > 0 && item.getDuration() < this.config.videoMinSecond) {
                        showPromptDialog(getContext().getString(C3979R.string.picture_choose_min_seconds, Integer.valueOf(this.config.videoMinSecond / 1000)));
                        return;
                    } else if (!this.check.isSelected() && this.config.videoMaxSecond > 0 && item.getDuration() > this.config.videoMaxSecond) {
                        showPromptDialog(getContext().getString(C3979R.string.picture_choose_max_seconds, Integer.valueOf(this.config.videoMaxSecond / 1000)));
                        return;
                    }
                }
            }
            if (this.check.isSelected()) {
                this.check.setSelected(false);
                z = false;
            } else {
                this.check.setSelected(true);
                this.check.startAnimation(this.animation);
                z = true;
            }
            this.isChangeSelectedData = true;
            if (z) {
                VoiceUtils.getInstance().play();
                if (this.config.selectionMode == 1) {
                    this.selectData.clear();
                }
                if (item.getWidth() == 0 || item.getHeight() == 0) {
                    item.setOrientation(-1);
                    if (PictureMimeType.isContent(item.getPath())) {
                        if (PictureMimeType.isHasVideo(item.getMimeType())) {
                            MediaUtils.getVideoSizeForUri(getContext(), Uri.parse(item.getPath()), item);
                        } else if (PictureMimeType.isHasImage(item.getMimeType())) {
                            int[] imageSizeForUri = MediaUtils.getImageSizeForUri(getContext(), Uri.parse(item.getPath()));
                            item.setWidth(imageSizeForUri[0]);
                            item.setHeight(imageSizeForUri[1]);
                        }
                    } else if (PictureMimeType.isHasVideo(item.getMimeType())) {
                        int[] videoSizeForUrl = MediaUtils.getVideoSizeForUrl(item.getPath());
                        item.setWidth(videoSizeForUrl[0]);
                        item.setHeight(videoSizeForUrl[1]);
                    } else if (PictureMimeType.isHasImage(item.getMimeType())) {
                        int[] imageSizeForUrl = MediaUtils.getImageSizeForUrl(item.getPath());
                        item.setWidth(imageSizeForUrl[0]);
                        item.setHeight(imageSizeForUrl[1]);
                    }
                }
                Context context = getContext();
                PictureSelectionConfig pictureSelectionConfig2 = this.config;
                MediaUtils.setOrientationAsynchronous(context, item, pictureSelectionConfig2.isAndroidQChangeWH, pictureSelectionConfig2.isAndroidQChangeVideoWH, null);
                this.selectData.add(item);
                onSelectedChange(true, item);
                item.setNum(this.selectData.size());
                if (this.config.checkNumMode) {
                    this.check.setText(String.valueOf(item.getNum()));
                }
            } else {
                int size2 = this.selectData.size();
                for (int i5 = 0; i5 < size2; i5++) {
                    LocalMedia localMedia = this.selectData.get(i5);
                    if (localMedia.getPath().equals(item.getPath()) || localMedia.getId() == item.getId()) {
                        this.selectData.remove(localMedia);
                        onSelectedChange(false, item);
                        subSelectPosition();
                        notifyCheckChanged(localMedia);
                        break;
                    }
                }
            }
            onSelectNumChange(true);
        }
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        int id = view.getId();
        if (id == C3979R.id.pictureLeftBack) {
            onBackPressed();
            return;
        }
        if (id == C3979R.id.picture_tv_ok || id == C3979R.id.tv_media_num) {
            onComplete();
        } else if (id == C3979R.id.btnCheck) {
            onCheckedComplete();
        }
    }

    public void onComplete() {
        int i2;
        int i3;
        int size = this.selectData.size();
        LocalMedia localMedia = this.selectData.size() > 0 ? this.selectData.get(0) : null;
        String mimeType = localMedia != null ? localMedia.getMimeType() : "";
        PictureSelectionConfig pictureSelectionConfig = this.config;
        if (pictureSelectionConfig.isWithVideoImage) {
            int size2 = this.selectData.size();
            int i4 = 0;
            int i5 = 0;
            for (int i6 = 0; i6 < size2; i6++) {
                if (PictureMimeType.isHasVideo(this.selectData.get(i6).getMimeType())) {
                    i5++;
                } else {
                    i4++;
                }
            }
            PictureSelectionConfig pictureSelectionConfig2 = this.config;
            if (pictureSelectionConfig2.selectionMode == 2) {
                int i7 = pictureSelectionConfig2.minSelectNum;
                if (i7 > 0 && i4 < i7) {
                    showPromptDialog(getString(C3979R.string.picture_min_img_num, new Object[]{Integer.valueOf(i7)}));
                    return;
                }
                int i8 = pictureSelectionConfig2.minVideoSelectNum;
                if (i8 > 0 && i5 < i8) {
                    showPromptDialog(getString(C3979R.string.picture_min_video_num, new Object[]{Integer.valueOf(i8)}));
                    return;
                }
            }
        } else if (pictureSelectionConfig.selectionMode == 2) {
            if (PictureMimeType.isHasImage(mimeType) && (i3 = this.config.minSelectNum) > 0 && size < i3) {
                showPromptDialog(getString(C3979R.string.picture_min_img_num, new Object[]{Integer.valueOf(i3)}));
                return;
            } else if (PictureMimeType.isHasVideo(mimeType) && (i2 = this.config.minVideoSelectNum) > 0 && size < i2) {
                showPromptDialog(getString(C3979R.string.picture_min_video_num, new Object[]{Integer.valueOf(i2)}));
                return;
            }
        }
        this.isCompleteOrSelected = true;
        this.isChangeSelectedData = true;
        PictureSelectionConfig pictureSelectionConfig3 = this.config;
        if (pictureSelectionConfig3.isCheckOriginalImage) {
            onBackPressed();
        } else if (pictureSelectionConfig3.chooseMode == PictureMimeType.ofAll() && this.config.isWithVideoImage) {
            bothMimeTypeWith(mimeType, localMedia);
        } else {
            separateMimeTypeWith(mimeType, localMedia);
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (bundle != null) {
            List<LocalMedia> obtainSelectorList = PictureSelector.obtainSelectorList(bundle);
            if (obtainSelectorList == null) {
                obtainSelectorList = this.selectData;
            }
            this.selectData = obtainSelectorList;
            this.isCompleteOrSelected = bundle.getBoolean(PictureConfig.EXTRA_COMPLETE_SELECTED, false);
            this.isChangeSelectedData = bundle.getBoolean(PictureConfig.EXTRA_CHANGE_SELECTED_DATA, false);
            onImageChecked(this.position);
            onSelectNumChange(false);
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        if (!this.isOnSaveInstanceState) {
            ImagesObservable.getInstance().clearPreviewMediaData();
        }
        Handler handler = this.mHandler;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
            this.mHandler = null;
        }
        Animation animation = this.animation;
        if (animation != null) {
            animation.cancel();
            this.animation = null;
        }
        PictureSimpleFragmentAdapter pictureSimpleFragmentAdapter = this.adapter;
        if (pictureSimpleFragmentAdapter != null) {
            pictureSimpleFragmentAdapter.clear();
        }
    }

    public void onImageChecked(int i2) {
        if (this.adapter.getSize() <= 0) {
            this.check.setSelected(false);
            return;
        }
        LocalMedia item = this.adapter.getItem(i2);
        if (item != null) {
            this.check.setSelected(isSelected(item));
        }
    }

    public void onPageSelectedChange(LocalMedia localMedia) {
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onSaveInstanceState(@NotNull Bundle bundle) {
        super.onSaveInstanceState(bundle);
        bundle.putBoolean(PictureConfig.EXTRA_COMPLETE_SELECTED, this.isCompleteOrSelected);
        bundle.putBoolean(PictureConfig.EXTRA_CHANGE_SELECTED_DATA, this.isChangeSelectedData);
        PictureSelector.saveSelectorList(bundle, this.selectData);
    }

    public void onSelectNumChange(boolean z) {
        this.refresh = z;
        List<LocalMedia> list = this.selectData;
        if (!((list == null || list.size() == 0) ? false : true)) {
            this.mTvPictureOk.setEnabled(false);
            this.mTvPictureOk.setSelected(false);
            PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
            if (pictureParameterStyle != null) {
                int i2 = pictureParameterStyle.pictureUnCompleteTextColor;
                if (i2 != 0) {
                    this.mTvPictureOk.setTextColor(i2);
                } else {
                    this.mTvPictureOk.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_9b));
                }
            }
            if (this.numComplete) {
                initCompleteText(0);
                return;
            }
            this.tvMediaNum.setVisibility(4);
            PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle != null) {
                if (TextUtils.isEmpty(pictureSelectorUIStyle.picture_bottom_completeDefaultText)) {
                    return;
                }
                this.mTvPictureOk.setText(PictureSelectionConfig.uiStyle.picture_bottom_completeDefaultText);
                return;
            }
            PictureParameterStyle pictureParameterStyle2 = PictureSelectionConfig.style;
            if (pictureParameterStyle2 == null) {
                this.mTvPictureOk.setText(getString(C3979R.string.picture_please_select));
                return;
            } else {
                if (TextUtils.isEmpty(pictureParameterStyle2.pictureUnCompleteText)) {
                    return;
                }
                this.mTvPictureOk.setText(PictureSelectionConfig.style.pictureUnCompleteText);
                return;
            }
        }
        this.mTvPictureOk.setEnabled(true);
        this.mTvPictureOk.setSelected(true);
        PictureParameterStyle pictureParameterStyle3 = PictureSelectionConfig.style;
        if (pictureParameterStyle3 != null) {
            int i3 = pictureParameterStyle3.pictureCompleteTextColor;
            if (i3 != 0) {
                this.mTvPictureOk.setTextColor(i3);
            } else {
                this.mTvPictureOk.setTextColor(ContextCompat.getColor(getContext(), C3979R.color.picture_color_fa632d));
            }
        }
        if (this.numComplete) {
            initCompleteText(this.selectData.size());
            return;
        }
        if (this.refresh) {
            this.tvMediaNum.startAnimation(this.animation);
        }
        this.tvMediaNum.setVisibility(0);
        this.tvMediaNum.setText(String.valueOf(this.selectData.size()));
        PictureSelectorUIStyle pictureSelectorUIStyle2 = PictureSelectionConfig.uiStyle;
        if (pictureSelectorUIStyle2 != null) {
            if (TextUtils.isEmpty(pictureSelectorUIStyle2.picture_bottom_completeNormalText)) {
                return;
            }
            this.mTvPictureOk.setText(PictureSelectionConfig.uiStyle.picture_bottom_completeNormalText);
            return;
        }
        PictureParameterStyle pictureParameterStyle4 = PictureSelectionConfig.style;
        if (pictureParameterStyle4 == null) {
            this.mTvPictureOk.setText(getString(C3979R.string.picture_completed));
        } else {
            if (TextUtils.isEmpty(pictureParameterStyle4.pictureCompleteText)) {
                return;
            }
            this.mTvPictureOk.setText(PictureSelectionConfig.style.pictureCompleteText);
        }
    }

    public void onSelectedChange(boolean z, LocalMedia localMedia) {
    }

    public void onUpdateSelectedChange(LocalMedia localMedia) {
    }
}
