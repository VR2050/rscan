package com.yalantis.ucrop;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.text.TextUtils;
import android.view.View;
import android.view.animation.AnimationUtils;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.SimpleItemAnimator;
import com.yalantis.ucrop.PicturePhotoGalleryAdapter;
import com.yalantis.ucrop.UCrop;
import com.yalantis.ucrop.model.CutInfo;
import com.yalantis.ucrop.util.FileUtils;
import com.yalantis.ucrop.util.MimeType;
import com.yalantis.ucrop.util.ScreenUtils;
import java.io.File;
import java.util.ArrayList;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class PictureMultiCuttingActivity extends UCropActivity {
    private static final int MIN_NUM = 1;
    private int cutIndex;
    private boolean isAnimation;
    private boolean isCamera;
    private boolean isWithVideoImage;
    private ArrayList<CutInfo> list;
    private PicturePhotoGalleryAdapter mAdapter;
    private RecyclerView mRecyclerView;
    private int oldCutIndex;
    private String renameCropFilename;

    private void addPhotoRecyclerView() {
        boolean booleanExtra = getIntent().getBooleanExtra(UCrop.Options.EXTRA_SKIP_MULTIPLE_CROP, true);
        RecyclerView recyclerView = new RecyclerView(this);
        this.mRecyclerView = recyclerView;
        int i2 = C4161R.id.id_recycler;
        recyclerView.setId(i2);
        this.mRecyclerView.setBackgroundColor(ContextCompat.getColor(this, C4161R.color.ucrop_color_widget_background));
        this.mRecyclerView.setLayoutParams(new RelativeLayout.LayoutParams(-1, ScreenUtils.dip2px(this, 80.0f)));
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this);
        linearLayoutManager.setOrientation(0);
        if (this.isAnimation) {
            this.mRecyclerView.setLayoutAnimation(AnimationUtils.loadLayoutAnimation(getApplicationContext(), C4161R.anim.ucrop_layout_animation_fall_down));
        }
        this.mRecyclerView.setLayoutManager(linearLayoutManager);
        ((SimpleItemAnimator) this.mRecyclerView.getItemAnimator()).setSupportsChangeAnimations(false);
        resetCutDataStatus();
        this.list.get(this.cutIndex).setCut(true);
        PicturePhotoGalleryAdapter picturePhotoGalleryAdapter = new PicturePhotoGalleryAdapter(this, this.list);
        this.mAdapter = picturePhotoGalleryAdapter;
        this.mRecyclerView.setAdapter(picturePhotoGalleryAdapter);
        if (booleanExtra) {
            this.mAdapter.setOnItemClickListener(new PicturePhotoGalleryAdapter.OnItemClickListener() { // from class: com.yalantis.ucrop.PictureMultiCuttingActivity.1
                @Override // com.yalantis.ucrop.PicturePhotoGalleryAdapter.OnItemClickListener
                public void onItemClick(int i3, View view) {
                    if (MimeType.isHasVideo(((CutInfo) PictureMultiCuttingActivity.this.list.get(i3)).getMimeType()) || PictureMultiCuttingActivity.this.cutIndex == i3) {
                        return;
                    }
                    PictureMultiCuttingActivity.this.resetLastCropStatus();
                    PictureMultiCuttingActivity.this.cutIndex = i3;
                    PictureMultiCuttingActivity pictureMultiCuttingActivity = PictureMultiCuttingActivity.this;
                    pictureMultiCuttingActivity.oldCutIndex = pictureMultiCuttingActivity.cutIndex;
                    PictureMultiCuttingActivity.this.resetCutData();
                }
            });
        }
        this.uCropPhotoBox.addView(this.mRecyclerView);
        changeLayoutParams(this.mShowBottomControls);
        ((RelativeLayout.LayoutParams) ((FrameLayout) findViewById(C4161R.id.ucrop_frame)).getLayoutParams()).addRule(2, i2);
        ((RelativeLayout.LayoutParams) this.mRecyclerView.getLayoutParams()).addRule(2, C4161R.id.controls_wrapper);
    }

    private void changeLayoutParams(boolean z) {
        if (this.mRecyclerView.getLayoutParams() == null) {
            return;
        }
        if (z) {
            ((RelativeLayout.LayoutParams) this.mRecyclerView.getLayoutParams()).addRule(12, 0);
            ((RelativeLayout.LayoutParams) this.mRecyclerView.getLayoutParams()).addRule(2, C4161R.id.wrapper_controls);
        } else {
            ((RelativeLayout.LayoutParams) this.mRecyclerView.getLayoutParams()).addRule(12);
            ((RelativeLayout.LayoutParams) this.mRecyclerView.getLayoutParams()).addRule(2, 0);
        }
    }

    private void getIndex(int i2) {
        for (int i3 = 0; i3 < i2; i3++) {
            CutInfo cutInfo = this.list.get(i3);
            if (cutInfo != null && MimeType.isHasImage(cutInfo.getMimeType())) {
                this.cutIndex = i3;
                return;
            }
        }
    }

    private void initLoadCutData() {
        ArrayList<CutInfo> arrayList = this.list;
        if (arrayList == null || arrayList.size() == 0) {
            onBackPressed();
            return;
        }
        int size = this.list.size();
        if (this.isWithVideoImage) {
            getIndex(size);
        }
        for (int i2 = 0; i2 < size; i2++) {
            CutInfo cutInfo = this.list.get(i2);
            if (MimeType.isHttp(cutInfo.getPath())) {
                String path = this.list.get(i2).getPath();
                String lastImgType = MimeType.getLastImgType(path);
                if (!TextUtils.isEmpty(path) && !TextUtils.isEmpty(lastImgType)) {
                    File file = new File(Environment.getExternalStorageState().equals("mounted") ? getExternalFilesDir(Environment.DIRECTORY_PICTURES) : getCacheDir(), C1499a.m628n("temporary_thumbnail_", i2, lastImgType));
                    cutInfo.setMimeType(MimeType.getImageMimeType(path));
                    cutInfo.setHttpOutUri(Uri.fromFile(file));
                }
            }
        }
    }

    private void refreshPhotoRecyclerData() {
        resetCutDataStatus();
        this.list.get(this.cutIndex).setCut(true);
        this.mAdapter.notifyItemChanged(this.cutIndex);
        this.uCropPhotoBox.addView(this.mRecyclerView);
        changeLayoutParams(this.mShowBottomControls);
        ((RelativeLayout.LayoutParams) ((FrameLayout) findViewById(C4161R.id.ucrop_frame)).getLayoutParams()).addRule(2, C4161R.id.id_recycler);
        ((RelativeLayout.LayoutParams) this.mRecyclerView.getLayoutParams()).addRule(2, C4161R.id.controls_wrapper);
    }

    private void resetCutDataStatus() {
        int size = this.list.size();
        for (int i2 = 0; i2 < size; i2++) {
            this.list.get(i2).setCut(false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resetLastCropStatus() {
        int i2;
        int size = this.list.size();
        if (size <= 1 || size <= (i2 = this.oldCutIndex)) {
            return;
        }
        this.list.get(i2).setCut(false);
        this.mAdapter.notifyItemChanged(this.cutIndex);
    }

    @Override // com.yalantis.ucrop.UCropActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        Intent intent = getIntent();
        this.renameCropFilename = intent.getStringExtra(UCrop.Options.EXTRA_RENAME_CROP_FILENAME);
        this.isCamera = intent.getBooleanExtra(UCrop.Options.EXTRA_CAMERA, false);
        this.isWithVideoImage = intent.getBooleanExtra(UCrop.Options.EXTRA_WITH_VIDEO_IMAGE, false);
        this.list = getIntent().getParcelableArrayListExtra(UCrop.Options.EXTRA_CUT_CROP);
        this.isAnimation = getIntent().getBooleanExtra(UCrop.Options.EXTRA_MULTIPLE_RECYCLERANIMATION, true);
        ArrayList<CutInfo> arrayList = this.list;
        if (arrayList == null || arrayList.size() == 0) {
            onBackPressed();
        } else if (this.list.size() > 1) {
            initLoadCutData();
            addPhotoRecyclerView();
        }
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        PicturePhotoGalleryAdapter picturePhotoGalleryAdapter = this.mAdapter;
        if (picturePhotoGalleryAdapter != null) {
            picturePhotoGalleryAdapter.setOnItemClickListener(null);
        }
        super.onDestroy();
    }

    public void resetCutData() {
        String rename;
        this.uCropPhotoBox.removeView(this.mRecyclerView);
        View view = this.mBlockingView;
        if (view != null) {
            this.uCropPhotoBox.removeView(view);
        }
        setContentView(C4161R.layout.ucrop_activity_photobox);
        this.uCropPhotoBox = (RelativeLayout) findViewById(C4161R.id.ucrop_photobox);
        addBlockingView();
        Intent intent = getIntent();
        Bundle extras = intent.getExtras();
        if (extras == null) {
            extras = new Bundle();
        }
        CutInfo cutInfo = this.list.get(this.cutIndex);
        String path = cutInfo.getPath();
        boolean isHttp = MimeType.isHttp(path);
        String lastImgType = MimeType.getLastImgType(MimeType.isContent(path) ? FileUtils.getPath(this, Uri.parse(path)) : path);
        extras.putParcelable(UCrop.EXTRA_INPUT_URI, !TextUtils.isEmpty(cutInfo.getAndroidQToPath()) ? Uri.fromFile(new File(cutInfo.getAndroidQToPath())) : (isHttp || MimeType.isContent(path)) ? Uri.parse(path) : Uri.fromFile(new File(path)));
        File externalFilesDir = Environment.getExternalStorageState().equals("mounted") ? getExternalFilesDir(Environment.DIRECTORY_PICTURES) : getCacheDir();
        if (TextUtils.isEmpty(this.renameCropFilename)) {
            rename = FileUtils.getCreateFileName("IMG_CROP_") + lastImgType;
        } else {
            rename = this.isCamera ? this.renameCropFilename : FileUtils.rename(this.renameCropFilename);
        }
        extras.putParcelable(UCrop.EXTRA_OUTPUT_URI, Uri.fromFile(new File(externalFilesDir, rename)));
        intent.putExtras(extras);
        setupViews(intent);
        refreshPhotoRecyclerData();
        setImageData(intent);
        setInitialState();
        double dip2px = ScreenUtils.dip2px(this, 60.0f) * this.cutIndex;
        int i2 = this.mScreenWidth;
        if (dip2px > i2 * 0.8d) {
            this.mRecyclerView.scrollBy(ScreenUtils.dip2px(this, 60.0f), 0);
        } else if (dip2px < i2 * 0.4d) {
            this.mRecyclerView.scrollBy(ScreenUtils.dip2px(this, -60.0f), 0);
        }
    }

    @Override // com.yalantis.ucrop.UCropActivity
    public void setResultUri(Uri uri, float f2, int i2, int i3, int i4, int i5) {
        try {
            int size = this.list.size();
            int i6 = this.cutIndex;
            if (size < i6) {
                onBackPressed();
                return;
            }
            CutInfo cutInfo = this.list.get(i6);
            cutInfo.setCutPath(uri.getPath());
            cutInfo.setCut(true);
            cutInfo.setResultAspectRatio(f2);
            cutInfo.setOffsetX(i2);
            cutInfo.setOffsetY(i3);
            cutInfo.setImageWidth(i4);
            cutInfo.setImageHeight(i5);
            resetLastCropStatus();
            int i7 = this.cutIndex + 1;
            this.cutIndex = i7;
            if (this.isWithVideoImage && i7 < this.list.size() && MimeType.isHasVideo(this.list.get(this.cutIndex).getMimeType())) {
                while (this.cutIndex < this.list.size() && !MimeType.isHasImage(this.list.get(this.cutIndex).getMimeType())) {
                    this.cutIndex++;
                }
            }
            int i8 = this.cutIndex;
            this.oldCutIndex = i8;
            if (i8 < this.list.size()) {
                resetCutData();
            } else {
                setResult(-1, new Intent().putExtra(UCrop.Options.EXTRA_OUTPUT_URI_LIST, this.list));
                onBackPressed();
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }
}
