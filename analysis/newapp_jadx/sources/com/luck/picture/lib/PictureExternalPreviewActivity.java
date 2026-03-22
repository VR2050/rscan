package com.luck.picture.lib;

import android.content.ContentValues;
import android.content.Intent;
import android.graphics.PointF;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.text.TextUtils;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.viewpager.widget.PagerAdapter;
import androidx.viewpager.widget.ViewPager;
import com.luck.picture.lib.PictureExternalPreviewActivity;
import com.luck.picture.lib.PictureMediaScannerConnection;
import com.luck.picture.lib.broadcast.BroadcastAction;
import com.luck.picture.lib.broadcast.BroadcastManager;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.dialog.PictureCustomDialog;
import com.luck.picture.lib.engine.ImageEngine;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnImageCompleteCallback;
import com.luck.picture.lib.listener.OnVideoSelectedPlayCallback;
import com.luck.picture.lib.permissions.PermissionChecker;
import com.luck.picture.lib.photoview.OnViewTapListener;
import com.luck.picture.lib.photoview.PhotoView;
import com.luck.picture.lib.style.PictureParameterStyle;
import com.luck.picture.lib.thread.PictureThreadUtils;
import com.luck.picture.lib.tools.AttrsUtils;
import com.luck.picture.lib.tools.DateUtils;
import com.luck.picture.lib.tools.JumpUtils;
import com.luck.picture.lib.tools.MediaUtils;
import com.luck.picture.lib.tools.PictureFileUtils;
import com.luck.picture.lib.tools.SdkVersionUtils;
import com.luck.picture.lib.tools.ToastUtils;
import com.luck.picture.lib.tools.ValueOf;
import com.luck.picture.lib.widget.PreviewViewPager;
import com.luck.picture.lib.widget.longimage.ImageSource;
import com.luck.picture.lib.widget.longimage.ImageViewState;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import java.io.Closeable;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p474l.C4758t;
import p474l.InterfaceC4746h;

/* loaded from: classes2.dex */
public class PictureExternalPreviewActivity extends PictureBaseActivity implements View.OnClickListener {

    /* renamed from: e */
    public static final /* synthetic */ int f10205e = 0;
    private SimpleFragmentAdapter adapter;
    private String downloadPath;
    private ImageButton ibDelete;
    private ImageButton ibLeftBack;
    private String mMimeType;
    private View mTitleBar;
    private TextView tvTitle;
    private PreviewViewPager viewPager;
    private List<LocalMedia> images = new ArrayList();
    private int position = 0;

    public class SimpleFragmentAdapter extends PagerAdapter {
        private static final int MAX_CACHE_SIZE = 20;
        private SparseArray<View> mCacheView = new SparseArray<>();

        public SimpleFragmentAdapter() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void clear() {
            SparseArray<View> sparseArray = this.mCacheView;
            if (sparseArray != null) {
                sparseArray.clear();
                this.mCacheView = null;
            }
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public void destroyItem(ViewGroup viewGroup, int i2, Object obj) {
            viewGroup.removeView((View) obj);
            if (this.mCacheView.size() > 20) {
                this.mCacheView.remove(i2);
            }
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public int getCount() {
            if (PictureExternalPreviewActivity.this.images != null) {
                return PictureExternalPreviewActivity.this.images.size();
            }
            return 0;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public int getItemPosition(@NonNull Object obj) {
            return -2;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public Object instantiateItem(final ViewGroup viewGroup, int i2) {
            View view = this.mCacheView.get(i2);
            if (view == null) {
                view = LayoutInflater.from(viewGroup.getContext()).inflate(C3979R.layout.picture_image_preview, viewGroup, false);
                this.mCacheView.put(i2, view);
            }
            PhotoView photoView = (PhotoView) view.findViewById(C3979R.id.preview_image);
            SubsamplingScaleImageView subsamplingScaleImageView = (SubsamplingScaleImageView) view.findViewById(C3979R.id.longImg);
            ImageView imageView = (ImageView) view.findViewById(C3979R.id.iv_play);
            final LocalMedia localMedia = (LocalMedia) PictureExternalPreviewActivity.this.images.get(i2);
            if (localMedia != null) {
                final String compressPath = (!localMedia.isCut() || localMedia.isCompressed()) ? (localMedia.isCompressed() || (localMedia.isCut() && localMedia.isCompressed())) ? localMedia.getCompressPath() : !TextUtils.isEmpty(localMedia.getAndroidQToPath()) ? localMedia.getAndroidQToPath() : localMedia.getPath() : localMedia.getCutPath();
                boolean isHasHttp = PictureMimeType.isHasHttp(compressPath);
                String imageMimeType = isHasHttp ? PictureMimeType.getImageMimeType(localMedia.getPath()) : localMedia.getMimeType();
                boolean isHasVideo = PictureMimeType.isHasVideo(imageMimeType);
                int i3 = 8;
                imageView.setVisibility(isHasVideo ? 0 : 8);
                boolean isGif = PictureMimeType.isGif(imageMimeType);
                boolean isLongImg = MediaUtils.isLongImg(localMedia);
                photoView.setVisibility((!isLongImg || isGif) ? 0 : 8);
                if (isLongImg && !isGif) {
                    i3 = 0;
                }
                subsamplingScaleImageView.setVisibility(i3);
                if (!isGif || localMedia.isCompressed()) {
                    ImageEngine imageEngine = PictureSelectionConfig.imageEngine;
                    if (imageEngine != null) {
                        if (isHasHttp) {
                            imageEngine.loadImage(view.getContext(), compressPath, photoView, subsamplingScaleImageView, new OnImageCompleteCallback() { // from class: com.luck.picture.lib.PictureExternalPreviewActivity.SimpleFragmentAdapter.1
                                @Override // com.luck.picture.lib.listener.OnImageCompleteCallback
                                public void onHideLoading() {
                                    PictureExternalPreviewActivity.this.dismissDialog();
                                }

                                @Override // com.luck.picture.lib.listener.OnImageCompleteCallback
                                public void onShowLoading() {
                                    PictureExternalPreviewActivity.this.showPleaseDialog();
                                }
                            });
                        } else if (isLongImg) {
                            PictureExternalPreviewActivity.this.displayLongPic(PictureMimeType.isContent(compressPath) ? Uri.parse(compressPath) : Uri.fromFile(new File(compressPath)), subsamplingScaleImageView);
                        } else {
                            imageEngine.loadImage(view.getContext(), compressPath, photoView);
                        }
                    }
                } else {
                    ImageEngine imageEngine2 = PictureSelectionConfig.imageEngine;
                    if (imageEngine2 != null) {
                        imageEngine2.loadAsGifImage(PictureExternalPreviewActivity.this.getContext(), compressPath, photoView);
                    }
                }
                photoView.setOnViewTapListener(new OnViewTapListener() { // from class: b.t.a.a.i
                    @Override // com.luck.picture.lib.photoview.OnViewTapListener
                    public final void onViewTap(View view2, float f2, float f3) {
                        PictureExternalPreviewActivity.SimpleFragmentAdapter simpleFragmentAdapter = PictureExternalPreviewActivity.SimpleFragmentAdapter.this;
                        PictureExternalPreviewActivity.this.finish();
                        PictureExternalPreviewActivity.this.exitAnimation();
                    }
                });
                subsamplingScaleImageView.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.k
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        PictureExternalPreviewActivity.SimpleFragmentAdapter simpleFragmentAdapter = PictureExternalPreviewActivity.SimpleFragmentAdapter.this;
                        PictureExternalPreviewActivity.this.finish();
                        PictureExternalPreviewActivity.this.exitAnimation();
                    }
                });
                if (!isHasVideo) {
                    subsamplingScaleImageView.setOnLongClickListener(new View.OnLongClickListener() { // from class: b.t.a.a.j
                        @Override // android.view.View.OnLongClickListener
                        public final boolean onLongClick(View view2) {
                            PictureExternalPreviewActivity.SimpleFragmentAdapter simpleFragmentAdapter = PictureExternalPreviewActivity.SimpleFragmentAdapter.this;
                            String str = compressPath;
                            LocalMedia localMedia2 = localMedia;
                            PictureExternalPreviewActivity pictureExternalPreviewActivity = PictureExternalPreviewActivity.this;
                            if (pictureExternalPreviewActivity.config.isNotPreviewDownload) {
                                if (PermissionChecker.checkSelfPermission(pictureExternalPreviewActivity.getContext(), "android.permission.WRITE_EXTERNAL_STORAGE")) {
                                    PictureExternalPreviewActivity.this.downloadPath = str;
                                    String imageMimeType2 = PictureMimeType.isHasHttp(str) ? PictureMimeType.getImageMimeType(localMedia2.getPath()) : localMedia2.getMimeType();
                                    PictureExternalPreviewActivity pictureExternalPreviewActivity2 = PictureExternalPreviewActivity.this;
                                    if (PictureMimeType.isJPG(imageMimeType2)) {
                                        imageMimeType2 = "image/jpeg";
                                    }
                                    pictureExternalPreviewActivity2.mMimeType = imageMimeType2;
                                    PictureExternalPreviewActivity.this.showDownLoadDialog();
                                } else {
                                    PermissionChecker.requestPermissions(PictureExternalPreviewActivity.this, new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 1);
                                }
                            }
                            return true;
                        }
                    });
                }
                if (!isHasVideo) {
                    photoView.setOnLongClickListener(new View.OnLongClickListener() { // from class: b.t.a.a.l
                        @Override // android.view.View.OnLongClickListener
                        public final boolean onLongClick(View view2) {
                            PictureExternalPreviewActivity.SimpleFragmentAdapter simpleFragmentAdapter = PictureExternalPreviewActivity.SimpleFragmentAdapter.this;
                            String str = compressPath;
                            LocalMedia localMedia2 = localMedia;
                            PictureExternalPreviewActivity pictureExternalPreviewActivity = PictureExternalPreviewActivity.this;
                            if (pictureExternalPreviewActivity.config.isNotPreviewDownload) {
                                if (PermissionChecker.checkSelfPermission(pictureExternalPreviewActivity.getContext(), "android.permission.WRITE_EXTERNAL_STORAGE")) {
                                    PictureExternalPreviewActivity.this.downloadPath = str;
                                    String imageMimeType2 = PictureMimeType.isHasHttp(str) ? PictureMimeType.getImageMimeType(localMedia2.getPath()) : localMedia2.getMimeType();
                                    PictureExternalPreviewActivity pictureExternalPreviewActivity2 = PictureExternalPreviewActivity.this;
                                    if (PictureMimeType.isJPG(imageMimeType2)) {
                                        imageMimeType2 = "image/jpeg";
                                    }
                                    pictureExternalPreviewActivity2.mMimeType = imageMimeType2;
                                    PictureExternalPreviewActivity.this.showDownLoadDialog();
                                } else {
                                    PermissionChecker.requestPermissions(PictureExternalPreviewActivity.this, new String[]{"android.permission.WRITE_EXTERNAL_STORAGE"}, 1);
                                }
                            }
                            return true;
                        }
                    });
                }
                imageView.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.m
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        LocalMedia localMedia2 = LocalMedia.this;
                        String str = compressPath;
                        ViewGroup viewGroup2 = viewGroup;
                        OnVideoSelectedPlayCallback onVideoSelectedPlayCallback = PictureSelectionConfig.customVideoPlayCallback;
                        if (onVideoSelectedPlayCallback != null) {
                            onVideoSelectedPlayCallback.startPlayVideo(localMedia2);
                            return;
                        }
                        Intent intent = new Intent();
                        Bundle bundle = new Bundle();
                        bundle.putString(PictureConfig.EXTRA_VIDEO_PATH, str);
                        intent.putExtras(bundle);
                        JumpUtils.startPictureVideoPlayActivity(viewGroup2.getContext(), bundle, 166);
                    }
                });
            }
            viewGroup.addView(view, 0);
            return view;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public boolean isViewFromObject(View view, Object obj) {
            return view == obj;
        }

        public void removeCacheView(int i2) {
            SparseArray<View> sparseArray = this.mCacheView;
            if (sparseArray == null || i2 >= sparseArray.size()) {
                return;
            }
            this.mCacheView.removeAt(i2);
        }
    }

    private Uri createOutImageUri() {
        ContentValues contentValues = new ContentValues();
        contentValues.put("_display_name", DateUtils.getCreateFileName("IMG_"));
        contentValues.put("datetaken", ValueOf.toString(Long.valueOf(System.currentTimeMillis())));
        contentValues.put("mime_type", this.mMimeType);
        contentValues.put("relative_path", PictureMimeType.DCIM);
        return getContentResolver().insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void displayLongPic(Uri uri, SubsamplingScaleImageView subsamplingScaleImageView) {
        subsamplingScaleImageView.setQuickScaleEnabled(true);
        subsamplingScaleImageView.setZoomEnabled(true);
        subsamplingScaleImageView.setDoubleTapZoomDuration(100);
        subsamplingScaleImageView.setMinimumScaleType(2);
        subsamplingScaleImageView.setDoubleTapZoomDpi(2);
        subsamplingScaleImageView.setImage(ImageSource.uri(uri), new ImageViewState(0.0f, new PointF(0.0f, 0.0f), 0));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void exitAnimation() {
        overridePendingTransition(C3979R.anim.picture_anim_fade_in, PictureSelectionConfig.windowAnimationStyle.activityPreviewExitAnimation);
    }

    private void initViewPageAdapterData() {
        this.tvTitle.setText(getString(C3979R.string.picture_preview_image_num, new Object[]{Integer.valueOf(this.position + 1), Integer.valueOf(this.images.size())}));
        SimpleFragmentAdapter simpleFragmentAdapter = new SimpleFragmentAdapter();
        this.adapter = simpleFragmentAdapter;
        this.viewPager.setAdapter(simpleFragmentAdapter);
        this.viewPager.setCurrentItem(this.position);
        this.viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.luck.picture.lib.PictureExternalPreviewActivity.1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int i2) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int i2, float f2, int i3) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int i2) {
                PictureExternalPreviewActivity.this.tvTitle.setText(PictureExternalPreviewActivity.this.getString(C3979R.string.picture_preview_image_num, new Object[]{Integer.valueOf(i2 + 1), Integer.valueOf(PictureExternalPreviewActivity.this.images.size())}));
                PictureExternalPreviewActivity.this.position = i2;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onSuccessful(String str) {
        dismissDialog();
        if (TextUtils.isEmpty(str)) {
            ToastUtils.m4555s(getContext(), getString(C3979R.string.picture_save_error));
            return;
        }
        try {
            if (!SdkVersionUtils.checkedAndroid_Q()) {
                File file = new File(str);
                MediaStore.Images.Media.insertImage(getContentResolver(), file.getAbsolutePath(), file.getName(), (String) null);
                new PictureMediaScannerConnection(getContext(), file.getAbsolutePath(), new PictureMediaScannerConnection.ScanListener() { // from class: b.t.a.a.h
                    @Override // com.luck.picture.lib.PictureMediaScannerConnection.ScanListener
                    public final void onScanFinish() {
                        int i2 = PictureExternalPreviewActivity.f10205e;
                    }
                });
            }
            ToastUtils.m4555s(getContext(), getString(C3979R.string.picture_save_success) + "\n" + str);
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    private void savePictureAlbum() {
        String absolutePath;
        String lastImgSuffix = PictureMimeType.getLastImgSuffix(this.mMimeType);
        String externalStorageState = Environment.getExternalStorageState();
        File externalStoragePublicDirectory = externalStorageState.equals("mounted") ? Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM) : getContext().getExternalFilesDir(Environment.DIRECTORY_PICTURES);
        if (externalStoragePublicDirectory != null && !externalStoragePublicDirectory.exists()) {
            externalStoragePublicDirectory.mkdirs();
        }
        if (SdkVersionUtils.checkedAndroid_Q() || !externalStorageState.equals("mounted")) {
            absolutePath = externalStoragePublicDirectory.getAbsolutePath();
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(externalStoragePublicDirectory.getAbsolutePath());
            String str = File.separator;
            absolutePath = C1499a.m583E(sb, str, PictureMimeType.CAMERA, str);
        }
        File file = new File(absolutePath);
        if (!file.exists()) {
            file.mkdirs();
        }
        File file2 = new File(file, DateUtils.getCreateFileName("IMG_") + lastImgSuffix);
        PictureFileUtils.copyFile(this.downloadPath, file2.getAbsolutePath());
        onSuccessful(file2.getAbsolutePath());
    }

    private void savePictureAlbumAndroidQ(final Uri uri) {
        ContentValues contentValues = new ContentValues();
        contentValues.put("_display_name", DateUtils.getCreateFileName("IMG_"));
        contentValues.put("datetaken", ValueOf.toString(Long.valueOf(System.currentTimeMillis())));
        contentValues.put("mime_type", this.mMimeType);
        contentValues.put("relative_path", PictureMimeType.DCIM);
        final Uri insert = getContentResolver().insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues);
        if (insert == null) {
            ToastUtils.m4555s(getContext(), getString(C3979R.string.picture_save_error));
        } else {
            PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<String>() { // from class: com.luck.picture.lib.PictureExternalPreviewActivity.3
                @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                public String doInBackground() {
                    InterfaceC4746h interfaceC4746h = null;
                    try {
                        try {
                            InputStream openInputStream = PictureExternalPreviewActivity.this.getContentResolver().openInputStream(uri);
                            Objects.requireNonNull(openInputStream);
                            interfaceC4746h = C2354n.m2500o(C2354n.m2397H1(openInputStream));
                        } catch (Exception e2) {
                            e2.printStackTrace();
                            if (interfaceC4746h == null || !((C4758t) interfaceC4746h).isOpen()) {
                                return "";
                            }
                        }
                        if (PictureFileUtils.bufferCopy(interfaceC4746h, PictureExternalPreviewActivity.this.getContentResolver().openOutputStream(insert))) {
                            String path = PictureFileUtils.getPath(PictureExternalPreviewActivity.this.getContext(), insert);
                            if (((C4758t) interfaceC4746h).isOpen()) {
                                PictureFileUtils.close(interfaceC4746h);
                            }
                            return path;
                        }
                        if (!((C4758t) interfaceC4746h).isOpen()) {
                            return "";
                        }
                        PictureFileUtils.close(interfaceC4746h);
                        return "";
                    } catch (Throwable th) {
                        if (interfaceC4746h != null && ((C4758t) interfaceC4746h).isOpen()) {
                            PictureFileUtils.close(interfaceC4746h);
                        }
                        throw th;
                    }
                }

                @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                public void onSuccess(String str) {
                    PictureThreadUtils.cancel(PictureThreadUtils.getIoPool());
                    PictureExternalPreviewActivity.this.onSuccessful(str);
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showDownLoadDialog() {
        if (isFinishing() || TextUtils.isEmpty(this.downloadPath)) {
            return;
        }
        final PictureCustomDialog pictureCustomDialog = new PictureCustomDialog(getContext(), C3979R.layout.picture_wind_base_dialog);
        Button button = (Button) pictureCustomDialog.findViewById(C3979R.id.btn_cancel);
        Button button2 = (Button) pictureCustomDialog.findViewById(C3979R.id.btn_commit);
        TextView textView = (TextView) pictureCustomDialog.findViewById(C3979R.id.tvTitle);
        TextView textView2 = (TextView) pictureCustomDialog.findViewById(C3979R.id.tv_content);
        textView.setText(getString(C3979R.string.picture_prompt));
        textView2.setText(getString(C3979R.string.picture_prompt_content));
        button.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.n
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PictureExternalPreviewActivity pictureExternalPreviewActivity = PictureExternalPreviewActivity.this;
                PictureCustomDialog pictureCustomDialog2 = pictureCustomDialog;
                if (pictureExternalPreviewActivity.isFinishing()) {
                    return;
                }
                pictureCustomDialog2.dismiss();
            }
        });
        button2.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.g
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PictureExternalPreviewActivity.this.m4522a(pictureCustomDialog, view);
            }
        });
        pictureCustomDialog.show();
    }

    /* renamed from: a */
    public /* synthetic */ void m4522a(PictureCustomDialog pictureCustomDialog, View view) {
        boolean isHasHttp = PictureMimeType.isHasHttp(this.downloadPath);
        showPleaseDialog();
        if (isHasHttp) {
            PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<String>() { // from class: com.luck.picture.lib.PictureExternalPreviewActivity.2
                @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                public String doInBackground() {
                    PictureExternalPreviewActivity pictureExternalPreviewActivity = PictureExternalPreviewActivity.this;
                    return pictureExternalPreviewActivity.showLoadingImage(pictureExternalPreviewActivity.downloadPath);
                }

                @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                public void onSuccess(String str) {
                    PictureExternalPreviewActivity.this.onSuccessful(str);
                }
            });
        } else {
            try {
                if (PictureMimeType.isContent(this.downloadPath)) {
                    savePictureAlbumAndroidQ(PictureMimeType.isContent(this.downloadPath) ? Uri.parse(this.downloadPath) : Uri.fromFile(new File(this.downloadPath)));
                } else {
                    savePictureAlbum();
                }
            } catch (Exception e2) {
                ToastUtils.m4555s(getContext(), getString(C3979R.string.picture_save_error) + "\n" + e2.getMessage());
                dismissDialog();
                e2.printStackTrace();
            }
        }
        if (isFinishing()) {
            return;
        }
        pictureCustomDialog.dismiss();
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public int getResourceId() {
        return C3979R.layout.picture_activity_external_preview;
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initPictureSelectorStyle() {
        PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
        if (pictureParameterStyle == null) {
            int typeValueColor = AttrsUtils.getTypeValueColor(getContext(), C3979R.attr.picture_ac_preview_title_bg);
            if (typeValueColor != 0) {
                this.mTitleBar.setBackgroundColor(typeValueColor);
                return;
            } else {
                this.mTitleBar.setBackgroundColor(this.colorPrimary);
                return;
            }
        }
        int i2 = pictureParameterStyle.pictureTitleTextColor;
        if (i2 != 0) {
            this.tvTitle.setTextColor(i2);
        }
        int i3 = PictureSelectionConfig.style.pictureTitleTextSize;
        if (i3 != 0) {
            this.tvTitle.setTextSize(i3);
        }
        int i4 = PictureSelectionConfig.style.pictureLeftBackIcon;
        if (i4 != 0) {
            this.ibLeftBack.setImageResource(i4);
        }
        int i5 = PictureSelectionConfig.style.pictureExternalPreviewDeleteStyle;
        if (i5 != 0) {
            this.ibDelete.setImageResource(i5);
        }
        if (PictureSelectionConfig.style.pictureTitleBarBackgroundColor != 0) {
            this.mTitleBar.setBackgroundColor(this.colorPrimary);
        }
    }

    @Override // com.luck.picture.lib.PictureBaseActivity
    public void initWidgets() {
        super.initWidgets();
        this.mTitleBar = findViewById(C3979R.id.titleBar);
        this.tvTitle = (TextView) findViewById(C3979R.id.picture_title);
        this.ibLeftBack = (ImageButton) findViewById(C3979R.id.left_back);
        this.ibDelete = (ImageButton) findViewById(C3979R.id.ib_delete);
        this.viewPager = (PreviewViewPager) findViewById(C3979R.id.preview_pager);
        this.position = getIntent().getIntExtra("position", 0);
        if (getIntent().getSerializableExtra(PictureConfig.EXTRA_PREVIEW_SELECT_LIST) != null) {
            this.images = (List) getIntent().getSerializableExtra(PictureConfig.EXTRA_PREVIEW_SELECT_LIST);
        }
        this.ibLeftBack.setOnClickListener(this);
        this.ibDelete.setOnClickListener(this);
        ImageButton imageButton = this.ibDelete;
        PictureParameterStyle pictureParameterStyle = PictureSelectionConfig.style;
        imageButton.setVisibility((pictureParameterStyle == null || !pictureParameterStyle.pictureExternalPreviewGonePreviewDelete) ? 8 : 0);
        initViewPageAdapterData();
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        super.onBackPressed();
        finish();
        exitAnimation();
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        List<LocalMedia> list;
        int id = view.getId();
        if (id == C3979R.id.left_back) {
            finish();
            exitAnimation();
            return;
        }
        if (id != C3979R.id.ib_delete || (list = this.images) == null || list.size() <= 0) {
            return;
        }
        int currentItem = this.viewPager.getCurrentItem();
        this.images.remove(currentItem);
        this.adapter.removeCacheView(currentItem);
        Bundle bundle = new Bundle();
        bundle.putInt("position", currentItem);
        BroadcastManager.getInstance(getContext()).action(BroadcastAction.ACTION_DELETE_PREVIEW_POSITION).extras(bundle).broadcast();
        if (this.images.size() == 0) {
            onBackPressed();
            return;
        }
        this.tvTitle.setText(getString(C3979R.string.picture_preview_image_num, new Object[]{Integer.valueOf(this.position + 1), Integer.valueOf(this.images.size())}));
        this.position = currentItem;
        this.adapter.notifyDataSetChanged();
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        SimpleFragmentAdapter simpleFragmentAdapter = this.adapter;
        if (simpleFragmentAdapter != null) {
            simpleFragmentAdapter.clear();
        }
        PictureSelectionConfig.destroy();
    }

    @Override // com.luck.picture.lib.PictureBaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int i2, @NonNull String[] strArr, @NonNull int[] iArr) {
        super.onRequestPermissionsResult(i2, strArr, iArr);
        if (i2 == 1) {
            for (int i3 : iArr) {
                if (i3 == 0) {
                    showDownLoadDialog();
                } else {
                    ToastUtils.m4555s(getContext(), getString(C3979R.string.picture_jurisdiction));
                }
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r3v1 */
    /* JADX WARN: Type inference failed for: r3v12 */
    /* JADX WARN: Type inference failed for: r3v15 */
    /* JADX WARN: Type inference failed for: r3v17, types: [java.io.Closeable, l.h] */
    /* JADX WARN: Type inference failed for: r3v18 */
    /* JADX WARN: Type inference failed for: r3v19 */
    /* JADX WARN: Type inference failed for: r3v4 */
    /* JADX WARN: Type inference failed for: r3v5, types: [java.io.Closeable] */
    /* JADX WARN: Type inference failed for: r7v0, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r7v11 */
    /* JADX WARN: Type inference failed for: r7v12, types: [java.io.Closeable, java.io.InputStream] */
    /* JADX WARN: Type inference failed for: r7v13 */
    /* JADX WARN: Type inference failed for: r7v14 */
    /* JADX WARN: Type inference failed for: r7v15 */
    /* JADX WARN: Type inference failed for: r7v16 */
    /* JADX WARN: Type inference failed for: r7v5 */
    /* JADX WARN: Type inference failed for: r7v7 */
    /* JADX WARN: Type inference failed for: r7v8, types: [java.io.Closeable] */
    public String showLoadingImage(String str) {
        OutputStream outputStream;
        Closeable closeable;
        Object obj;
        Uri uri;
        ?? r3;
        String sb;
        Closeable closeable2 = null;
        try {
            try {
                try {
                    if (SdkVersionUtils.checkedAndroid_Q()) {
                        uri = createOutImageUri();
                    } else {
                        String lastImgSuffix = PictureMimeType.getLastImgSuffix(this.mMimeType);
                        String externalStorageState = Environment.getExternalStorageState();
                        File externalStoragePublicDirectory = externalStorageState.equals("mounted") ? Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM) : getContext().getExternalFilesDir(Environment.DIRECTORY_PICTURES);
                        if (externalStoragePublicDirectory != null) {
                            if (!externalStoragePublicDirectory.exists()) {
                                externalStoragePublicDirectory.mkdirs();
                            }
                            if (externalStorageState.equals("mounted")) {
                                StringBuilder sb2 = new StringBuilder();
                                sb2.append(externalStoragePublicDirectory.getAbsolutePath());
                                String str2 = File.separator;
                                sb2.append(str2);
                                sb2.append(PictureMimeType.CAMERA);
                                sb2.append(str2);
                                sb = sb2.toString();
                            } else {
                                sb = externalStoragePublicDirectory.getAbsolutePath();
                            }
                            File file = new File(sb);
                            if (!file.exists()) {
                                file.mkdirs();
                            }
                            uri = Uri.fromFile(new File(file, DateUtils.getCreateFileName("IMG_") + lastImgSuffix));
                        } else {
                            uri = null;
                        }
                    }
                    if (uri != null) {
                        try {
                            OutputStream openOutputStream = getContentResolver().openOutputStream(uri);
                            Objects.requireNonNull(openOutputStream);
                            outputStream = openOutputStream;
                            try {
                                str = new URL(str).openStream();
                            } catch (Exception unused) {
                                str = 0;
                                r3 = 0;
                            } catch (Throwable th) {
                                th = th;
                                closeable = null;
                                PictureFileUtils.close(closeable2);
                                PictureFileUtils.close(outputStream);
                                PictureFileUtils.close(closeable);
                                throw th;
                            }
                            try {
                                r3 = C2354n.m2500o(C2354n.m2397H1(str));
                                try {
                                    if (PictureFileUtils.bufferCopy((InterfaceC4746h) r3, outputStream)) {
                                        String path = PictureFileUtils.getPath(this, uri);
                                        PictureFileUtils.close(str);
                                        PictureFileUtils.close(outputStream);
                                        PictureFileUtils.close(r3);
                                        return path;
                                    }
                                } catch (Exception unused2) {
                                    r3 = r3;
                                    str = str;
                                    if (uri != null && SdkVersionUtils.checkedAndroid_Q()) {
                                        getContentResolver().delete(uri, null, null);
                                    }
                                    PictureFileUtils.close(str);
                                    PictureFileUtils.close(outputStream);
                                    PictureFileUtils.close(r3);
                                    return null;
                                }
                            } catch (Exception unused3) {
                                r3 = 0;
                                str = str;
                            } catch (Throwable th2) {
                                th = th2;
                                closeable = null;
                                closeable2 = str;
                                th = th;
                                PictureFileUtils.close(closeable2);
                                PictureFileUtils.close(outputStream);
                                PictureFileUtils.close(closeable);
                                throw th;
                            }
                        } catch (Exception unused4) {
                            obj = null;
                            outputStream = null;
                            r3 = outputStream;
                            str = obj;
                            if (uri != null) {
                                getContentResolver().delete(uri, null, null);
                            }
                            PictureFileUtils.close(str);
                            PictureFileUtils.close(outputStream);
                            PictureFileUtils.close(r3);
                            return null;
                        }
                    } else {
                        str = 0;
                        outputStream = null;
                        r3 = 0;
                    }
                } catch (Throwable th3) {
                    th = th3;
                }
            } catch (Exception unused5) {
                obj = null;
                uri = null;
                outputStream = null;
            }
            PictureFileUtils.close(str);
            PictureFileUtils.close(outputStream);
            PictureFileUtils.close(r3);
            return null;
        } catch (Throwable th4) {
            th = th4;
            outputStream = null;
            closeable = null;
        }
    }
}
