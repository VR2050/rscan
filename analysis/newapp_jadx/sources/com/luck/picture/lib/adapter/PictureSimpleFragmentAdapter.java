package com.luck.picture.lib.adapter;

import android.content.Intent;
import android.graphics.PointF;
import android.net.Uri;
import android.os.Bundle;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.viewpager.widget.PagerAdapter;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.adapter.PictureSimpleFragmentAdapter;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.engine.ImageEngine;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnVideoSelectedPlayCallback;
import com.luck.picture.lib.photoview.OnViewTapListener;
import com.luck.picture.lib.photoview.PhotoView;
import com.luck.picture.lib.tools.JumpUtils;
import com.luck.picture.lib.tools.MediaUtils;
import com.luck.picture.lib.widget.longimage.ImageSource;
import com.luck.picture.lib.widget.longimage.ImageViewState;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public class PictureSimpleFragmentAdapter extends PagerAdapter {
    private static final int MAX_CACHE_SIZE = 20;
    private PictureSelectionConfig config;
    private List<LocalMedia> data;
    private SparseArray<View> mCacheView = new SparseArray<>();
    private OnCallBackActivity onBackPressed;

    public interface OnCallBackActivity {
        void onActivityBackPressed();
    }

    public PictureSimpleFragmentAdapter(PictureSelectionConfig pictureSelectionConfig, OnCallBackActivity onCallBackActivity) {
        this.config = pictureSelectionConfig;
        this.onBackPressed = onCallBackActivity;
    }

    private void displayLongPic(Uri uri, SubsamplingScaleImageView subsamplingScaleImageView) {
        subsamplingScaleImageView.setQuickScaleEnabled(true);
        subsamplingScaleImageView.setZoomEnabled(true);
        subsamplingScaleImageView.setDoubleTapZoomDuration(100);
        subsamplingScaleImageView.setMinimumScaleType(2);
        subsamplingScaleImageView.setDoubleTapZoomDpi(2);
        subsamplingScaleImageView.setImage(ImageSource.uri(uri), new ImageViewState(0.0f, new PointF(0.0f, 0.0f), 0));
    }

    /* renamed from: a */
    public /* synthetic */ void m4538a(View view, float f2, float f3) {
        OnCallBackActivity onCallBackActivity = this.onBackPressed;
        if (onCallBackActivity != null) {
            onCallBackActivity.onActivityBackPressed();
        }
    }

    /* renamed from: b */
    public /* synthetic */ void m4539b(View view) {
        OnCallBackActivity onCallBackActivity = this.onBackPressed;
        if (onCallBackActivity != null) {
            onCallBackActivity.onActivityBackPressed();
        }
    }

    public void bindData(List<LocalMedia> list) {
        this.data = list;
    }

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
        List<LocalMedia> list = this.data;
        if (list != null) {
            return list.size();
        }
        return 0;
    }

    public List<LocalMedia> getData() {
        List<LocalMedia> list = this.data;
        return list == null ? new ArrayList() : list;
    }

    public LocalMedia getItem(int i2) {
        if (getSize() <= 0 || i2 >= getSize()) {
            return null;
        }
        return this.data.get(i2);
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public int getItemPosition(@NonNull Object obj) {
        return -2;
    }

    public int getSize() {
        List<LocalMedia> list = this.data;
        if (list == null) {
            return 0;
        }
        return list.size();
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    @NotNull
    public Object instantiateItem(@NotNull final ViewGroup viewGroup, int i2) {
        ImageEngine imageEngine;
        ImageEngine imageEngine2;
        View view = this.mCacheView.get(i2);
        if (view == null) {
            view = LayoutInflater.from(viewGroup.getContext()).inflate(C3979R.layout.picture_image_preview, viewGroup, false);
            this.mCacheView.put(i2, view);
        }
        PhotoView photoView = (PhotoView) view.findViewById(C3979R.id.preview_image);
        SubsamplingScaleImageView subsamplingScaleImageView = (SubsamplingScaleImageView) view.findViewById(C3979R.id.longImg);
        ImageView imageView = (ImageView) view.findViewById(C3979R.id.iv_play);
        final LocalMedia item = getItem(i2);
        if (item != null) {
            String mimeType = item.getMimeType();
            final String compressPath = (!item.isCut() || item.isCompressed()) ? (item.isCompressed() || (item.isCut() && item.isCompressed())) ? item.getCompressPath() : item.getPath() : item.getCutPath();
            boolean isGif = PictureMimeType.isGif(mimeType);
            int i3 = 8;
            imageView.setVisibility(PictureMimeType.isHasVideo(mimeType) ? 0 : 8);
            imageView.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.h0.f
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    LocalMedia localMedia = LocalMedia.this;
                    String str = compressPath;
                    ViewGroup viewGroup2 = viewGroup;
                    OnVideoSelectedPlayCallback onVideoSelectedPlayCallback = PictureSelectionConfig.customVideoPlayCallback;
                    if (onVideoSelectedPlayCallback != null) {
                        onVideoSelectedPlayCallback.startPlayVideo(localMedia);
                        return;
                    }
                    Intent intent = new Intent();
                    Bundle bundle = new Bundle();
                    bundle.putBoolean(PictureConfig.EXTRA_PREVIEW_VIDEO, true);
                    bundle.putString(PictureConfig.EXTRA_VIDEO_PATH, str);
                    intent.putExtras(bundle);
                    JumpUtils.startPictureVideoPlayActivity(viewGroup2.getContext(), bundle, 166);
                }
            });
            boolean isLongImg = MediaUtils.isLongImg(item);
            photoView.setVisibility((!isLongImg || isGif) ? 0 : 8);
            photoView.setOnViewTapListener(new OnViewTapListener() { // from class: b.t.a.a.h0.h
                @Override // com.luck.picture.lib.photoview.OnViewTapListener
                public final void onViewTap(View view2, float f2, float f3) {
                    PictureSimpleFragmentAdapter.this.m4538a(view2, f2, f3);
                }
            });
            if (isLongImg && !isGif) {
                i3 = 0;
            }
            subsamplingScaleImageView.setVisibility(i3);
            subsamplingScaleImageView.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.h0.g
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    PictureSimpleFragmentAdapter.this.m4539b(view2);
                }
            });
            if (!isGif || item.isCompressed()) {
                if (this.config != null && (imageEngine = PictureSelectionConfig.imageEngine) != null) {
                    if (isLongImg) {
                        displayLongPic(PictureMimeType.isContent(compressPath) ? Uri.parse(compressPath) : Uri.fromFile(new File(compressPath)), subsamplingScaleImageView);
                    } else {
                        imageEngine.loadImage(view.getContext(), compressPath, photoView);
                    }
                }
            } else if (this.config != null && (imageEngine2 = PictureSelectionConfig.imageEngine) != null) {
                imageEngine2.loadAsGifImage(view.getContext(), compressPath, photoView);
            }
        }
        viewGroup.addView(view, 0);
        return view;
    }

    @Override // androidx.viewpager.widget.PagerAdapter
    public boolean isViewFromObject(@NotNull View view, @NotNull Object obj) {
        return view == obj;
    }

    public void remove(int i2) {
        if (getSize() > i2) {
            this.data.remove(i2);
        }
    }

    public void removeCacheView(int i2) {
        SparseArray<View> sparseArray = this.mCacheView;
        if (sparseArray == null || i2 >= sparseArray.size()) {
            return;
        }
        this.mCacheView.removeAt(i2);
    }
}
