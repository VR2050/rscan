package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemChapteritemImgBinding implements ViewBinding {

    @NonNull
    public final ImageView ivChapteritemImg;

    @NonNull
    private final LinearLayout rootView;

    private ItemChapteritemImgBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView) {
        this.rootView = linearLayout;
        this.ivChapteritemImg = imageView;
    }

    @NonNull
    public static ItemChapteritemImgBinding bind(@NonNull View view) {
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_chapteritem_img);
        if (imageView != null) {
            return new ItemChapteritemImgBinding((LinearLayout) view, imageView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.iv_chapteritem_img)));
    }

    @NonNull
    public static ItemChapteritemImgBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemChapteritemImgBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_chapteritem_img, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
