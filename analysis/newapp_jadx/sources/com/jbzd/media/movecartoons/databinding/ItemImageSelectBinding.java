package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.AspectRatioLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemImageSelectBinding implements ViewBinding {

    @NonNull
    public final ImageView ivCover;

    @NonNull
    public final ImageView ivDelete;

    @NonNull
    public final AspectRatioLayout llAddSelect;

    @NonNull
    private final AspectRatioLayout rootView;

    @NonNull
    public final ImageView tvAddMedia;

    @NonNull
    public final TextView tvChange;

    @NonNull
    public final TextView tvCoverImg;

    private ItemImageSelectBinding(@NonNull AspectRatioLayout aspectRatioLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull AspectRatioLayout aspectRatioLayout2, @NonNull ImageView imageView3, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = aspectRatioLayout;
        this.ivCover = imageView;
        this.ivDelete = imageView2;
        this.llAddSelect = aspectRatioLayout2;
        this.tvAddMedia = imageView3;
        this.tvChange = textView;
        this.tvCoverImg = textView2;
    }

    @NonNull
    public static ItemImageSelectBinding bind(@NonNull View view) {
        int i2 = R.id.iv_cover;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_cover);
        if (imageView != null) {
            i2 = R.id.iv_delete;
            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_delete);
            if (imageView2 != null) {
                AspectRatioLayout aspectRatioLayout = (AspectRatioLayout) view;
                i2 = R.id.tv_add_media;
                ImageView imageView3 = (ImageView) view.findViewById(R.id.tv_add_media);
                if (imageView3 != null) {
                    i2 = R.id.tv_change;
                    TextView textView = (TextView) view.findViewById(R.id.tv_change);
                    if (textView != null) {
                        i2 = R.id.tv_cover_img;
                        TextView textView2 = (TextView) view.findViewById(R.id.tv_cover_img);
                        if (textView2 != null) {
                            return new ItemImageSelectBinding(aspectRatioLayout, imageView, imageView2, aspectRatioLayout, imageView3, textView, textView2);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemImageSelectBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemImageSelectBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_image_select, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public AspectRatioLayout getRoot() {
        return this.rootView;
    }
}
