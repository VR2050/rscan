package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemBasevideoAichangefaceBinding implements ViewBinding {

    @NonNull
    public final ImageView imgDefaultShow;

    @NonNull
    public final FullPlayerView itemPlayer;

    @NonNull
    public final ImageView ivCenterPlayicon;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final ConstraintLayout rvTagLayout;

    @NonNull
    public final View view;

    @NonNull
    public final View viewUp;

    private ItemBasevideoAichangefaceBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ImageView imageView, @NonNull FullPlayerView fullPlayerView, @NonNull ImageView imageView2, @NonNull ConstraintLayout constraintLayout2, @NonNull View view, @NonNull View view2) {
        this.rootView = constraintLayout;
        this.imgDefaultShow = imageView;
        this.itemPlayer = fullPlayerView;
        this.ivCenterPlayicon = imageView2;
        this.rvTagLayout = constraintLayout2;
        this.view = view;
        this.viewUp = view2;
    }

    @NonNull
    public static ItemBasevideoAichangefaceBinding bind(@NonNull View view) {
        int i2 = R.id.img_default_show;
        ImageView imageView = (ImageView) view.findViewById(R.id.img_default_show);
        if (imageView != null) {
            i2 = R.id.item_player;
            FullPlayerView fullPlayerView = (FullPlayerView) view.findViewById(R.id.item_player);
            if (fullPlayerView != null) {
                i2 = R.id.iv_center_playicon;
                ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_center_playicon);
                if (imageView2 != null) {
                    ConstraintLayout constraintLayout = (ConstraintLayout) view;
                    i2 = R.id.view;
                    View findViewById = view.findViewById(R.id.view);
                    if (findViewById != null) {
                        i2 = R.id.view_up;
                        View findViewById2 = view.findViewById(R.id.view_up);
                        if (findViewById2 != null) {
                            return new ItemBasevideoAichangefaceBinding(constraintLayout, imageView, fullPlayerView, imageView2, constraintLayout, findViewById, findViewById2);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemBasevideoAichangefaceBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemBasevideoAichangefaceBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_basevideo_aichangeface, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ConstraintLayout getRoot() {
        return this.rootView;
    }
}
