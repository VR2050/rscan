package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemPostdetailFileBinding implements ViewBinding {

    @NonNull
    public final ImageView ivItemfileImg;

    @NonNull
    public final LinearLayout llItemfileVideo;

    @NonNull
    public final FullPlayerView playerPostdetail;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvTipsVideoCoin;

    private ItemPostdetailFileBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull FullPlayerView fullPlayerView, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.ivItemfileImg = imageView;
        this.llItemfileVideo = linearLayout2;
        this.playerPostdetail = fullPlayerView;
        this.tvTipsVideoCoin = textView;
    }

    @NonNull
    public static ItemPostdetailFileBinding bind(@NonNull View view) {
        int i2 = R.id.iv_itemfile_img;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_itemfile_img);
        if (imageView != null) {
            i2 = R.id.ll_itemfile_video;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_itemfile_video);
            if (linearLayout != null) {
                i2 = R.id.player_postdetail;
                FullPlayerView fullPlayerView = (FullPlayerView) view.findViewById(R.id.player_postdetail);
                if (fullPlayerView != null) {
                    i2 = R.id.tv_tips_video_coin;
                    TextView textView = (TextView) view.findViewById(R.id.tv_tips_video_coin);
                    if (textView != null) {
                        return new ItemPostdetailFileBinding((LinearLayout) view, imageView, linearLayout, fullPlayerView, textView);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemPostdetailFileBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemPostdetailFileBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_postdetail_file, viewGroup, false);
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
