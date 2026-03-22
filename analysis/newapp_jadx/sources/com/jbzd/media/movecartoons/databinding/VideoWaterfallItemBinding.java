package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoWaterfallItemBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvDuration;

    @NonNull
    public final ImageView ivImg;

    @NonNull
    public final LinearLayout llHotWords;

    @NonNull
    public final LinearLayout llNormal;

    @NonNull
    public final RelativeLayout rlVideoBottom;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final RecyclerView rvWords;

    @NonNull
    public final ScaleRelativeLayout srlCover;

    @NonNull
    public final TextView tvName;

    private VideoWaterfallItemBinding(@NonNull RelativeLayout relativeLayout, @NonNull ImageTextView imageTextView, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull RelativeLayout relativeLayout2, @NonNull RecyclerView recyclerView, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull TextView textView) {
        this.rootView = relativeLayout;
        this.itvDuration = imageTextView;
        this.ivImg = imageView;
        this.llHotWords = linearLayout;
        this.llNormal = linearLayout2;
        this.rlVideoBottom = relativeLayout2;
        this.rvWords = recyclerView;
        this.srlCover = scaleRelativeLayout;
        this.tvName = textView;
    }

    @NonNull
    public static VideoWaterfallItemBinding bind(@NonNull View view) {
        int i2 = R.id.itv_duration;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_duration);
        if (imageTextView != null) {
            i2 = R.id.iv_img;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_img);
            if (imageView != null) {
                i2 = R.id.ll_hotWords;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_hotWords);
                if (linearLayout != null) {
                    i2 = R.id.ll_normal;
                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_normal);
                    if (linearLayout2 != null) {
                        i2 = R.id.rl_videoBottom;
                        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_videoBottom);
                        if (relativeLayout != null) {
                            i2 = R.id.rv_words;
                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_words);
                            if (recyclerView != null) {
                                i2 = R.id.srl_cover;
                                ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.srl_cover);
                                if (scaleRelativeLayout != null) {
                                    i2 = R.id.tv_name;
                                    TextView textView = (TextView) view.findViewById(R.id.tv_name);
                                    if (textView != null) {
                                        return new VideoWaterfallItemBinding((RelativeLayout) view, imageTextView, imageView, linearLayout, linearLayout2, relativeLayout, recyclerView, scaleRelativeLayout, textView);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static VideoWaterfallItemBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoWaterfallItemBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_waterfall_item, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
