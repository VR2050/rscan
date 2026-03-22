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
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemHomePreVideoBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvDuration;

    @NonNull
    public final ImageView ivImg;

    @NonNull
    public final RelativeLayout rlVideoBottom;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvDate;

    @NonNull
    public final TextView tvName;

    private ItemHomePreVideoBinding(@NonNull LinearLayout linearLayout, @NonNull ImageTextView imageTextView, @NonNull ImageView imageView, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.itvDuration = imageTextView;
        this.ivImg = imageView;
        this.rlVideoBottom = relativeLayout;
        this.tvDate = textView;
        this.tvName = textView2;
    }

    @NonNull
    public static ItemHomePreVideoBinding bind(@NonNull View view) {
        int i2 = R.id.itv_duration;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_duration);
        if (imageTextView != null) {
            i2 = R.id.iv_img;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_img);
            if (imageView != null) {
                i2 = R.id.rl_videoBottom;
                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_videoBottom);
                if (relativeLayout != null) {
                    i2 = R.id.tv_date;
                    TextView textView = (TextView) view.findViewById(R.id.tv_date);
                    if (textView != null) {
                        i2 = R.id.tv_name;
                        TextView textView2 = (TextView) view.findViewById(R.id.tv_name);
                        if (textView2 != null) {
                            return new ItemHomePreVideoBinding((LinearLayout) view, imageTextView, imageView, relativeLayout, textView, textView2);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemHomePreVideoBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemHomePreVideoBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_home_pre_video, viewGroup, false);
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
