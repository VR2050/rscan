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
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoGroupItemBinding implements ViewBinding {

    @NonNull
    public final ImageView ivImg;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvPostdetailNickname;

    private VideoGroupItemBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.ivImg = imageView;
        this.tvDesc = textView;
        this.tvName = textView2;
        this.tvPostdetailNickname = textView3;
    }

    @NonNull
    public static VideoGroupItemBinding bind(@NonNull View view) {
        int i2 = R.id.iv_img;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_img);
        if (imageView != null) {
            i2 = R.id.tv_desc;
            TextView textView = (TextView) view.findViewById(R.id.tv_desc);
            if (textView != null) {
                i2 = R.id.tv_name;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_name);
                if (textView2 != null) {
                    i2 = R.id.tv_postdetail_nickname;
                    TextView textView3 = (TextView) view.findViewById(R.id.tv_postdetail_nickname);
                    if (textView3 != null) {
                        return new VideoGroupItemBinding((LinearLayout) view, imageView, textView, textView2, textView3);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static VideoGroupItemBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoGroupItemBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_group_item, viewGroup, false);
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
