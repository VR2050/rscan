package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class LayoutVideoDetailFlavorBlackBinding implements ViewBinding {

    @NonNull
    public final FrameLayout fragFlavor;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final TextView tvDoCollect;

    @NonNull
    public final TextView tvFlavorName;

    @NonNull
    public final TextView tvLookMore;

    private LayoutVideoDetailFlavorBlackBinding(@NonNull RelativeLayout relativeLayout, @NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = relativeLayout;
        this.fragFlavor = frameLayout;
        this.ivClose = imageView;
        this.tvDoCollect = textView;
        this.tvFlavorName = textView2;
        this.tvLookMore = textView3;
    }

    @NonNull
    public static LayoutVideoDetailFlavorBlackBinding bind(@NonNull View view) {
        int i2 = R.id.frag_flavor;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_flavor);
        if (frameLayout != null) {
            i2 = R.id.iv_close;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
            if (imageView != null) {
                i2 = R.id.tv_doCollect;
                TextView textView = (TextView) view.findViewById(R.id.tv_doCollect);
                if (textView != null) {
                    i2 = R.id.tv_flavorName;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_flavorName);
                    if (textView2 != null) {
                        i2 = R.id.tv_lookMore;
                        TextView textView3 = (TextView) view.findViewById(R.id.tv_lookMore);
                        if (textView3 != null) {
                            return new LayoutVideoDetailFlavorBlackBinding((RelativeLayout) view, frameLayout, imageView, textView, textView2, textView3);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutVideoDetailFlavorBlackBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutVideoDetailFlavorBlackBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.layout_video_detail_flavor_black, viewGroup, false);
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
