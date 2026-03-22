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
public final class LayoutVideoDetailGroupBinding implements ViewBinding {

    @NonNull
    public final FrameLayout fragGroup;

    @NonNull
    public final ImageView ivCloseGroup;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final TextView tvDoGroupCollect;

    @NonNull
    public final TextView tvGroupName;

    @NonNull
    public final TextView tvLookGroupMore;

    private LayoutVideoDetailGroupBinding(@NonNull RelativeLayout relativeLayout, @NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = relativeLayout;
        this.fragGroup = frameLayout;
        this.ivCloseGroup = imageView;
        this.tvDoGroupCollect = textView;
        this.tvGroupName = textView2;
        this.tvLookGroupMore = textView3;
    }

    @NonNull
    public static LayoutVideoDetailGroupBinding bind(@NonNull View view) {
        int i2 = R.id.frag_group;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_group);
        if (frameLayout != null) {
            i2 = R.id.iv_closeGroup;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_closeGroup);
            if (imageView != null) {
                i2 = R.id.tv_doGroupCollect;
                TextView textView = (TextView) view.findViewById(R.id.tv_doGroupCollect);
                if (textView != null) {
                    i2 = R.id.tv_groupName;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_groupName);
                    if (textView2 != null) {
                        i2 = R.id.tv_lookGroupMore;
                        TextView textView3 = (TextView) view.findViewById(R.id.tv_lookGroupMore);
                        if (textView3 != null) {
                            return new LayoutVideoDetailGroupBinding((RelativeLayout) view, frameLayout, imageView, textView, textView2, textView3);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutVideoDetailGroupBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutVideoDetailGroupBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.layout_video_detail_group, viewGroup, false);
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
