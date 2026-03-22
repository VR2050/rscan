package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragShowBinding implements ViewBinding {

    @NonNull
    public final ImageView ivSearch;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final ViewPager vpContent;

    private FragShowBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.ivSearch = imageView;
        this.llTop = linearLayout2;
        this.vpContent = viewPager;
    }

    @NonNull
    public static FragShowBinding bind(@NonNull View view) {
        int i2 = R.id.iv_search;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_search);
        if (imageView != null) {
            i2 = R.id.ll_top;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_top);
            if (linearLayout != null) {
                i2 = R.id.vp_content;
                ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                if (viewPager != null) {
                    return new FragShowBinding((LinearLayout) view, imageView, linearLayout, viewPager);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragShowBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragShowBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_show, viewGroup, false);
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
