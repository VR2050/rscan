package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragCommunityBinding implements ViewBinding {

    @NonNull
    public final ImageView imgCommunityPost;

    @NonNull
    public final TextView itvSearch;

    @NonNull
    public final LinearLayout lLayoutBg;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final SlidingTabLayout tabLayout;

    @NonNull
    public final ViewPager vpContent;

    private FragCommunityBinding(@NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull SlidingTabLayout slidingTabLayout, @NonNull ViewPager viewPager) {
        this.rootView = frameLayout;
        this.imgCommunityPost = imageView;
        this.itvSearch = textView;
        this.lLayoutBg = linearLayout;
        this.llTop = linearLayout2;
        this.tabLayout = slidingTabLayout;
        this.vpContent = viewPager;
    }

    @NonNull
    public static FragCommunityBinding bind(@NonNull View view) {
        int i2 = R.id.img_community_post;
        ImageView imageView = (ImageView) view.findViewById(R.id.img_community_post);
        if (imageView != null) {
            i2 = R.id.itv_search;
            TextView textView = (TextView) view.findViewById(R.id.itv_search);
            if (textView != null) {
                i2 = R.id.lLayout_bg;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.lLayout_bg);
                if (linearLayout != null) {
                    i2 = R.id.ll_top;
                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_top);
                    if (linearLayout2 != null) {
                        i2 = R.id.tabLayout;
                        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tabLayout);
                        if (slidingTabLayout != null) {
                            i2 = R.id.vp_content;
                            ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                            if (viewPager != null) {
                                return new FragCommunityBinding((FrameLayout) view, imageView, textView, linearLayout, linearLayout2, slidingTabLayout, viewPager);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragCommunityBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragCommunityBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_community, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
