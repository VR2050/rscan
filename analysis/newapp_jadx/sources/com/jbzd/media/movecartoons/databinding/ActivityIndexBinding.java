package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RadioGroup;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.NoScrollViewPager;
import com.jbzd.media.movecartoons.view.text.MyRadioButton;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class ActivityIndexBinding implements ViewBinding {

    @NonNull
    public final Banner bannerIndexItem;

    @NonNull
    public final ImageView close;

    @NonNull
    public final LinearLayout llHomeAd;

    @NonNull
    public final FloatingWindowLayoutBinding llToolsLayout;

    @NonNull
    public final MyRadioButton radAi;

    @NonNull
    public final MyRadioButton radBcy;

    @NonNull
    public final MyRadioButton radCommunity;

    @NonNull
    public final MyRadioButton radDark;

    @NonNull
    public final MyRadioButton radMine;

    @NonNull
    public final MyRadioButton radVideo;

    @NonNull
    public final RadioGroup rgNav;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final View vDivider;

    @NonNull
    public final NoScrollViewPager vpContent;

    private ActivityIndexBinding(@NonNull RelativeLayout relativeLayout, @NonNull Banner banner, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout, @NonNull FloatingWindowLayoutBinding floatingWindowLayoutBinding, @NonNull MyRadioButton myRadioButton, @NonNull MyRadioButton myRadioButton2, @NonNull MyRadioButton myRadioButton3, @NonNull MyRadioButton myRadioButton4, @NonNull MyRadioButton myRadioButton5, @NonNull MyRadioButton myRadioButton6, @NonNull RadioGroup radioGroup, @NonNull View view, @NonNull NoScrollViewPager noScrollViewPager) {
        this.rootView = relativeLayout;
        this.bannerIndexItem = banner;
        this.close = imageView;
        this.llHomeAd = linearLayout;
        this.llToolsLayout = floatingWindowLayoutBinding;
        this.radAi = myRadioButton;
        this.radBcy = myRadioButton2;
        this.radCommunity = myRadioButton3;
        this.radDark = myRadioButton4;
        this.radMine = myRadioButton5;
        this.radVideo = myRadioButton6;
        this.rgNav = radioGroup;
        this.vDivider = view;
        this.vpContent = noScrollViewPager;
    }

    @NonNull
    public static ActivityIndexBinding bind(@NonNull View view) {
        int i2 = R.id.banner_index_item;
        Banner banner = (Banner) view.findViewById(R.id.banner_index_item);
        if (banner != null) {
            i2 = R.id.close;
            ImageView imageView = (ImageView) view.findViewById(R.id.close);
            if (imageView != null) {
                i2 = R.id.ll_home_ad;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_home_ad);
                if (linearLayout != null) {
                    i2 = R.id.ll_tools_layout;
                    View findViewById = view.findViewById(R.id.ll_tools_layout);
                    if (findViewById != null) {
                        FloatingWindowLayoutBinding bind = FloatingWindowLayoutBinding.bind(findViewById);
                        i2 = R.id.rad_ai;
                        MyRadioButton myRadioButton = (MyRadioButton) view.findViewById(R.id.rad_ai);
                        if (myRadioButton != null) {
                            i2 = R.id.rad_bcy;
                            MyRadioButton myRadioButton2 = (MyRadioButton) view.findViewById(R.id.rad_bcy);
                            if (myRadioButton2 != null) {
                                i2 = R.id.rad_community;
                                MyRadioButton myRadioButton3 = (MyRadioButton) view.findViewById(R.id.rad_community);
                                if (myRadioButton3 != null) {
                                    i2 = R.id.rad_dark;
                                    MyRadioButton myRadioButton4 = (MyRadioButton) view.findViewById(R.id.rad_dark);
                                    if (myRadioButton4 != null) {
                                        i2 = R.id.rad_mine;
                                        MyRadioButton myRadioButton5 = (MyRadioButton) view.findViewById(R.id.rad_mine);
                                        if (myRadioButton5 != null) {
                                            i2 = R.id.rad_video;
                                            MyRadioButton myRadioButton6 = (MyRadioButton) view.findViewById(R.id.rad_video);
                                            if (myRadioButton6 != null) {
                                                i2 = R.id.rg_nav;
                                                RadioGroup radioGroup = (RadioGroup) view.findViewById(R.id.rg_nav);
                                                if (radioGroup != null) {
                                                    i2 = R.id.v_divider;
                                                    View findViewById2 = view.findViewById(R.id.v_divider);
                                                    if (findViewById2 != null) {
                                                        i2 = R.id.vp_content;
                                                        NoScrollViewPager noScrollViewPager = (NoScrollViewPager) view.findViewById(R.id.vp_content);
                                                        if (noScrollViewPager != null) {
                                                            return new ActivityIndexBinding((RelativeLayout) view, banner, imageView, linearLayout, bind, myRadioButton, myRadioButton2, myRadioButton3, myRadioButton4, myRadioButton5, myRadioButton6, radioGroup, findViewById2, noScrollViewPager);
                                                        }
                                                    }
                                                }
                                            }
                                        }
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
    public static ActivityIndexBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActivityIndexBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.activity_index, viewGroup, false);
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
