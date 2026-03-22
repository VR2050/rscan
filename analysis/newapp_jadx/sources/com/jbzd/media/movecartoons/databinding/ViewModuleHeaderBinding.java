package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.p396ui.index.view.BloodColorText;
import com.jbzd.media.movecartoons.view.RecyclerViewAtViewPager2;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.MarqueeTextView;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class ViewModuleHeaderBinding implements ViewBinding {

    @NonNull
    public final RecyclerViewAtViewPager2 banner2;

    @NonNull
    public final Banner bannerVideoItem;

    @NonNull
    public final ScaleRelativeLayout bannerView;

    @NonNull
    public final ImageTextView itvHeaderMore;

    @NonNull
    public final TextView itvMore;

    @NonNull
    public final ImageView ivModulenameLeft;

    @NonNull
    public final LinearLayout llModuleHeader;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvListFunction;

    @NonNull
    public final BloodColorText tvTitleModule;

    @NonNull
    public final BloodColorText tvTitleModuleTips;

    @NonNull
    public final MarqueeTextView tvUserNewTipsVideo;

    private ViewModuleHeaderBinding(@NonNull LinearLayout linearLayout, @NonNull RecyclerViewAtViewPager2 recyclerViewAtViewPager2, @NonNull Banner banner, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull ImageTextView imageTextView, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull RecyclerView recyclerView, @NonNull BloodColorText bloodColorText, @NonNull BloodColorText bloodColorText2, @NonNull MarqueeTextView marqueeTextView) {
        this.rootView = linearLayout;
        this.banner2 = recyclerViewAtViewPager2;
        this.bannerVideoItem = banner;
        this.bannerView = scaleRelativeLayout;
        this.itvHeaderMore = imageTextView;
        this.itvMore = textView;
        this.ivModulenameLeft = imageView;
        this.llModuleHeader = linearLayout2;
        this.rvListFunction = recyclerView;
        this.tvTitleModule = bloodColorText;
        this.tvTitleModuleTips = bloodColorText2;
        this.tvUserNewTipsVideo = marqueeTextView;
    }

    @NonNull
    public static ViewModuleHeaderBinding bind(@NonNull View view) {
        int i2 = R.id.banner2;
        RecyclerViewAtViewPager2 recyclerViewAtViewPager2 = (RecyclerViewAtViewPager2) view.findViewById(R.id.banner2);
        if (recyclerViewAtViewPager2 != null) {
            i2 = R.id.banner_video_item;
            Banner banner = (Banner) view.findViewById(R.id.banner_video_item);
            if (banner != null) {
                i2 = R.id.banner_view;
                ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.banner_view);
                if (scaleRelativeLayout != null) {
                    i2 = R.id.itv_header_more;
                    ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_header_more);
                    if (imageTextView != null) {
                        i2 = R.id.itv_more;
                        TextView textView = (TextView) view.findViewById(R.id.itv_more);
                        if (textView != null) {
                            i2 = R.id.iv_modulename_left;
                            ImageView imageView = (ImageView) view.findViewById(R.id.iv_modulename_left);
                            if (imageView != null) {
                                i2 = R.id.ll_module_header;
                                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_module_header);
                                if (linearLayout != null) {
                                    i2 = R.id.rv_list_function;
                                    RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_list_function);
                                    if (recyclerView != null) {
                                        i2 = R.id.tv_title_module;
                                        BloodColorText bloodColorText = (BloodColorText) view.findViewById(R.id.tv_title_module);
                                        if (bloodColorText != null) {
                                            i2 = R.id.tv_title_module_tips;
                                            BloodColorText bloodColorText2 = (BloodColorText) view.findViewById(R.id.tv_title_module_tips);
                                            if (bloodColorText2 != null) {
                                                i2 = R.id.tv_user_new_tips_video;
                                                MarqueeTextView marqueeTextView = (MarqueeTextView) view.findViewById(R.id.tv_user_new_tips_video);
                                                if (marqueeTextView != null) {
                                                    return new ViewModuleHeaderBinding((LinearLayout) view, recyclerViewAtViewPager2, banner, scaleRelativeLayout, imageTextView, textView, imageView, linearLayout, recyclerView, bloodColorText, bloodColorText2, marqueeTextView);
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
    public static ViewModuleHeaderBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewModuleHeaderBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_module_header, viewGroup, false);
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
