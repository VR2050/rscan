package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActBuyBinding implements ViewBinding {

    @NonNull
    public final ShapeableImageView imgAvatar;

    @NonNull
    public final ConstraintLayout layoutVipHeader;

    @NonNull
    public final LinearLayout llBottomVip;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final SlidingTabLayout tabMembershipCard;

    @NonNull
    public final TextView tvExchangeVip;

    @NonNull
    public final TextView tvOpenVip;

    @NonNull
    public final TextView txtName;

    @NonNull
    public final TextView txtVipTag;

    @NonNull
    public final ViewPager viewpagerVipCard;

    private ActBuyBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull ConstraintLayout constraintLayout2, @NonNull LinearLayout linearLayout, @NonNull SlidingTabLayout slidingTabLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull ViewPager viewPager) {
        this.rootView = constraintLayout;
        this.imgAvatar = shapeableImageView;
        this.layoutVipHeader = constraintLayout2;
        this.llBottomVip = linearLayout;
        this.tabMembershipCard = slidingTabLayout;
        this.tvExchangeVip = textView;
        this.tvOpenVip = textView2;
        this.txtName = textView3;
        this.txtVipTag = textView4;
        this.viewpagerVipCard = viewPager;
    }

    @NonNull
    public static ActBuyBinding bind(@NonNull View view) {
        int i2 = R.id.img_avatar;
        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.img_avatar);
        if (shapeableImageView != null) {
            i2 = R.id.layout_vip_header;
            ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.layout_vip_header);
            if (constraintLayout != null) {
                i2 = R.id.ll_bottom_vip;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_bottom_vip);
                if (linearLayout != null) {
                    i2 = R.id.tab_membership_card;
                    SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tab_membership_card);
                    if (slidingTabLayout != null) {
                        i2 = R.id.tv_exchange_vip;
                        TextView textView = (TextView) view.findViewById(R.id.tv_exchange_vip);
                        if (textView != null) {
                            i2 = R.id.tv_open_vip;
                            TextView textView2 = (TextView) view.findViewById(R.id.tv_open_vip);
                            if (textView2 != null) {
                                i2 = R.id.txt_name;
                                TextView textView3 = (TextView) view.findViewById(R.id.txt_name);
                                if (textView3 != null) {
                                    i2 = R.id.txt_vip_tag;
                                    TextView textView4 = (TextView) view.findViewById(R.id.txt_vip_tag);
                                    if (textView4 != null) {
                                        i2 = R.id.viewpager_vip_card;
                                        ViewPager viewPager = (ViewPager) view.findViewById(R.id.viewpager_vip_card);
                                        if (viewPager != null) {
                                            return new ActBuyBinding((ConstraintLayout) view, shapeableImageView, constraintLayout, linearLayout, slidingTabLayout, textView, textView2, textView3, textView4, viewPager);
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
    public static ActBuyBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActBuyBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_buy, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ConstraintLayout getRoot() {
        return this.rootView;
    }
}
