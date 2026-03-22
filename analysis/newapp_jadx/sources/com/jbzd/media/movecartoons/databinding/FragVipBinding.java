package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.widget.NestedScrollView;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class FragVipBinding implements ViewBinding {

    @NonNull
    public final Banner banner;

    @NonNull
    public final TextView btnExchangeVip;

    @NonNull
    public final TextView btnOpenVip;

    @NonNull
    public final ImageView imgVipRights;

    @NonNull
    public final RecyclerView listPayMethod;

    @NonNull
    public final RecyclerView listVipRights;

    @NonNull
    public final LinearLayout llBottomVip;

    @NonNull
    public final LinearLayout llBottomVipcard;

    @NonNull
    public final LinearLayout llMemberQy;

    @NonNull
    public final LinearLayout llVipPayment;

    @NonNull
    private final NestedScrollView rootView;

    @NonNull
    public final TextView tvService;

    @NonNull
    public final TextView tvVipRights;

    @NonNull
    public final TextView txtChoiceMethod;

    private FragVipBinding(@NonNull NestedScrollView nestedScrollView, @NonNull Banner banner, @NonNull TextView textView, @NonNull TextView textView2, @NonNull ImageView imageView, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5) {
        this.rootView = nestedScrollView;
        this.banner = banner;
        this.btnExchangeVip = textView;
        this.btnOpenVip = textView2;
        this.imgVipRights = imageView;
        this.listPayMethod = recyclerView;
        this.listVipRights = recyclerView2;
        this.llBottomVip = linearLayout;
        this.llBottomVipcard = linearLayout2;
        this.llMemberQy = linearLayout3;
        this.llVipPayment = linearLayout4;
        this.tvService = textView3;
        this.tvVipRights = textView4;
        this.txtChoiceMethod = textView5;
    }

    @NonNull
    public static FragVipBinding bind(@NonNull View view) {
        int i2 = R.id.banner;
        Banner banner = (Banner) view.findViewById(R.id.banner);
        if (banner != null) {
            i2 = R.id.btn_exchange_vip;
            TextView textView = (TextView) view.findViewById(R.id.btn_exchange_vip);
            if (textView != null) {
                i2 = R.id.btn_open_vip;
                TextView textView2 = (TextView) view.findViewById(R.id.btn_open_vip);
                if (textView2 != null) {
                    i2 = R.id.img_vip_rights;
                    ImageView imageView = (ImageView) view.findViewById(R.id.img_vip_rights);
                    if (imageView != null) {
                        i2 = R.id.list_pay_method;
                        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.list_pay_method);
                        if (recyclerView != null) {
                            i2 = R.id.list_vip_rights;
                            RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.list_vip_rights);
                            if (recyclerView2 != null) {
                                i2 = R.id.ll_bottom_vip;
                                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_bottom_vip);
                                if (linearLayout != null) {
                                    i2 = R.id.ll_bottom_vipcard;
                                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_bottom_vipcard);
                                    if (linearLayout2 != null) {
                                        i2 = R.id.ll_member_qy;
                                        LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_member_qy);
                                        if (linearLayout3 != null) {
                                            i2 = R.id.ll_vip_payment;
                                            LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_vip_payment);
                                            if (linearLayout4 != null) {
                                                i2 = R.id.tv_service;
                                                TextView textView3 = (TextView) view.findViewById(R.id.tv_service);
                                                if (textView3 != null) {
                                                    i2 = R.id.tv_vip_rights;
                                                    TextView textView4 = (TextView) view.findViewById(R.id.tv_vip_rights);
                                                    if (textView4 != null) {
                                                        i2 = R.id.txt_choice_method;
                                                        TextView textView5 = (TextView) view.findViewById(R.id.txt_choice_method);
                                                        if (textView5 != null) {
                                                            return new FragVipBinding((NestedScrollView) view, banner, textView, textView2, imageView, recyclerView, recyclerView2, linearLayout, linearLayout2, linearLayout3, linearLayout4, textView3, textView4, textView5);
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
    public static FragVipBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragVipBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_vip, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public NestedScrollView getRoot() {
        return this.rootView;
    }
}
