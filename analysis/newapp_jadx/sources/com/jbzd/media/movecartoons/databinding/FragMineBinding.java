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
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Group;
import androidx.core.widget.NestedScrollView;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.drake.brv.PageRefreshLayout;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class FragMineBinding implements ViewBinding {

    @NonNull
    public final Banner bannerMine;

    @NonNull
    public final ScaleRelativeLayout bannerParent;

    @NonNull
    public final TextView beVip;

    @NonNull
    public final RecyclerView gridView;

    @NonNull
    public final ImageTextView itvSignMine;

    @NonNull
    public final ImageView ivIcon;

    @NonNull
    public final TextView ivSetting;

    @NonNull
    public final ImageView ivSharePromotion;

    @NonNull
    public final ShapeableImageView ivUserAvater;

    @NonNull
    public final ImageView ivUserSex;

    @NonNull
    public final ImageView ivViptipsShow;

    @NonNull
    public final ConstraintLayout layoutUserInfo;

    @NonNull
    public final RelativeLayout llAvtar;

    @NonNull
    public final LinearLayout llMembercenterWallet;

    @NonNull
    public final LinearLayout llServiceApplist;

    @NonNull
    public final LinearLayout llServiceGroup;

    @NonNull
    public final LinearLayout llServiceOnline;

    @NonNull
    public final RelativeLayout llVipInfos;

    @NonNull
    public final PageRefreshLayout mineRefresh;

    @NonNull
    public final RelativeLayout rlGoRecharge;

    @NonNull
    public final RelativeLayout rlGoVip;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvAds;

    @NonNull
    public final RecyclerView rvMineOne;

    @NonNull
    public final RecyclerView rvMineThree;

    @NonNull
    public final RecyclerView rvMineTwo;

    @NonNull
    public final NestedScrollView scrollBottom;

    @NonNull
    public final TextView tvBalance;

    @NonNull
    public final TextView tvBalanceTitle;

    @NonNull
    public final TextView tvBottomitemName;

    @NonNull
    public final TextView tvGroupEndtime;

    @NonNull
    public final TextView tvGroupName;

    @NonNull
    public final TextView tvGroupTitle;

    @NonNull
    public final TextView tvNameNew;

    @NonNull
    public final TextView tvNumNew;

    @NonNull
    public final TextView tvVersionName;

    @NonNull
    public final Group vipGroupIds;

    private FragMineBinding(@NonNull LinearLayout linearLayout, @NonNull Banner banner, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull TextView textView, @NonNull RecyclerView recyclerView, @NonNull ImageTextView imageTextView, @NonNull ImageView imageView, @NonNull TextView textView2, @NonNull ImageView imageView2, @NonNull ShapeableImageView shapeableImageView, @NonNull ImageView imageView3, @NonNull ImageView imageView4, @NonNull ConstraintLayout constraintLayout, @NonNull RelativeLayout relativeLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull RelativeLayout relativeLayout2, @NonNull PageRefreshLayout pageRefreshLayout, @NonNull RelativeLayout relativeLayout3, @NonNull RelativeLayout relativeLayout4, @NonNull RecyclerView recyclerView2, @NonNull RecyclerView recyclerView3, @NonNull RecyclerView recyclerView4, @NonNull RecyclerView recyclerView5, @NonNull NestedScrollView nestedScrollView, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8, @NonNull TextView textView9, @NonNull TextView textView10, @NonNull TextView textView11, @NonNull Group group) {
        this.rootView = linearLayout;
        this.bannerMine = banner;
        this.bannerParent = scaleRelativeLayout;
        this.beVip = textView;
        this.gridView = recyclerView;
        this.itvSignMine = imageTextView;
        this.ivIcon = imageView;
        this.ivSetting = textView2;
        this.ivSharePromotion = imageView2;
        this.ivUserAvater = shapeableImageView;
        this.ivUserSex = imageView3;
        this.ivViptipsShow = imageView4;
        this.layoutUserInfo = constraintLayout;
        this.llAvtar = relativeLayout;
        this.llMembercenterWallet = linearLayout2;
        this.llServiceApplist = linearLayout3;
        this.llServiceGroup = linearLayout4;
        this.llServiceOnline = linearLayout5;
        this.llVipInfos = relativeLayout2;
        this.mineRefresh = pageRefreshLayout;
        this.rlGoRecharge = relativeLayout3;
        this.rlGoVip = relativeLayout4;
        this.rvAds = recyclerView2;
        this.rvMineOne = recyclerView3;
        this.rvMineThree = recyclerView4;
        this.rvMineTwo = recyclerView5;
        this.scrollBottom = nestedScrollView;
        this.tvBalance = textView3;
        this.tvBalanceTitle = textView4;
        this.tvBottomitemName = textView5;
        this.tvGroupEndtime = textView6;
        this.tvGroupName = textView7;
        this.tvGroupTitle = textView8;
        this.tvNameNew = textView9;
        this.tvNumNew = textView10;
        this.tvVersionName = textView11;
        this.vipGroupIds = group;
    }

    @NonNull
    public static FragMineBinding bind(@NonNull View view) {
        int i2 = R.id.banner_mine;
        Banner banner = (Banner) view.findViewById(R.id.banner_mine);
        if (banner != null) {
            i2 = R.id.banner_parent;
            ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.banner_parent);
            if (scaleRelativeLayout != null) {
                i2 = R.id.be_vip;
                TextView textView = (TextView) view.findViewById(R.id.be_vip);
                if (textView != null) {
                    i2 = R.id.grid_view;
                    RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.grid_view);
                    if (recyclerView != null) {
                        i2 = R.id.itv_sign_mine;
                        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_sign_mine);
                        if (imageTextView != null) {
                            i2 = R.id.iv_icon;
                            ImageView imageView = (ImageView) view.findViewById(R.id.iv_icon);
                            if (imageView != null) {
                                i2 = R.id.iv_setting;
                                TextView textView2 = (TextView) view.findViewById(R.id.iv_setting);
                                if (textView2 != null) {
                                    i2 = R.id.iv_share_promotion;
                                    ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_share_promotion);
                                    if (imageView2 != null) {
                                        i2 = R.id.iv_user_avater;
                                        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_user_avater);
                                        if (shapeableImageView != null) {
                                            i2 = R.id.iv_user_sex;
                                            ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_user_sex);
                                            if (imageView3 != null) {
                                                i2 = R.id.iv_viptips_show;
                                                ImageView imageView4 = (ImageView) view.findViewById(R.id.iv_viptips_show);
                                                if (imageView4 != null) {
                                                    i2 = R.id.layout_user_info;
                                                    ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.layout_user_info);
                                                    if (constraintLayout != null) {
                                                        i2 = R.id.ll_avtar;
                                                        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.ll_avtar);
                                                        if (relativeLayout != null) {
                                                            i2 = R.id.ll_membercenter_wallet;
                                                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_membercenter_wallet);
                                                            if (linearLayout != null) {
                                                                i2 = R.id.ll_service_applist;
                                                                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_service_applist);
                                                                if (linearLayout2 != null) {
                                                                    i2 = R.id.ll_service_group;
                                                                    LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_service_group);
                                                                    if (linearLayout3 != null) {
                                                                        i2 = R.id.ll_service_online;
                                                                        LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_service_online);
                                                                        if (linearLayout4 != null) {
                                                                            i2 = R.id.ll_vip_infos;
                                                                            RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.ll_vip_infos);
                                                                            if (relativeLayout2 != null) {
                                                                                i2 = R.id.mine_refresh;
                                                                                PageRefreshLayout pageRefreshLayout = (PageRefreshLayout) view.findViewById(R.id.mine_refresh);
                                                                                if (pageRefreshLayout != null) {
                                                                                    i2 = R.id.rl_goRecharge;
                                                                                    RelativeLayout relativeLayout3 = (RelativeLayout) view.findViewById(R.id.rl_goRecharge);
                                                                                    if (relativeLayout3 != null) {
                                                                                        i2 = R.id.rl_goVip;
                                                                                        RelativeLayout relativeLayout4 = (RelativeLayout) view.findViewById(R.id.rl_goVip);
                                                                                        if (relativeLayout4 != null) {
                                                                                            i2 = R.id.rvAds;
                                                                                            RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rvAds);
                                                                                            if (recyclerView2 != null) {
                                                                                                i2 = R.id.rv_mine_one;
                                                                                                RecyclerView recyclerView3 = (RecyclerView) view.findViewById(R.id.rv_mine_one);
                                                                                                if (recyclerView3 != null) {
                                                                                                    i2 = R.id.rv_mine_three;
                                                                                                    RecyclerView recyclerView4 = (RecyclerView) view.findViewById(R.id.rv_mine_three);
                                                                                                    if (recyclerView4 != null) {
                                                                                                        i2 = R.id.rv_mine_two;
                                                                                                        RecyclerView recyclerView5 = (RecyclerView) view.findViewById(R.id.rv_mine_two);
                                                                                                        if (recyclerView5 != null) {
                                                                                                            i2 = R.id.scroll_bottom;
                                                                                                            NestedScrollView nestedScrollView = (NestedScrollView) view.findViewById(R.id.scroll_bottom);
                                                                                                            if (nestedScrollView != null) {
                                                                                                                i2 = R.id.tv_balance;
                                                                                                                TextView textView3 = (TextView) view.findViewById(R.id.tv_balance);
                                                                                                                if (textView3 != null) {
                                                                                                                    i2 = R.id.tv_balance_title;
                                                                                                                    TextView textView4 = (TextView) view.findViewById(R.id.tv_balance_title);
                                                                                                                    if (textView4 != null) {
                                                                                                                        i2 = R.id.tv_bottomitem_name;
                                                                                                                        TextView textView5 = (TextView) view.findViewById(R.id.tv_bottomitem_name);
                                                                                                                        if (textView5 != null) {
                                                                                                                            i2 = R.id.tv_group_endtime;
                                                                                                                            TextView textView6 = (TextView) view.findViewById(R.id.tv_group_endtime);
                                                                                                                            if (textView6 != null) {
                                                                                                                                i2 = R.id.tv_group_name;
                                                                                                                                TextView textView7 = (TextView) view.findViewById(R.id.tv_group_name);
                                                                                                                                if (textView7 != null) {
                                                                                                                                    i2 = R.id.tv_groupTitle;
                                                                                                                                    TextView textView8 = (TextView) view.findViewById(R.id.tv_groupTitle);
                                                                                                                                    if (textView8 != null) {
                                                                                                                                        i2 = R.id.tv_name_new;
                                                                                                                                        TextView textView9 = (TextView) view.findViewById(R.id.tv_name_new);
                                                                                                                                        if (textView9 != null) {
                                                                                                                                            i2 = R.id.tv_num_new;
                                                                                                                                            TextView textView10 = (TextView) view.findViewById(R.id.tv_num_new);
                                                                                                                                            if (textView10 != null) {
                                                                                                                                                i2 = R.id.tv_version_name;
                                                                                                                                                TextView textView11 = (TextView) view.findViewById(R.id.tv_version_name);
                                                                                                                                                if (textView11 != null) {
                                                                                                                                                    i2 = R.id.vip_group_ids;
                                                                                                                                                    Group group = (Group) view.findViewById(R.id.vip_group_ids);
                                                                                                                                                    if (group != null) {
                                                                                                                                                        return new FragMineBinding((LinearLayout) view, banner, scaleRelativeLayout, textView, recyclerView, imageTextView, imageView, textView2, imageView2, shapeableImageView, imageView3, imageView4, constraintLayout, relativeLayout, linearLayout, linearLayout2, linearLayout3, linearLayout4, relativeLayout2, pageRefreshLayout, relativeLayout3, relativeLayout4, recyclerView2, recyclerView3, recyclerView4, recyclerView5, nestedScrollView, textView3, textView4, textView5, textView6, textView7, textView8, textView9, textView10, textView11, group);
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
    public static FragMineBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragMineBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_mine, viewGroup, false);
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
