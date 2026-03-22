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
import androidx.appcompat.widget.AppCompatTextView;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragPostabsingleChildBinding implements ViewBinding {

    @NonNull
    public final ImageView imgTanotSingleimg;

    @NonNull
    public final ImageView imgTanotTwoimgLeft;

    @NonNull
    public final ImageView imgTanotTwoimgRight;

    @NonNull
    public final ImageTextView itvCommunityDiscuss;

    @NonNull
    public final ImageTextView itvCommunityLikes;

    @NonNull
    public final ImageTextView itvCommunityWatchtimes;

    @NonNull
    public final ImageTextView itvDislike;

    @NonNull
    public final TextView itvMicrotanotDetailFollow;

    @NonNull
    public final ImageTextView itvMicrotanotWantsee;

    @NonNull
    public final ImageTextView itvShareCommunity;

    @NonNull
    public final ImageView ivCommunityThree;

    @NonNull
    public final ImageView ivCommunityThreevideo;

    @NonNull
    public final ImageView ivCreaterType;

    @NonNull
    public final ImageView ivPostdetailTwoType;

    @NonNull
    public final CircleImageView ivUserfollowAvatar;

    @NonNull
    public final ImageView llCommunityImgOneleft;

    @NonNull
    public final ImageView llCommunityImgOneright;

    @NonNull
    public final LinearLayout llCommunityImgOnethree;

    @NonNull
    public final LinearLayout llCommunityImgOnetwo;

    @NonNull
    public final ImageView llCommunityImgTwolft;

    @NonNull
    public final ImageView llCommunityImgTworight;

    @NonNull
    public final LinearLayout llMicrotanotItem;

    @NonNull
    public final LinearLayout llMicrotanotUserrow;

    @NonNull
    public final LinearLayout llMicrotnaotdetailMsgbottomTools;

    @NonNull
    public final LinearLayout llTanotSingleimg;

    @NonNull
    public final LinearLayout llTanotSingleimgTwo;

    @NonNull
    public final RelativeLayout rlWantsee;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvInner;

    @NonNull
    public final RecyclerView rvTag;

    @NonNull
    public final TextView tvCommunityImgcount;

    @NonNull
    public final AppCompatTextView tvCommunityTitle;

    @NonNull
    public final TextView tvPostCreatedAt;

    @NonNull
    public final TextView tvPostdetailNickname;

    @NonNull
    public final TextView tvPosthomeContent;

    @NonNull
    public final TextView tvReward;

    private FragPostabsingleChildBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4, @NonNull TextView textView, @NonNull ImageTextView imageTextView5, @NonNull ImageTextView imageTextView6, @NonNull ImageView imageView4, @NonNull ImageView imageView5, @NonNull ImageView imageView6, @NonNull ImageView imageView7, @NonNull CircleImageView circleImageView, @NonNull ImageView imageView8, @NonNull ImageView imageView9, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull ImageView imageView10, @NonNull ImageView imageView11, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull LinearLayout linearLayout6, @NonNull LinearLayout linearLayout7, @NonNull LinearLayout linearLayout8, @NonNull RelativeLayout relativeLayout, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull TextView textView2, @NonNull AppCompatTextView appCompatTextView, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6) {
        this.rootView = linearLayout;
        this.imgTanotSingleimg = imageView;
        this.imgTanotTwoimgLeft = imageView2;
        this.imgTanotTwoimgRight = imageView3;
        this.itvCommunityDiscuss = imageTextView;
        this.itvCommunityLikes = imageTextView2;
        this.itvCommunityWatchtimes = imageTextView3;
        this.itvDislike = imageTextView4;
        this.itvMicrotanotDetailFollow = textView;
        this.itvMicrotanotWantsee = imageTextView5;
        this.itvShareCommunity = imageTextView6;
        this.ivCommunityThree = imageView4;
        this.ivCommunityThreevideo = imageView5;
        this.ivCreaterType = imageView6;
        this.ivPostdetailTwoType = imageView7;
        this.ivUserfollowAvatar = circleImageView;
        this.llCommunityImgOneleft = imageView8;
        this.llCommunityImgOneright = imageView9;
        this.llCommunityImgOnethree = linearLayout2;
        this.llCommunityImgOnetwo = linearLayout3;
        this.llCommunityImgTwolft = imageView10;
        this.llCommunityImgTworight = imageView11;
        this.llMicrotanotItem = linearLayout4;
        this.llMicrotanotUserrow = linearLayout5;
        this.llMicrotnaotdetailMsgbottomTools = linearLayout6;
        this.llTanotSingleimg = linearLayout7;
        this.llTanotSingleimgTwo = linearLayout8;
        this.rlWantsee = relativeLayout;
        this.rvInner = recyclerView;
        this.rvTag = recyclerView2;
        this.tvCommunityImgcount = textView2;
        this.tvCommunityTitle = appCompatTextView;
        this.tvPostCreatedAt = textView3;
        this.tvPostdetailNickname = textView4;
        this.tvPosthomeContent = textView5;
        this.tvReward = textView6;
    }

    @NonNull
    public static FragPostabsingleChildBinding bind(@NonNull View view) {
        int i2 = R.id.img_tanot_singleimg;
        ImageView imageView = (ImageView) view.findViewById(R.id.img_tanot_singleimg);
        if (imageView != null) {
            i2 = R.id.img_tanot_twoimg_left;
            ImageView imageView2 = (ImageView) view.findViewById(R.id.img_tanot_twoimg_left);
            if (imageView2 != null) {
                i2 = R.id.img_tanot_twoimg_right;
                ImageView imageView3 = (ImageView) view.findViewById(R.id.img_tanot_twoimg_right);
                if (imageView3 != null) {
                    i2 = R.id.itv_community_discuss;
                    ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_community_discuss);
                    if (imageTextView != null) {
                        i2 = R.id.itv_community_likes;
                        ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_community_likes);
                        if (imageTextView2 != null) {
                            i2 = R.id.itv_community_watchtimes;
                            ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.itv_community_watchtimes);
                            if (imageTextView3 != null) {
                                i2 = R.id.itv_dislike;
                                ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.itv_dislike);
                                if (imageTextView4 != null) {
                                    i2 = R.id.itv_microtanot_detail_follow;
                                    TextView textView = (TextView) view.findViewById(R.id.itv_microtanot_detail_follow);
                                    if (textView != null) {
                                        i2 = R.id.itv_microtanot_wantsee;
                                        ImageTextView imageTextView5 = (ImageTextView) view.findViewById(R.id.itv_microtanot_wantsee);
                                        if (imageTextView5 != null) {
                                            i2 = R.id.itv_share_community;
                                            ImageTextView imageTextView6 = (ImageTextView) view.findViewById(R.id.itv_share_community);
                                            if (imageTextView6 != null) {
                                                i2 = R.id.iv_community_three;
                                                ImageView imageView4 = (ImageView) view.findViewById(R.id.iv_community_three);
                                                if (imageView4 != null) {
                                                    i2 = R.id.iv_community_threevideo;
                                                    ImageView imageView5 = (ImageView) view.findViewById(R.id.iv_community_threevideo);
                                                    if (imageView5 != null) {
                                                        i2 = R.id.iv_creater_type;
                                                        ImageView imageView6 = (ImageView) view.findViewById(R.id.iv_creater_type);
                                                        if (imageView6 != null) {
                                                            i2 = R.id.iv_postdetail_two_type;
                                                            ImageView imageView7 = (ImageView) view.findViewById(R.id.iv_postdetail_two_type);
                                                            if (imageView7 != null) {
                                                                i2 = R.id.iv_userfollow_avatar;
                                                                CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.iv_userfollow_avatar);
                                                                if (circleImageView != null) {
                                                                    i2 = R.id.ll_community_img_oneleft;
                                                                    ImageView imageView8 = (ImageView) view.findViewById(R.id.ll_community_img_oneleft);
                                                                    if (imageView8 != null) {
                                                                        i2 = R.id.ll_community_img_oneright;
                                                                        ImageView imageView9 = (ImageView) view.findViewById(R.id.ll_community_img_oneright);
                                                                        if (imageView9 != null) {
                                                                            i2 = R.id.ll_community_img_onethree;
                                                                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_community_img_onethree);
                                                                            if (linearLayout != null) {
                                                                                i2 = R.id.ll_community_img_onetwo;
                                                                                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_community_img_onetwo);
                                                                                if (linearLayout2 != null) {
                                                                                    i2 = R.id.ll_community_img_twolft;
                                                                                    ImageView imageView10 = (ImageView) view.findViewById(R.id.ll_community_img_twolft);
                                                                                    if (imageView10 != null) {
                                                                                        i2 = R.id.ll_community_img_tworight;
                                                                                        ImageView imageView11 = (ImageView) view.findViewById(R.id.ll_community_img_tworight);
                                                                                        if (imageView11 != null) {
                                                                                            i2 = R.id.ll_microtanot_item;
                                                                                            LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_microtanot_item);
                                                                                            if (linearLayout3 != null) {
                                                                                                i2 = R.id.ll_microtanot_userrow;
                                                                                                LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_microtanot_userrow);
                                                                                                if (linearLayout4 != null) {
                                                                                                    i2 = R.id.ll_microtnaotdetail_msgbottom_tools;
                                                                                                    LinearLayout linearLayout5 = (LinearLayout) view.findViewById(R.id.ll_microtnaotdetail_msgbottom_tools);
                                                                                                    if (linearLayout5 != null) {
                                                                                                        i2 = R.id.ll_tanot_singleimg;
                                                                                                        LinearLayout linearLayout6 = (LinearLayout) view.findViewById(R.id.ll_tanot_singleimg);
                                                                                                        if (linearLayout6 != null) {
                                                                                                            i2 = R.id.ll_tanot_singleimg_two;
                                                                                                            LinearLayout linearLayout7 = (LinearLayout) view.findViewById(R.id.ll_tanot_singleimg_two);
                                                                                                            if (linearLayout7 != null) {
                                                                                                                i2 = R.id.rl_wantsee;
                                                                                                                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_wantsee);
                                                                                                                if (relativeLayout != null) {
                                                                                                                    i2 = R.id.rv_inner;
                                                                                                                    RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_inner);
                                                                                                                    if (recyclerView != null) {
                                                                                                                        i2 = R.id.rv_tag;
                                                                                                                        RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_tag);
                                                                                                                        if (recyclerView2 != null) {
                                                                                                                            i2 = R.id.tv_community_imgcount;
                                                                                                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_community_imgcount);
                                                                                                                            if (textView2 != null) {
                                                                                                                                i2 = R.id.tv_community_title;
                                                                                                                                AppCompatTextView appCompatTextView = (AppCompatTextView) view.findViewById(R.id.tv_community_title);
                                                                                                                                if (appCompatTextView != null) {
                                                                                                                                    i2 = R.id.tv_post_created_at;
                                                                                                                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_post_created_at);
                                                                                                                                    if (textView3 != null) {
                                                                                                                                        i2 = R.id.tv_postdetail_nickname;
                                                                                                                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_postdetail_nickname);
                                                                                                                                        if (textView4 != null) {
                                                                                                                                            i2 = R.id.tv_posthome_content;
                                                                                                                                            TextView textView5 = (TextView) view.findViewById(R.id.tv_posthome_content);
                                                                                                                                            if (textView5 != null) {
                                                                                                                                                i2 = R.id.tvReward;
                                                                                                                                                TextView textView6 = (TextView) view.findViewById(R.id.tvReward);
                                                                                                                                                if (textView6 != null) {
                                                                                                                                                    return new FragPostabsingleChildBinding((LinearLayout) view, imageView, imageView2, imageView3, imageTextView, imageTextView2, imageTextView3, imageTextView4, textView, imageTextView5, imageTextView6, imageView4, imageView5, imageView6, imageView7, circleImageView, imageView8, imageView9, linearLayout, linearLayout2, imageView10, imageView11, linearLayout3, linearLayout4, linearLayout5, linearLayout6, linearLayout7, relativeLayout, recyclerView, recyclerView2, textView2, appCompatTextView, textView3, textView4, textView5, textView6);
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
    public static FragPostabsingleChildBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragPostabsingleChildBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_postabsingle_child, viewGroup, false);
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
