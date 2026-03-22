package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class ActDarkPlayDetailBinding implements ViewBinding {

    @NonNull
    public final Banner banner;

    @NonNull
    public final ScaleRelativeLayout bannerParent;

    @NonNull
    public final TextView btnMinus;

    @NonNull
    public final TextView btnPlus;

    @NonNull
    public final TextView btnSubmitAichangefaceVideo;

    @NonNull
    public final ConstraintLayout clCertificate;

    @NonNull
    public final ConstraintLayout clService2;

    @NonNull
    public final FrameLayout errorView;

    @NonNull
    public final ImageView ivCertificate;

    @NonNull
    public final LinearLayout llPrice;

    @NonNull
    public final Guideline midGuideline;

    @NonNull
    public final RadioButton rbBody;

    @NonNull
    public final RadioButton rbFace;

    @NonNull
    public final RadioGroup rgFace;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final RecyclerView rvOptionalService;

    @NonNull
    public final RecyclerView rvRequiredService;

    @NonNull
    public final RecyclerView rvTag;

    @NonNull
    public final TextView textGorecharge;

    @NonNull
    public final TextView tvAge;

    @NonNull
    public final TextView tvAgeTitle;

    @NonNull
    public final TextView tvCup;

    @NonNull
    public final TextView tvCupTitle;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvHeight;

    @NonNull
    public final TextView tvHeightTitle;

    @NonNull
    public final TextView tvInfo;

    @NonNull
    public final TextView tvIntro;

    @NonNull
    public final TextView tvLabel;

    @NonNull
    public final TextView tvMinute;

    @NonNull
    public final TextView tvMinuteTitle;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final ImageTextView tvOrder;

    @NonNull
    public final TextView tvPrice;

    @NonNull
    public final TextView tvPriceTitle;

    @NonNull
    public final TextView tvService1;

    @NonNull
    public final TextView tvService2;

    @NonNull
    public final TextView tvServiceOptionalTitle;

    @NonNull
    public final TextView tvServiceRequiredTitle;

    @NonNull
    public final ImageTextView tvShare;

    @NonNull
    public final TextView tvTime;

    @NonNull
    public final TextView tvWeight;

    @NonNull
    public final TextView tvWeightTitle;

    @NonNull
    public final TextView userAccountAmount;

    @NonNull
    public final View viewPaidCover;

    private ActDarkPlayDetailBinding(@NonNull FrameLayout frameLayout, @NonNull Banner banner, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull ConstraintLayout constraintLayout, @NonNull ConstraintLayout constraintLayout2, @NonNull FrameLayout frameLayout2, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout, @NonNull Guideline guideline, @NonNull RadioButton radioButton, @NonNull RadioButton radioButton2, @NonNull RadioGroup radioGroup, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull RecyclerView recyclerView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8, @NonNull TextView textView9, @NonNull TextView textView10, @NonNull TextView textView11, @NonNull TextView textView12, @NonNull TextView textView13, @NonNull TextView textView14, @NonNull TextView textView15, @NonNull TextView textView16, @NonNull TextView textView17, @NonNull ImageTextView imageTextView, @NonNull TextView textView18, @NonNull TextView textView19, @NonNull TextView textView20, @NonNull TextView textView21, @NonNull TextView textView22, @NonNull TextView textView23, @NonNull ImageTextView imageTextView2, @NonNull TextView textView24, @NonNull TextView textView25, @NonNull TextView textView26, @NonNull TextView textView27, @NonNull View view) {
        this.rootView = frameLayout;
        this.banner = banner;
        this.bannerParent = scaleRelativeLayout;
        this.btnMinus = textView;
        this.btnPlus = textView2;
        this.btnSubmitAichangefaceVideo = textView3;
        this.clCertificate = constraintLayout;
        this.clService2 = constraintLayout2;
        this.errorView = frameLayout2;
        this.ivCertificate = imageView;
        this.llPrice = linearLayout;
        this.midGuideline = guideline;
        this.rbBody = radioButton;
        this.rbFace = radioButton2;
        this.rgFace = radioGroup;
        this.rvOptionalService = recyclerView;
        this.rvRequiredService = recyclerView2;
        this.rvTag = recyclerView3;
        this.textGorecharge = textView4;
        this.tvAge = textView5;
        this.tvAgeTitle = textView6;
        this.tvCup = textView7;
        this.tvCupTitle = textView8;
        this.tvDesc = textView9;
        this.tvHeight = textView10;
        this.tvHeightTitle = textView11;
        this.tvInfo = textView12;
        this.tvIntro = textView13;
        this.tvLabel = textView14;
        this.tvMinute = textView15;
        this.tvMinuteTitle = textView16;
        this.tvName = textView17;
        this.tvOrder = imageTextView;
        this.tvPrice = textView18;
        this.tvPriceTitle = textView19;
        this.tvService1 = textView20;
        this.tvService2 = textView21;
        this.tvServiceOptionalTitle = textView22;
        this.tvServiceRequiredTitle = textView23;
        this.tvShare = imageTextView2;
        this.tvTime = textView24;
        this.tvWeight = textView25;
        this.tvWeightTitle = textView26;
        this.userAccountAmount = textView27;
        this.viewPaidCover = view;
    }

    @NonNull
    public static ActDarkPlayDetailBinding bind(@NonNull View view) {
        int i2 = R.id.banner;
        Banner banner = (Banner) view.findViewById(R.id.banner);
        if (banner != null) {
            i2 = R.id.banner_parent;
            ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.banner_parent);
            if (scaleRelativeLayout != null) {
                i2 = R.id.btn_minus;
                TextView textView = (TextView) view.findViewById(R.id.btn_minus);
                if (textView != null) {
                    i2 = R.id.btn_plus;
                    TextView textView2 = (TextView) view.findViewById(R.id.btn_plus);
                    if (textView2 != null) {
                        i2 = R.id.btn_submit_aichangeface_video;
                        TextView textView3 = (TextView) view.findViewById(R.id.btn_submit_aichangeface_video);
                        if (textView3 != null) {
                            i2 = R.id.cl_certificate;
                            ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.cl_certificate);
                            if (constraintLayout != null) {
                                i2 = R.id.cl_service2;
                                ConstraintLayout constraintLayout2 = (ConstraintLayout) view.findViewById(R.id.cl_service2);
                                if (constraintLayout2 != null) {
                                    i2 = R.id.error_view;
                                    FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.error_view);
                                    if (frameLayout != null) {
                                        i2 = R.id.iv_certificate;
                                        ImageView imageView = (ImageView) view.findViewById(R.id.iv_certificate);
                                        if (imageView != null) {
                                            i2 = R.id.ll_price;
                                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_price);
                                            if (linearLayout != null) {
                                                i2 = R.id.mid_guideline;
                                                Guideline guideline = (Guideline) view.findViewById(R.id.mid_guideline);
                                                if (guideline != null) {
                                                    i2 = R.id.rb_body;
                                                    RadioButton radioButton = (RadioButton) view.findViewById(R.id.rb_body);
                                                    if (radioButton != null) {
                                                        i2 = R.id.rb_face;
                                                        RadioButton radioButton2 = (RadioButton) view.findViewById(R.id.rb_face);
                                                        if (radioButton2 != null) {
                                                            i2 = R.id.rg_face;
                                                            RadioGroup radioGroup = (RadioGroup) view.findViewById(R.id.rg_face);
                                                            if (radioGroup != null) {
                                                                i2 = R.id.rv_optional_service;
                                                                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_optional_service);
                                                                if (recyclerView != null) {
                                                                    i2 = R.id.rv_required_service;
                                                                    RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_required_service);
                                                                    if (recyclerView2 != null) {
                                                                        i2 = R.id.rv_tag;
                                                                        RecyclerView recyclerView3 = (RecyclerView) view.findViewById(R.id.rv_tag);
                                                                        if (recyclerView3 != null) {
                                                                            i2 = R.id.text_gorecharge;
                                                                            TextView textView4 = (TextView) view.findViewById(R.id.text_gorecharge);
                                                                            if (textView4 != null) {
                                                                                i2 = R.id.tv_age;
                                                                                TextView textView5 = (TextView) view.findViewById(R.id.tv_age);
                                                                                if (textView5 != null) {
                                                                                    i2 = R.id.tv_age_title;
                                                                                    TextView textView6 = (TextView) view.findViewById(R.id.tv_age_title);
                                                                                    if (textView6 != null) {
                                                                                        i2 = R.id.tv_cup;
                                                                                        TextView textView7 = (TextView) view.findViewById(R.id.tv_cup);
                                                                                        if (textView7 != null) {
                                                                                            i2 = R.id.tv_cup_title;
                                                                                            TextView textView8 = (TextView) view.findViewById(R.id.tv_cup_title);
                                                                                            if (textView8 != null) {
                                                                                                i2 = R.id.tv_desc;
                                                                                                TextView textView9 = (TextView) view.findViewById(R.id.tv_desc);
                                                                                                if (textView9 != null) {
                                                                                                    i2 = R.id.tv_height;
                                                                                                    TextView textView10 = (TextView) view.findViewById(R.id.tv_height);
                                                                                                    if (textView10 != null) {
                                                                                                        i2 = R.id.tv_height_title;
                                                                                                        TextView textView11 = (TextView) view.findViewById(R.id.tv_height_title);
                                                                                                        if (textView11 != null) {
                                                                                                            i2 = R.id.tv_info;
                                                                                                            TextView textView12 = (TextView) view.findViewById(R.id.tv_info);
                                                                                                            if (textView12 != null) {
                                                                                                                i2 = R.id.tv_intro;
                                                                                                                TextView textView13 = (TextView) view.findViewById(R.id.tv_intro);
                                                                                                                if (textView13 != null) {
                                                                                                                    i2 = R.id.tv_label;
                                                                                                                    TextView textView14 = (TextView) view.findViewById(R.id.tv_label);
                                                                                                                    if (textView14 != null) {
                                                                                                                        i2 = R.id.tv_minute;
                                                                                                                        TextView textView15 = (TextView) view.findViewById(R.id.tv_minute);
                                                                                                                        if (textView15 != null) {
                                                                                                                            i2 = R.id.tv_minute_title;
                                                                                                                            TextView textView16 = (TextView) view.findViewById(R.id.tv_minute_title);
                                                                                                                            if (textView16 != null) {
                                                                                                                                i2 = R.id.tv_name;
                                                                                                                                TextView textView17 = (TextView) view.findViewById(R.id.tv_name);
                                                                                                                                if (textView17 != null) {
                                                                                                                                    i2 = R.id.tv_order;
                                                                                                                                    ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.tv_order);
                                                                                                                                    if (imageTextView != null) {
                                                                                                                                        i2 = R.id.tv_price;
                                                                                                                                        TextView textView18 = (TextView) view.findViewById(R.id.tv_price);
                                                                                                                                        if (textView18 != null) {
                                                                                                                                            i2 = R.id.tv_price_title;
                                                                                                                                            TextView textView19 = (TextView) view.findViewById(R.id.tv_price_title);
                                                                                                                                            if (textView19 != null) {
                                                                                                                                                i2 = R.id.tv_service1;
                                                                                                                                                TextView textView20 = (TextView) view.findViewById(R.id.tv_service1);
                                                                                                                                                if (textView20 != null) {
                                                                                                                                                    i2 = R.id.tv_service2;
                                                                                                                                                    TextView textView21 = (TextView) view.findViewById(R.id.tv_service2);
                                                                                                                                                    if (textView21 != null) {
                                                                                                                                                        i2 = R.id.tv_service_optional_title;
                                                                                                                                                        TextView textView22 = (TextView) view.findViewById(R.id.tv_service_optional_title);
                                                                                                                                                        if (textView22 != null) {
                                                                                                                                                            i2 = R.id.tv_service_required_title;
                                                                                                                                                            TextView textView23 = (TextView) view.findViewById(R.id.tv_service_required_title);
                                                                                                                                                            if (textView23 != null) {
                                                                                                                                                                i2 = R.id.tv_share;
                                                                                                                                                                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.tv_share);
                                                                                                                                                                if (imageTextView2 != null) {
                                                                                                                                                                    i2 = R.id.tv_time;
                                                                                                                                                                    TextView textView24 = (TextView) view.findViewById(R.id.tv_time);
                                                                                                                                                                    if (textView24 != null) {
                                                                                                                                                                        i2 = R.id.tv_weight;
                                                                                                                                                                        TextView textView25 = (TextView) view.findViewById(R.id.tv_weight);
                                                                                                                                                                        if (textView25 != null) {
                                                                                                                                                                            i2 = R.id.tv_weight_title;
                                                                                                                                                                            TextView textView26 = (TextView) view.findViewById(R.id.tv_weight_title);
                                                                                                                                                                            if (textView26 != null) {
                                                                                                                                                                                i2 = R.id.user_account_amount;
                                                                                                                                                                                TextView textView27 = (TextView) view.findViewById(R.id.user_account_amount);
                                                                                                                                                                                if (textView27 != null) {
                                                                                                                                                                                    i2 = R.id.view_paid_cover;
                                                                                                                                                                                    View findViewById = view.findViewById(R.id.view_paid_cover);
                                                                                                                                                                                    if (findViewById != null) {
                                                                                                                                                                                        return new ActDarkPlayDetailBinding((FrameLayout) view, banner, scaleRelativeLayout, textView, textView2, textView3, constraintLayout, constraintLayout2, frameLayout, imageView, linearLayout, guideline, radioButton, radioButton2, radioGroup, recyclerView, recyclerView2, recyclerView3, textView4, textView5, textView6, textView7, textView8, textView9, textView10, textView11, textView12, textView13, textView14, textView15, textView16, textView17, imageTextView, textView18, textView19, textView20, textView21, textView22, textView23, imageTextView2, textView24, textView25, textView26, textView27, findViewById);
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
    public static ActDarkPlayDetailBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActDarkPlayDetailBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_dark_play_detail, viewGroup, false);
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
