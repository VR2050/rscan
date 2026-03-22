package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.github.mmin18.widget.RealtimeBlurView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class ActMovieDetailsBinding implements ViewBinding {

    @NonNull
    public final TextView btnRecheckLine;

    @NonNull
    public final FrameLayout errorView;

    @NonNull
    public final FrameLayout flVideo;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final FullPlayerView fullPlayer;

    @NonNull
    public final ImageTextView itvReplay;

    @NonNull
    public final ImageView ivBack;

    @NonNull
    public final FrameLayout lLayoutBg;

    @NonNull
    public final LinearLayout layoutDayInfo;

    @NonNull
    public final RelativeLayout layoutError;

    @NonNull
    public final LinearLayout layoutHourInfo;

    @NonNull
    public final LinearLayout layoutMinutesInfo;

    @NonNull
    public final LinearLayout linearLayout;

    @NonNull
    public final LinearLayout llBuyLimitTime;

    @NonNull
    public final LinearLayout llEndPreviewPrice;

    @NonNull
    public final LinearLayout llSpinner;

    @NonNull
    public final Banner playAd;

    @NonNull
    public final RealtimeBlurView rbvEndPreviewPrice;

    @NonNull
    public final ConstraintLayout rlEndPreviewPrice;

    @NonNull
    public final ConstraintLayout rlEndPreviewVip;

    @NonNull
    public final ConstraintLayout rlEndPreviewWatch;

    @NonNull
    public final ConstraintLayout rlReplay;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final SlidingTabLayout tablayoutDetails;

    @NonNull
    public final TextView tvAdTime;

    @NonNull
    public final TextView tvDay;

    @NonNull
    public final TextView tvGold;

    @NonNull
    public final TextView tvGoldVip;

    @NonNull
    public final TextView tvHour;

    @NonNull
    public final TextView tvLookTips;

    @NonNull
    public final TextView tvMin;

    @NonNull
    public final TextView tvRed;

    @NonNull
    public final TextView tvRedPrice;

    @NonNull
    public final TextView tvRedUnlockPrice;

    @NonNull
    public final TextView tvRedUnlockWatch;

    @NonNull
    public final TextView tvSec;

    @NonNull
    public final ImageTextView tvSpinner;

    @NonNull
    public final TextView tvTimeCountDown;

    @NonNull
    public final TextView tvVip;

    @NonNull
    public final ViewPager vpContentDetails;

    private ActMovieDetailsBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull FrameLayout frameLayout2, @NonNull FrameLayout frameLayout3, @NonNull FrameLayout frameLayout4, @NonNull FullPlayerView fullPlayerView, @NonNull ImageTextView imageTextView, @NonNull ImageView imageView, @NonNull FrameLayout frameLayout5, @NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull LinearLayout linearLayout6, @NonNull LinearLayout linearLayout7, @NonNull Banner banner, @NonNull RealtimeBlurView realtimeBlurView, @NonNull ConstraintLayout constraintLayout, @NonNull ConstraintLayout constraintLayout2, @NonNull ConstraintLayout constraintLayout3, @NonNull ConstraintLayout constraintLayout4, @NonNull SlidingTabLayout slidingTabLayout, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8, @NonNull TextView textView9, @NonNull TextView textView10, @NonNull TextView textView11, @NonNull TextView textView12, @NonNull TextView textView13, @NonNull ImageTextView imageTextView2, @NonNull TextView textView14, @NonNull TextView textView15, @NonNull ViewPager viewPager) {
        this.rootView = frameLayout;
        this.btnRecheckLine = textView;
        this.errorView = frameLayout2;
        this.flVideo = frameLayout3;
        this.fragContent = frameLayout4;
        this.fullPlayer = fullPlayerView;
        this.itvReplay = imageTextView;
        this.ivBack = imageView;
        this.lLayoutBg = frameLayout5;
        this.layoutDayInfo = linearLayout;
        this.layoutError = relativeLayout;
        this.layoutHourInfo = linearLayout2;
        this.layoutMinutesInfo = linearLayout3;
        this.linearLayout = linearLayout4;
        this.llBuyLimitTime = linearLayout5;
        this.llEndPreviewPrice = linearLayout6;
        this.llSpinner = linearLayout7;
        this.playAd = banner;
        this.rbvEndPreviewPrice = realtimeBlurView;
        this.rlEndPreviewPrice = constraintLayout;
        this.rlEndPreviewVip = constraintLayout2;
        this.rlEndPreviewWatch = constraintLayout3;
        this.rlReplay = constraintLayout4;
        this.tablayoutDetails = slidingTabLayout;
        this.tvAdTime = textView2;
        this.tvDay = textView3;
        this.tvGold = textView4;
        this.tvGoldVip = textView5;
        this.tvHour = textView6;
        this.tvLookTips = textView7;
        this.tvMin = textView8;
        this.tvRed = textView9;
        this.tvRedPrice = textView10;
        this.tvRedUnlockPrice = textView11;
        this.tvRedUnlockWatch = textView12;
        this.tvSec = textView13;
        this.tvSpinner = imageTextView2;
        this.tvTimeCountDown = textView14;
        this.tvVip = textView15;
        this.vpContentDetails = viewPager;
    }

    @NonNull
    public static ActMovieDetailsBinding bind(@NonNull View view) {
        int i2 = R.id.btn_recheck_line;
        TextView textView = (TextView) view.findViewById(R.id.btn_recheck_line);
        if (textView != null) {
            i2 = R.id.error_view;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.error_view);
            if (frameLayout != null) {
                i2 = R.id.flVideo;
                FrameLayout frameLayout2 = (FrameLayout) view.findViewById(R.id.flVideo);
                if (frameLayout2 != null) {
                    i2 = R.id.frag_content;
                    FrameLayout frameLayout3 = (FrameLayout) view.findViewById(R.id.frag_content);
                    if (frameLayout3 != null) {
                        i2 = R.id.full_player;
                        FullPlayerView fullPlayerView = (FullPlayerView) view.findViewById(R.id.full_player);
                        if (fullPlayerView != null) {
                            i2 = R.id.itv_replay;
                            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_replay);
                            if (imageTextView != null) {
                                i2 = R.id.iv_back;
                                ImageView imageView = (ImageView) view.findViewById(R.id.iv_back);
                                if (imageView != null) {
                                    FrameLayout frameLayout4 = (FrameLayout) view;
                                    i2 = R.id.layout_day_info;
                                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.layout_day_info);
                                    if (linearLayout != null) {
                                        i2 = R.id.layout_error;
                                        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.layout_error);
                                        if (relativeLayout != null) {
                                            i2 = R.id.layout_hour_info;
                                            LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.layout_hour_info);
                                            if (linearLayout2 != null) {
                                                i2 = R.id.layout_minutes_info;
                                                LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.layout_minutes_info);
                                                if (linearLayout3 != null) {
                                                    i2 = R.id.linearLayout;
                                                    LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.linearLayout);
                                                    if (linearLayout4 != null) {
                                                        i2 = R.id.ll_buy_limit_time;
                                                        LinearLayout linearLayout5 = (LinearLayout) view.findViewById(R.id.ll_buy_limit_time);
                                                        if (linearLayout5 != null) {
                                                            i2 = R.id.ll_endPreview_price;
                                                            LinearLayout linearLayout6 = (LinearLayout) view.findViewById(R.id.ll_endPreview_price);
                                                            if (linearLayout6 != null) {
                                                                i2 = R.id.ll_spinner;
                                                                LinearLayout linearLayout7 = (LinearLayout) view.findViewById(R.id.ll_spinner);
                                                                if (linearLayout7 != null) {
                                                                    i2 = R.id.playAd;
                                                                    Banner banner = (Banner) view.findViewById(R.id.playAd);
                                                                    if (banner != null) {
                                                                        i2 = R.id.rbv_endPreview_price;
                                                                        RealtimeBlurView realtimeBlurView = (RealtimeBlurView) view.findViewById(R.id.rbv_endPreview_price);
                                                                        if (realtimeBlurView != null) {
                                                                            i2 = R.id.rl_endPreview_price;
                                                                            ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.rl_endPreview_price);
                                                                            if (constraintLayout != null) {
                                                                                i2 = R.id.rl_endPreview_vip;
                                                                                ConstraintLayout constraintLayout2 = (ConstraintLayout) view.findViewById(R.id.rl_endPreview_vip);
                                                                                if (constraintLayout2 != null) {
                                                                                    i2 = R.id.rl_endPreview_watch;
                                                                                    ConstraintLayout constraintLayout3 = (ConstraintLayout) view.findViewById(R.id.rl_endPreview_watch);
                                                                                    if (constraintLayout3 != null) {
                                                                                        i2 = R.id.rl_replay;
                                                                                        ConstraintLayout constraintLayout4 = (ConstraintLayout) view.findViewById(R.id.rl_replay);
                                                                                        if (constraintLayout4 != null) {
                                                                                            i2 = R.id.tablayout_details;
                                                                                            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tablayout_details);
                                                                                            if (slidingTabLayout != null) {
                                                                                                i2 = R.id.tv_adTime;
                                                                                                TextView textView2 = (TextView) view.findViewById(R.id.tv_adTime);
                                                                                                if (textView2 != null) {
                                                                                                    i2 = R.id.tv_day;
                                                                                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_day);
                                                                                                    if (textView3 != null) {
                                                                                                        i2 = R.id.tv_gold;
                                                                                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_gold);
                                                                                                        if (textView4 != null) {
                                                                                                            i2 = R.id.tv_gold_vip;
                                                                                                            TextView textView5 = (TextView) view.findViewById(R.id.tv_gold_vip);
                                                                                                            if (textView5 != null) {
                                                                                                                i2 = R.id.tv_hour;
                                                                                                                TextView textView6 = (TextView) view.findViewById(R.id.tv_hour);
                                                                                                                if (textView6 != null) {
                                                                                                                    i2 = R.id.tv_lookTips;
                                                                                                                    TextView textView7 = (TextView) view.findViewById(R.id.tv_lookTips);
                                                                                                                    if (textView7 != null) {
                                                                                                                        i2 = R.id.tv_min;
                                                                                                                        TextView textView8 = (TextView) view.findViewById(R.id.tv_min);
                                                                                                                        if (textView8 != null) {
                                                                                                                            i2 = R.id.tv_red;
                                                                                                                            TextView textView9 = (TextView) view.findViewById(R.id.tv_red);
                                                                                                                            if (textView9 != null) {
                                                                                                                                i2 = R.id.tv_red_price;
                                                                                                                                TextView textView10 = (TextView) view.findViewById(R.id.tv_red_price);
                                                                                                                                if (textView10 != null) {
                                                                                                                                    i2 = R.id.tv_red_unlock_price;
                                                                                                                                    TextView textView11 = (TextView) view.findViewById(R.id.tv_red_unlock_price);
                                                                                                                                    if (textView11 != null) {
                                                                                                                                        i2 = R.id.tv_red_unlock_watch;
                                                                                                                                        TextView textView12 = (TextView) view.findViewById(R.id.tv_red_unlock_watch);
                                                                                                                                        if (textView12 != null) {
                                                                                                                                            i2 = R.id.tv_sec;
                                                                                                                                            TextView textView13 = (TextView) view.findViewById(R.id.tv_sec);
                                                                                                                                            if (textView13 != null) {
                                                                                                                                                i2 = R.id.tv_spinner;
                                                                                                                                                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.tv_spinner);
                                                                                                                                                if (imageTextView2 != null) {
                                                                                                                                                    i2 = R.id.tv_time_count_down;
                                                                                                                                                    TextView textView14 = (TextView) view.findViewById(R.id.tv_time_count_down);
                                                                                                                                                    if (textView14 != null) {
                                                                                                                                                        i2 = R.id.tv_vip;
                                                                                                                                                        TextView textView15 = (TextView) view.findViewById(R.id.tv_vip);
                                                                                                                                                        if (textView15 != null) {
                                                                                                                                                            i2 = R.id.vp_content_details;
                                                                                                                                                            ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content_details);
                                                                                                                                                            if (viewPager != null) {
                                                                                                                                                                return new ActMovieDetailsBinding(frameLayout4, textView, frameLayout, frameLayout2, frameLayout3, fullPlayerView, imageTextView, imageView, frameLayout4, linearLayout, relativeLayout, linearLayout2, linearLayout3, linearLayout4, linearLayout5, linearLayout6, linearLayout7, banner, realtimeBlurView, constraintLayout, constraintLayout2, constraintLayout3, constraintLayout4, slidingTabLayout, textView2, textView3, textView4, textView5, textView6, textView7, textView8, textView9, textView10, textView11, textView12, textView13, imageTextView2, textView14, textView15, viewPager);
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
    public static ActMovieDetailsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActMovieDetailsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_movie_details, viewGroup, false);
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
