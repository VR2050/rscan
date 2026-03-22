package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatButton;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActPromotionDataBinding implements ViewBinding {

    @NonNull
    public final AppCompatButton btnRecharge;

    @NonNull
    public final Guideline guideCenter;

    @NonNull
    public final Guideline guideLine;

    @NonNull
    public final ConstraintLayout layoutUserInfo;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView txtAmount;

    @NonNull
    public final TextView txtDirectNum;

    @NonNull
    public final TextView txtDirectPay;

    @NonNull
    public final TextView txtDirectProxy;

    @NonNull
    public final TextView txtDirectStatistics;

    @NonNull
    public final TextView txtMonthAmount;

    @NonNull
    public final TextView txtMonthPerformance;

    @NonNull
    public final TextView txtMonthPromotion;

    @NonNull
    public final TextView txtMonthTotal;

    @NonNull
    public final TextView txtRechargeLabel;

    @NonNull
    public final TextView txtTodayAmount;

    @NonNull
    public final TextView txtTodayPerformance;

    @NonNull
    public final TextView txtTodayPromotion;

    @NonNull
    public final TextView txtTodayTotal;

    @NonNull
    public final TextView txtTotal;

    @NonNull
    public final TextView txtTotalLabel;

    private ActPromotionDataBinding(@NonNull ConstraintLayout constraintLayout, @NonNull AppCompatButton appCompatButton, @NonNull Guideline guideline, @NonNull Guideline guideline2, @NonNull ConstraintLayout constraintLayout2, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8, @NonNull TextView textView9, @NonNull TextView textView10, @NonNull TextView textView11, @NonNull TextView textView12, @NonNull TextView textView13, @NonNull TextView textView14, @NonNull TextView textView15, @NonNull TextView textView16) {
        this.rootView = constraintLayout;
        this.btnRecharge = appCompatButton;
        this.guideCenter = guideline;
        this.guideLine = guideline2;
        this.layoutUserInfo = constraintLayout2;
        this.txtAmount = textView;
        this.txtDirectNum = textView2;
        this.txtDirectPay = textView3;
        this.txtDirectProxy = textView4;
        this.txtDirectStatistics = textView5;
        this.txtMonthAmount = textView6;
        this.txtMonthPerformance = textView7;
        this.txtMonthPromotion = textView8;
        this.txtMonthTotal = textView9;
        this.txtRechargeLabel = textView10;
        this.txtTodayAmount = textView11;
        this.txtTodayPerformance = textView12;
        this.txtTodayPromotion = textView13;
        this.txtTodayTotal = textView14;
        this.txtTotal = textView15;
        this.txtTotalLabel = textView16;
    }

    @NonNull
    public static ActPromotionDataBinding bind(@NonNull View view) {
        int i2 = R.id.btn_recharge;
        AppCompatButton appCompatButton = (AppCompatButton) view.findViewById(R.id.btn_recharge);
        if (appCompatButton != null) {
            i2 = R.id.guide_center;
            Guideline guideline = (Guideline) view.findViewById(R.id.guide_center);
            if (guideline != null) {
                i2 = R.id.guideLine;
                Guideline guideline2 = (Guideline) view.findViewById(R.id.guideLine);
                if (guideline2 != null) {
                    i2 = R.id.layout_user_info;
                    ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.layout_user_info);
                    if (constraintLayout != null) {
                        i2 = R.id.txt_amount;
                        TextView textView = (TextView) view.findViewById(R.id.txt_amount);
                        if (textView != null) {
                            i2 = R.id.txt_direct_num;
                            TextView textView2 = (TextView) view.findViewById(R.id.txt_direct_num);
                            if (textView2 != null) {
                                i2 = R.id.txt_direct_pay;
                                TextView textView3 = (TextView) view.findViewById(R.id.txt_direct_pay);
                                if (textView3 != null) {
                                    i2 = R.id.txt_direct_proxy;
                                    TextView textView4 = (TextView) view.findViewById(R.id.txt_direct_proxy);
                                    if (textView4 != null) {
                                        i2 = R.id.txt_direct_statistics;
                                        TextView textView5 = (TextView) view.findViewById(R.id.txt_direct_statistics);
                                        if (textView5 != null) {
                                            i2 = R.id.txt_month_amount;
                                            TextView textView6 = (TextView) view.findViewById(R.id.txt_month_amount);
                                            if (textView6 != null) {
                                                i2 = R.id.txt_month_performance;
                                                TextView textView7 = (TextView) view.findViewById(R.id.txt_month_performance);
                                                if (textView7 != null) {
                                                    i2 = R.id.txt_month_promotion;
                                                    TextView textView8 = (TextView) view.findViewById(R.id.txt_month_promotion);
                                                    if (textView8 != null) {
                                                        i2 = R.id.txt_month_total;
                                                        TextView textView9 = (TextView) view.findViewById(R.id.txt_month_total);
                                                        if (textView9 != null) {
                                                            i2 = R.id.txt_recharge_label;
                                                            TextView textView10 = (TextView) view.findViewById(R.id.txt_recharge_label);
                                                            if (textView10 != null) {
                                                                i2 = R.id.txt_today_amount;
                                                                TextView textView11 = (TextView) view.findViewById(R.id.txt_today_amount);
                                                                if (textView11 != null) {
                                                                    i2 = R.id.txt_today_performance;
                                                                    TextView textView12 = (TextView) view.findViewById(R.id.txt_today_performance);
                                                                    if (textView12 != null) {
                                                                        i2 = R.id.txt_today_promotion;
                                                                        TextView textView13 = (TextView) view.findViewById(R.id.txt_today_promotion);
                                                                        if (textView13 != null) {
                                                                            i2 = R.id.txt_today_total;
                                                                            TextView textView14 = (TextView) view.findViewById(R.id.txt_today_total);
                                                                            if (textView14 != null) {
                                                                                i2 = R.id.txt_total;
                                                                                TextView textView15 = (TextView) view.findViewById(R.id.txt_total);
                                                                                if (textView15 != null) {
                                                                                    i2 = R.id.txt_total_label;
                                                                                    TextView textView16 = (TextView) view.findViewById(R.id.txt_total_label);
                                                                                    if (textView16 != null) {
                                                                                        return new ActPromotionDataBinding((ConstraintLayout) view, appCompatButton, guideline, guideline2, constraintLayout, textView, textView2, textView3, textView4, textView5, textView6, textView7, textView8, textView9, textView10, textView11, textView12, textView13, textView14, textView15, textView16);
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
    public static ActPromotionDataBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActPromotionDataBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_promotion_data, viewGroup, false);
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
