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
import com.github.mmin18.widget.RealtimeBlurView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogAlertDarkBinding implements ViewBinding {

    @NonNull
    public final RealtimeBlurView blurView;

    @NonNull
    public final TextView btnBuyVip;

    @NonNull
    public final ConstraintLayout clBlurNovip;

    @NonNull
    public final TextView itvBlur;

    @NonNull
    public final LinearLayout llContentCenter;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvLeave;

    private DialogAlertDarkBinding(@NonNull LinearLayout linearLayout, @NonNull RealtimeBlurView realtimeBlurView, @NonNull TextView textView, @NonNull ConstraintLayout constraintLayout, @NonNull TextView textView2, @NonNull LinearLayout linearLayout2, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.blurView = realtimeBlurView;
        this.btnBuyVip = textView;
        this.clBlurNovip = constraintLayout;
        this.itvBlur = textView2;
        this.llContentCenter = linearLayout2;
        this.tvLeave = textView3;
    }

    @NonNull
    public static DialogAlertDarkBinding bind(@NonNull View view) {
        int i2 = R.id.blur_view;
        RealtimeBlurView realtimeBlurView = (RealtimeBlurView) view.findViewById(R.id.blur_view);
        if (realtimeBlurView != null) {
            i2 = R.id.btn_buy_vip;
            TextView textView = (TextView) view.findViewById(R.id.btn_buy_vip);
            if (textView != null) {
                i2 = R.id.cl_blur_novip;
                ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.cl_blur_novip);
                if (constraintLayout != null) {
                    i2 = R.id.itv_blur;
                    TextView textView2 = (TextView) view.findViewById(R.id.itv_blur);
                    if (textView2 != null) {
                        i2 = R.id.ll_content_center;
                        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_content_center);
                        if (linearLayout != null) {
                            i2 = R.id.tv_leave;
                            TextView textView3 = (TextView) view.findViewById(R.id.tv_leave);
                            if (textView3 != null) {
                                return new DialogAlertDarkBinding((LinearLayout) view, realtimeBlurView, textView, constraintLayout, textView2, linearLayout, textView3);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogAlertDarkBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogAlertDarkBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_alert_dark, viewGroup, false);
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
