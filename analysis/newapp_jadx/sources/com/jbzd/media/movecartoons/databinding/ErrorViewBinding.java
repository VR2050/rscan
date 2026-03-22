package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.ProgressButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ErrorViewBinding implements ViewBinding {

    @NonNull
    public final ProgressButton btnRetry;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView txtTips;

    private ErrorViewBinding(@NonNull LinearLayout linearLayout, @NonNull ProgressButton progressButton, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.btnRetry = progressButton;
        this.txtTips = textView;
    }

    @NonNull
    public static ErrorViewBinding bind(@NonNull View view) {
        int i2 = R.id.btn_retry;
        ProgressButton progressButton = (ProgressButton) view.findViewById(R.id.btn_retry);
        if (progressButton != null) {
            i2 = R.id.txt_tips;
            TextView textView = (TextView) view.findViewById(R.id.txt_tips);
            if (textView != null) {
                return new ErrorViewBinding((LinearLayout) view, progressButton, textView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ErrorViewBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ErrorViewBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.error_view, viewGroup, false);
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
