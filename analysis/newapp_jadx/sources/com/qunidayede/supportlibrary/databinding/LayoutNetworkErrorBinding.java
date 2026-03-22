package com.qunidayede.supportlibrary.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qunidayede.supportlibrary.R$id;
import com.qunidayede.supportlibrary.R$layout;

/* loaded from: classes2.dex */
public final class LayoutNetworkErrorBinding implements ViewBinding {

    @NonNull
    public final AppCompatImageView ivImg;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvNetworkerrorReconnect;

    @NonNull
    public final TextView tvTips;

    private LayoutNetworkErrorBinding(@NonNull ConstraintLayout constraintLayout, @NonNull AppCompatImageView appCompatImageView, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = constraintLayout;
        this.ivImg = appCompatImageView;
        this.tvNetworkerrorReconnect = textView;
        this.tvTips = textView2;
    }

    @NonNull
    public static LayoutNetworkErrorBinding bind(@NonNull View view) {
        int i2 = R$id.iv_img;
        AppCompatImageView appCompatImageView = (AppCompatImageView) view.findViewById(i2);
        if (appCompatImageView != null) {
            i2 = R$id.tv_networkerror_reconnect;
            TextView textView = (TextView) view.findViewById(i2);
            if (textView != null) {
                i2 = R$id.tv_tips;
                TextView textView2 = (TextView) view.findViewById(i2);
                if (textView2 != null) {
                    return new LayoutNetworkErrorBinding((ConstraintLayout) view, appCompatImageView, textView, textView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutNetworkErrorBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutNetworkErrorBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R$layout.layout_network_error, viewGroup, false);
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
