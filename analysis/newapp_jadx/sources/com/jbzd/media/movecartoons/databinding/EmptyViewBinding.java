package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class EmptyViewBinding implements ViewBinding {

    /* renamed from: iv */
    @NonNull
    public final ImageView f10052iv;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvEmptyTips;

    private EmptyViewBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.f10052iv = imageView;
        this.tvEmptyTips = textView;
    }

    @NonNull
    public static EmptyViewBinding bind(@NonNull View view) {
        int i2 = R.id.f13001iv;
        ImageView imageView = (ImageView) view.findViewById(R.id.f13001iv);
        if (imageView != null) {
            i2 = R.id.tv_empty_tips;
            TextView textView = (TextView) view.findViewById(R.id.tv_empty_tips);
            if (textView != null) {
                return new EmptyViewBinding((LinearLayout) view, imageView, textView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static EmptyViewBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static EmptyViewBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.empty_view, viewGroup, false);
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
